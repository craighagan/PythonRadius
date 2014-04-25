
from radiusconstants import *

import boto
import time

import json
import base64
import re
import platform
import string
import random
import logging
import sqlite3

from boto.dynamodb2.fields import HashKey, RangeKey, KeysOnlyIndex, AllIndex
from boto.dynamodb2.layer1 import DynamoDBConnection
from boto.dynamodb2.table import Table
from boto.dynamodb2.types import NUMBER

from awssecrets import *
from radiusencryption import *

DEFAULT_KEY_LIFE=365*10*86400 #ten years

PURGE_RETAIN_NR_ACTIVE_KEYS=5
PURGE_TIME_BEFORE_NOW=86400


class RadiusServer:
    """
    container to represent radius master servers
    """

    def __init__(self,ip=None,weight=None,secret=None,hops=None,cluster=None,timeout=None):
        self.ip = ip
        self.weight = weight
        self.secret = secret
        self.hops = hops
        self.cluster = cluster
        self.timeout = timeout

    def validate(self):
        if self.ip is None or self.secret is None or self.cluster is None or self.timeout is None or self.hops is None:
            return False
        else:
            return True

    def __repr__(self):
        outstr = "RadiusServer:{ip=%s,weight=%s,secret=%s,hops=%s,cluster=%s,timeout=%s}" % (
            self.ip,
            self.weight,
            self.secret,
            self.hops,
            self.cluster,
            self.timeout)

        return outstr
        
class RadiusServerList:
    """
    list of radiusservers and secrets
    """

    def __init__(self,server_file=None):
        self._clusters = {}
        self._servers = {}

        logging.debug("initialize radiuserver file=%s"%server_file)
        if server_file is not None:
            self._parseServerFile(server_file)
        
    def addServer(self, server):
        if not isinstance(server,RadiusServer):
            raise ValueError("server must be of type RadiusServer")

        if not server.validate():
            raise ValueError("please insure that the server configuration is complete")

        if server.cluster not in self._clusters:
            self._clusters[server.cluster.upper()] = [server]
        else:
            self._clusters[server.cluster].append(server)
        
        self._servers[server.ip] = server

        logging.debug('added server %s to cluster %s' % (server.ip,server.cluster))
    
    def _getMyCluster(self):
        hostname = platform.node()
        cluster = platform.node().split('.')[-3].rstrip(string.digits).upper()

        #exceptions
        if cluster == "VDC":
            cluster = "IAD"

        logging.debug('_getMyCluster found %s from %s' % (hostname,cluster))

        return cluster

    def _parseServerFile(self, serverfile):
        parse_comment=re.compile(r'^\s*#\s*([\d\.]+): NLS weight = (\d+); ICMP hops = (\d+); Cluster: (\S+)$')
        blank=re.compile(r'^\s$')
        comment=re.compile(r'^\s*#')
        
        servers = {}
        
        with open(serverfile) as f:
            for line in f:
                line = line.rstrip().lstrip()

                if blank.match(line):
                    pass
                elif comment.match(line):
                    res = parse_comment.search(line)
                    if res is not None:
                        (ip, weight, hops, cluster) = res.groups()

                        if ip not in servers:
                            r = RadiusServer(ip=ip,weight=int(weight),cluster=cluster,hops=int(hops))
                            servers[ip] = r
                        else:
                            servers[ip].ip = ip
                            servers[ip].weight = int(weight)
                            servers[ip].hops = int(hops)
                            servers[ip].cluster = cluster

                else:
                    try:
                        (ip,secret,timeout) = line.split()
                        if ip not in servers:
                            r = RadiusServer(ip=ip,secret=secret,timeout=int(timeout))
                            servers[ip] = r
                        else:
                            servers[ip].ip = ip
                            servers[ip].secret = secret
                            servers[ip].timeout = int(timeout)
                    except ValueError:
                        pass

        for key in servers:
            self.addServer(servers[key])


    def getServer(self,cluster=None):

        if cluster is None:
            cluster = self._getMyCluster()

        if cluster not in self._clusters:
            #need to return closest
            def redfn(a,b):
                if isinstance(a, str):
                    a=reduce(redfn, self._clusters[a])
                if isinstance(b, str):
                    b=reduce(redfn, self._clusters[b])
                if a.hops < b.hops:
                    return a
                else:
                    return b
                
            #just give fastest, but we really want
            #to flip coins
            #return reduce(redfn, self._clusters)
            cluster = reduce(redfn, self._clusters).cluster
            return random.choice(self._clusters[cluster])
        
        #yah, i probably should deal with weighting        
        server = random.choice(self._clusters[cluster])

        logging.debug('selected server %s from cluster %s for requet' % (server.ip,cluster)
                      )
        return server
        

class RadiusSecrets:
    """
    container system for obtaining radius secrets
    """

    def __init__(self):
        raise NotImplementedError;

    def getSecret(self):
        raise NotImplementedError;
    

class MasterRadiusSecrets(RadiusSecrets):
    """
    this is for obtaining secrets for the master
    radius server
    """

    def __init__(self,secret_file="/etc/raddb/secret",server_file="/etc/raddb/server",default_master_server=None):
        """
        @params secret_file: represents the file where the master
                secret is. defaults to /etc/raddb/secret

        @type string
        """
        self._secret_file = secret_file
        self._server_file = server_file

        if default_master_server is None:
            self._default_master_server='AUTOMATIC'

        self._default_master_server = default_master_server

        logging.debug("MasterRadiusSecrets initialize, secret_file=%s server_file=%s" % (secret_file,server_file))
        
    def getSecret(self):
        """
        pull the secret from /etc/raddb/secret
        """

        with open(self._secret_file) as f:
            secret=f.readline().rstrip()
            
        return secret

    def getMaster(self):
        return self._default_master_server

    def getServerAndSecret(self):
        """
        read from the radius server file,
        pull a list of secrets/servers and choose one

        returns a tuple of server_ip, secret
        
        """

        if self._default_master_server is not None and self._default_master_server != "AUTOMATIC":
            return (self._default_master_server,self.getSecret())
        
        sl=RadiusServerList(server_file=self._server_file)

        rs=sl.getServer()

        return((rs.ip,rs.secret))

class ClientRadiusSecretsSQLite(RadiusSecrets):
    """
    get secrets for a particular client

    """
    def __init__(self, secretdbfile, table_name="host_secrets"):
        """
        @param secretdbfile file to sqlite user database

        @type secretdbfile string (filepath)

        """

        self._secretdbfile = secretdbfile

        if table_name is None:
            raise ValueError("table name containing host secrets must be specified")

        self._table_name = table_name 

        self._secretdb = sqlite3.connect(secretdbfile,check_same_thread=False)

        self._createTable()


    def _createTable(self):
        """
        create sqlite table
        """
        
        try:
            self._secretdb.execute('create table %s (ip_Address text, not_before number, not_after number, secret text)' % (self._table_name))
            self._secretdb.commit()
            logging.debug("created sqlite table %s" % self._table_name)
            
        except sqlite3.OperationalError as e:
            logging.debug("failed to create table %s, usually this means table already exists %s " % (self._table_name,e))
            pass


    def putSecret(self, clientIP, secret, not_before=None,not_after=None,tries=0):
        """
        store a secret for clientIP

        @param clientIP : client ip address

        @param secret : radius secret for client

        @param tries : internal parameter to constrain recursion depth for self-calls
        
        @type clientIP string 

        @type secret

        example usage:

        from radiussecrets import *
        rs=ClientRadiusSecrets(encryption_key='someencryptionkey',
        aws_keys=AWSKeys('myaccesskey','mysecretkey'),table_name='qradius_secrets')

        ValidationException


        rs.putSecret('1.2.3.4','shhdonottellanyone')


        """

        now = time.time()

        if not_before is None:
            not_before = now

        if not_after is None:
            not_after = now + DEFAULT_KEY_LIFE

        if not isinstance(not_before,(int,float,long)) or not_before < 0:
            raise ValueError("not_before must be a number representing seconds since epoch")

        if not isinstance(not_after,(int,float,long)) or not_after < 0:
            raise ValueError("not_before must be a number representing seconds since epoch")

        if len(secret) > MAX_SECRET_LENGTH:
            raise ValueError("length of secret may not exceed %d bytes" % MAX_SECRET_LENGTH)


        result = self._secretdb.execute('insert into %s values (:ip_address,:not_before,:not_after,:secret)' % (self._table_name),
                               {'ip_address': clientIP,
                                'not_before': not_before,
                                'not_after': not_after,
                                'secret': secret})
        
        logging.debug("inserted host secret %s %d %d [...]" % (clientIP, not_before, not_after))
        self._secretdb.commit()
        
        
        return result

    def deleteSecret(self, clientIP, not_before):
        """
        delete a secret

        this should be used carefully

        @param clientIP

        @param not_before

        @type clientIP string

        @type not_before number

        """

        return self._secretdb.execute('delete from %s where ip_address=:ip_address and not_before=:not_before' % self._table_name,
                                      {'ip_address': ip_address,
                                       'not_before': not_before})
        
    def getSecret(self, clientIP):
        """
        return the secret associated with IP address

        if multiple secrets are found, selection is by:

        1) not_before < now
        2) not_after >= now
        3) the highest value of not before, if there are still multiple secrets
        

        @param clientIP

        @param not_before seconds since epoch that the secret becomes valid

        @param not_after seconds since epoch after which the secret is not valid

        @type clientIP string representing an ip address

        """

        now = time.time()        

        #i wanted to limit to 3 (limit=3) but, boto kept barfing
        results = self._secretdb.execute('select secret,not_before,not_after from %s where ip_address=:ip_address and not_before < :not_before and not_after >= :not_after order by not_before,not_after' % self._table_name,
                                         {'ip_address': clientIP,
                                          'not_before': now,
                                          'not_after': now}).fetchall()
        client_secret = None
        client_secret_not_before = 0
        
        for result in results:
            client_secret = str(result[0])

            logging.debug('retrieved secret for %s' % (clientIP))
            return client_secret
        #only should be reached if it is None
        return client_secret                                      


    def purgeSecrets(self, clientIP):
        """
        purge stale secrets associated with IP address

        1) remove all keys for clientIP where not after is older than 
           current time - PURGE_TIME_BEFORE_NOW

        2) scan remaining keys, keep 

        @param clientIP

        @type string

        @returns # of purged secrets
        """

        now = time.time()
        min_purge_time = now

        nr_purged = 0

        # first get rid of expired keys
        results = self._secretdb.execute('delete from %s where ip_address=:ip_address and not_after <:not_after' % self._table_name,
                                      {'ip_address': clientIP,
                                       'not_after': min_purge_time}).fetchall()

        for result in results:
            logging.info('purging secret: %s %d' % (result['ip'],result['not_before']))
            result.delete()
            nr_purged += 1
        
        # now the fun...
        result_list = []

        results = self._secretdb.execute('select ip_address,not_before,not_after from %s where ip_address=:ip_address and not_before < :not_before order by not_before' % self._table_name,
                                         {'ip_address': clientIP,
                                          'not_before': min_purge_time}).fetchall()

        for result in results:
            result_list.append(result)
            

        # delete results if there are more than PURGE_RETAIN_NR_ACTIVE results,
        # we want the oldest not befores to be removed first
        if len(result_list) > PURGE_RETAIN_NR_ACTIVE_KEYS:
            for result in result_list:
                self._secretdb.execute('delete from %s where ip_address=:ip_address and not_before=:not_before and not_after = :not_after' % self._table_name,
                                       {'ip_address': clientIP,
                                        'not_before': result[1],
                                        'not_after': result[2]})
                nr_purged += 1
            self._secretdb.commit()


        return nr_purged


class ClientRadiusSecretsDDB(RadiusSecrets):
    """
    get secrets for a particular client

    ddb=DynamoDBConnection(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key
    )


    secrets = Table.create('qradius_secrets',schema=[\
       HashKey('ip_address'),
       RangeKey('not_before',data_type=NUMBER),
    ], indexes=[
       AllIndex('IPNotAfter',parts=[
          HashKey('ip_address'),
          RangeKey('not_after',data_type=NUMBER),
       ])
    ],connection=ddb)


    we will normally want secrets where

    ip_address = client ip address
    not_before < now
    not_after >= now

    likely we'll want to limit the # of secrets we look at, here i limit it to 3


    For queries (these are the least impactful on dynamo:
    res=secrets.query(ip_address__eq='10.25.95.158',not_before__lt=now,limit=3,consistent=False)
    res=secrets.query(ip_address__eq='10.25.95.158',not_after__gt=now,limit=3,consistent=False,index='IPNotAfter')


    if you really need everything, this is a full scan:
    res=secrets.scan(ip_address__eq='10.25.95.158',not_before__lt=now,not_after__gt=now,limit=3)

    """
    
    def __init__(self, encryption_key=None, aws_keys=None, table_name=None):
        """

        @param encryption_key : string containing encryption key
        
        @param aws_keys : object containing aws keys

        @param table_name : dynamo table name

        @type encryption_key string
        
        @type aws_keys AWSKeys

        @type table_name string

        """

        if encryption_key is None:
            raise ValueError("encryption_key must be specified")

        if not isinstance(aws_keys,AWSKeys):
            raise ValueError("aws_material must be specified and of type AWSKeys")

        if table_name is None:
            raise ValueError("dynamo table containing secrets must be specified")

        self._encryption_key = encryption_key
        
        self._encryptor = DataEncryptor(self._encryption_key)

        self._ddb_connection = DynamoDBConnection(
                aws_access_key_id=aws_keys.aws_access_key,
                aws_secret_access_key=aws_keys.aws_secret_key
                )

        if self._ddb_connection is None:
            raise ValueError("unable to obtain dynamo connection using %s" % aws_material)
        
        self._secret_table = Table(table_name,connection=self._ddb_connection)

        logging.debug('connectd to dynamo table %s' % table_name)

        if self._secret_table is None:
            raise ValueError("unable to connect to dynamo table %s" % table_name)

        
    def encryptSecret(self, secret):
        """
        call the included encryption module to encrypt/encode
        secrets

        @param secret

        @type secret string

        """

        if len(secret) > MAX_SECRET_LENGTH:
            raise ValueError("secret may not be more than %d bytes" % MAX_SECRET_LENGTH)

        encoded_secret = self._encryptor.encrypt(secret)

        return(encoded_secret)

    def decryptSecret(self, encoded_secret):
        """
        call the included encryption module to decrypt/decode
        secrets

        @param encoded_secret

        @type encoded_secret string

        """
        
        plain_secret = self._encryptor.decrypt(encoded_secret)

        if len(plain_secret) > MAX_SECRET_LENGTH:
            raise ValueError("decryption resulted in a plain secret longer than the maximum length of %d bytes" % MAX_SECRET_LENGTH)
        
        return(plain_secret)

        
    def putSecret(self, clientIP, secret, not_before=None,not_after=None,tries=0):
        """
        store a secret for clientIP

        @param clientIP : client ip address

        @param secret : radius secret for client

        @param tries : internal parameter to constrain recursion depth for self-calls
        
        @type clientIP string 

        @type secret

        example usage:

        from radiussecrets import *
        rs=ClientRadiusSecrets(encryption_key='someencryptionkey',
        aws_keys=AWSKeys('myaccesskey','mysecretkey'),table_name='qradius_secrets')

        ValidationException


        rs.putSecret('1.2.3.4','shhdonottellanyone')


        """

        now = time.time()

        if not_before is None:
            not_before = now

        if not_after is None:
            not_after = now + DEFAULT_KEY_LIFE

        if not isinstance(not_before,(int,float,long)) or not_before < 0:
            raise ValueError("not_before must be a number representing seconds since epoch")

        if not isinstance(not_after,(int,float,long)) or not_after < 0:
            raise ValueError("not_before must be a number representing seconds since epoch")

        if len(secret) > MAX_SECRET_LENGTH:
            raise ValueError("length of secret may not exceed %d bytes" % MAX_SECRET_LENGTH)


        result = None
        try:
            result = self._secret_table.put_item(data={
                'ip_address': clientIP,
                'not_before': not_before,
                'not_after': not_after,
                'secret': self.encryptSecret(secret)
                })

        except boto.dynamodb2.exceptions.ConditionalCheckFailedException as e:
            tries += 1
            if tries > 5:
                logging.crit('pk violation for client %s not_before %d after %d tries at incrementing' % (clientIP,not_before,tries))
                raise e

            #increment not_before to avoid pk violation
            not_before += 1
            logging.warn('pk violation for client %s not_before %d; retrying with higher not_before ' % (clientIP,not_before))
            result = self.putSecret(clientIP, secret, not_before=not_before,not_after=not_after,tries=tries)
        
        return result

    def deleteSecret(self, clientIP, not_before):
        """
        delete a secret

        this should be used carefully

        @param clientIP

        @param not_before

        @type clientIP string

        @type not_before number

        """

        return self._secret_table.delete_item(ip_address=clientIP,not_before=not_before)
        
    def getSecret(self, clientIP):
        """
        return the secret associated with IP address

        if multiple secrets are found, selection is by:

        1) not_before < now
        2) not_after >= now
        3) the highest value of not before, if there are still multiple secrets
        

        @param clientIP

        @param not_before seconds since epoch that the secret becomes valid

        @param not_after seconds since epoch after which the secret is not valid

        @type clientIP string representing an ip address

        """

        now = time.time()        

        #i wanted to limit to 3 (limit=3) but, boto kept barfing
        results = self._secret_table.query(ip_address__eq=clientIP,not_before__lt=now,consistent=False)
        client_secret = None
        client_secret_not_before = 0

        for result in results:
            if result['not_after'] >= now:
                if client_secret_not_before < result['not_before']:
                    client_secret_not_before = result['not_before']
                    client_secret = self.decryptSecret(result['secret'])


        logging.debug('retrieved secret for %s' % (clientIP))
        return client_secret
                                      


    def purgeSecrets(self, clientIP):
        """
        purge stale secrets associated with IP address

        1) remove all keys for clientIP where not after is older than 
           current time - PURGE_TIME_BEFORE_NOW

        2) scan remaining keys, keep 

        @param clientIP

        @type string

        @returns # of purged secrets
        """

        now = time.time()
        min_purge_time = now

        nr_purged = 0

        # first get rid of expired keys
        results = self._secret_table.query(ip_address__eq=clientIP,
                                           not_after__lt=min_purge_time,
                                           consistent=False,
                                           index='IPNotAfter')
        
        for result in results:
            logging.info('purging secret: %s %d' % (result['ip'],result['not_before']))
            result.delete()
            nr_purged += 1
        
        # now the fun...
        result_list = []
        results = self._secret_table.query(ip_address__eq=clientIP,
                                           not_before__lt=min_purge_time,
                                           consistent=False)

        for result in results:
            result_list.append(result)


        # delete results if there are more than PURGE_RETAIN_NR_ACTIVE results,
        # we want the oldest not befores to be removed first
        if len(result_list) > PURGE_RETAIN_NR_ACTIVE_KEYS:
            for result in sorted(result_list, key=lambda result: result['not_before'])[:-PURGE_RETAIN_NR_ACTIVE_KEYS]:
                logging.info('purging secret: %s %d' % (result['ip'],result['not_before']))
                result.delete()
                nr_purged += 1


        return nr_purged
