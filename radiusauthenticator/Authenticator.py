
import hmac, base64, struct, hashlib, time
import sys
import sqlite3
import time
import logging

class Authenticator(object):

    def authenticateUser(self,username, password):
        """
        verify that a given username/password pair is valid

        @param username

        @param password

        @type username string

        @type password string

        return boolean
        
        """
        raise NotImplementedError
    

class AlwaysFalse(Authenticator):

    def authenticateUser(self,username, password):
        """
        authenticate user, example case - always return false

        @param username
        
        @param password
        
        @type username string
        
        @type password string

        return boolean
        
        """

        return False


class GoogleAuth(Authenticator):
    """
    use the google auth method
    """

    def _getGoogleAuthSecrets(self,username):
        """
        obtain the google auth secrets for a user
        """
        raise NotImplementedError

    def _getHotpToken(self,secret, intervals_no):
        """
        compute the one time password for a google auth
        secret
        """
        key = base64.b32decode(secret)
        msg = struct.pack(">Q", intervals_no)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = ord(h[19]) & 15
        h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
        return h

    def _getTotpToken(self,secret,now=None):
        """
        given a google auth secret, return the one time password

        @param secret google auth secret

        @param now : current time in seconds since epoch format (for testing)

        @type secret strnig

        @type now number
        """

        if now is None:
            now = time.time()

        now=int(now)
        
        return self._getHotpToken(secret, intervals_no=now//30)


    def authenticateUser(self,username, password, now=None):
        """
        authenticate user, example case - always return false

        @param username
        
        @param password

        @param now current time in seconds since epoch
        
        @type username string
        
        @type password string

        @type now number

        return boolean
        
        """

        if now is None:
            now = int(time.time())
        
        now = int(now)
        

        token = "%0.6d" % self._getTotpToken(self._getGoogleAuthSecrets(username),now=now)

        return token == str(password)

class GoogleAuthSQLite(GoogleAuth):
    """
    google auth class using sqlite backend for user tokens
    """

    def __init__(self, userdbfile, table_name="user_tokens"):
        """
        @param userdbfile file to sqlite user database

        @type userdbfile string (filepath)

        """


        super(self.__class__,self).__init__()

        if table_name is None:
            raise ValueError("table name containing user_tokens must be specified")

        self._valid_usertypes = ['OTP','P']
        self._userdbfile = userdbfile
        self._table_name = table_name 
        self._userdb = sqlite3.connect(userdbfile,check_same_thread=False)
        self._createTable()

    def putUserToken(self, username=None, token="", passprefix="",not_before=None,not_after=None,user_type=""):
        """
        store a user token

        @param username username for data being stored

        @param token google auth token being stored

        @param passprefix prefix to one time password being stored (or password for non otp use)

        @param not_before seconds since epoch after which token is valid

        @param not_after seconds since epoch after which token is invalid

        @param user_type type of auth: otp or std password

        @type username string

        @type token string

        @type not_before number

        @type not_after number

        @type user_type string (in set of self._valid_usertypes)
        """

        assert(isinstance(username,basestring))
        assert(isinstance(token,basestring))
        assert(isinstance(passprefix,basestring))

        #default expire time is 10 years
        now = time.time()

        if not_after is None:
            not_after = now + 365*86400*10
        else:
            not_after = int(not_after)

        if not_before is None:
            not_before = now
        else:
            not_before = int(not_before)

        if user_type == "":
            user_type ='OTP'

        if user_type == 'OTP' and token == "":
            raise ValueError('token must be specified if user type is OTP')

        if user_type == 'OTP':
            #vet token
            try:
                base64.b32decode(token)
            except TypeError:
                raise ValueError("token must be a proper google auth token which is a base32 encoded string")
            

        if user_type == 'P' and passprefix == "":
            raise ValueError('passprefix must be specified if user type is P')

        if user_type not in self._valid_usertypes:
            raise ValueError('user type must be in %s'%(self._valid_usertypes))

        self._userdb.execute('insert into %s values (:created, :user_type, :not_before, :not_after, :username, :passprefix, :token)' % (self._table_name),
                             {'created': now,
                              'user_type': user_type,
                              'not_before':not_before,
                              'not_after':not_after,
                              'username': username,
                              'passprefix':passprefix,
                              'token':token})
        logging.debug("inserted user token %d %s %d %d %s %s %s into table %s" % (now,user_type,not_before,not_after,username,passprefix,token,self._table_name) )
        self._userdb.commit()


    def _createTable(self):
        """
        create sqlite table
        """
        
        try:
            self._userdb.execute('create table %s (created number, user_type string,not_before number, not_after number, username text, passprefix text, token text)' % (self._table_name))
            self._userdb.commit()
            logging.debug("created sqlite table %s" % self._table_name)
            
        except sqlite3.OperationalError as e:
            logging.debug("failed to create table %s, usually this means table already exists %s " % (self._table_name, e))
            pass

    def getUserTokens(self,username):
        """
        given a username, return a vector of 
        [(username, user_type, passwordprefix, token, created, not_before, not_after)]

        @param username

        @type username string

        returns list of lists
        """

        assert(isinstance(username,basestring))

        results=self._userdb.execute('select username, user_type, passprefix,token,created,not_before,not_after from %s where username=:username order by created desc' % self._table_name, {'username':username}).fetchall()

        return results

    def deleteUserTokens(self,username=None,user_type=None,not_after=None,not_before=None):
        """
        delete user tokens

        @param username

        @param user_type

        @param not_after

        @param not_before

        @type username string

        @type user_type string

        @type not_after number

        @type not_before number
        """

        #make sure that params are presented and are correct types (default of none will fail missing params)
        assert(isinstance(username,basestring))
        assert(isinstance(user_type,basestring))
        assert(isinstance(not_after,(float,int)))
        assert(isinstance(not_before,(float,int)))

        if user_type not in self._valid_usertypes:
            raise ValueError('user type must be in %s'%(self._valid_usertypes))

        results=self._userdb.execute('delete from %s where username=:username and not_after=:not_after and not_before=:not_before and user_type=:user_type' % self._table_name,{'username':username,'not_after':not_after,'not_before':not_before,'user_type':user_type})

    def _getGoogleAuthSecrets(self,username):
        """
        given a username, return a vector of 
        [(username, user_type, passwordprefix, token)]

        @param username

        @type username string

        returns list of lists
        """

        assert(isinstance(username,basestring))

        now = time.time()
        results=self._userdb.execute('select username, user_type, passprefix,token from %s where username=:username and not_after > :now and not_before < :now order by created desc' % self._table_name, {'now':now,'username':username}).fetchall()

        #in theory there could be multiple valid tokens for a user
        #i dislike this; this returns the lot
        #could just send back the first row (newest key, in theory based upon dates)

        return results

    def authenticateUser(self,username, password, now=None):
        """
        authenticate the user against a list of valid tokens/prefixes

        @param username username to auth

        @param password plaintext password

        @param now current time seconds since epoch

        @type username string

        @type password string

        @type now number

        returns True if user/pass are valid, else False

        """

        assert(isinstance(username,basestring))
        assert(isinstance(password,(basestring,int,float)))

        if now is None:
            now = time.time()        

        results = self._getGoogleAuthSecrets(username)

        for (ex_username, user_type, ex_passprefix,token) in results:
            logging.debug("try to validate user %s type %s" % (ex_username, user_type))
            
            if ex_username != username:
                raise ValueError('got incorrect username from data store')

            if user_type == 'P':
                if ex_passprefix == password:
                    return True

            if user_type == 'OTP':
                ex_token = self._getTotpToken(token,now=now)
                ex_pass = ex_passprefix + "%0.6d" % ex_token

                try:
                    if ex_pass == password:
                        return True
                except UnicodeWarning:
                    #this rears up with incorrect keys
                    return False

        return False


