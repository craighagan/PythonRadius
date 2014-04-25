
import logging
from radiusconstants import *
from select import select
from struct import pack,unpack
try:
    from hashlib import md5
except ImportError:
    from md5 import new as md5
          

  
class RadiusMessage(object):
    """
    data representing a radius message
 
    based upon data gleaned from:

    http://tools.ietf.org/html/rfc2865
    http://www.untruth.org/~josh/security/radius/radius-auth.html
    http://code.google.com/p/dpkt/source/browse/trunk/dpkt/radius.py

    and trying things out.

    Message/Requests and responses are different; You'll want to use
    RadiusRequest for a Request
    RadiusResponse for a Response

    The packets look like this:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         Authenticator                         |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

   Code: Type of packet, see constants

   Identifier: unique identifier to allow a server to distinguish 
            multiple authentication requests from the same client

   Length: size of the packet in octets

   Authenticator is a randomly chosen string, 

   Attributes are a an 8bit length and a string concatenated together; 
   per the rfc, the maximum attribute sizes are:

      text      1-253 octets containing UTF-8 encoded 10646 [7]
                characters.  Text of length zero (0) MUST NOT be sent;
                omit the entire attribute instead.

      string    1-253 octets containing binary data (values 0 through
                255 decimal, inclusive).  Strings of length zero (0)
                MUST NOT be sent; omit the entire attribute instead.
      
      address   32 bit value, most significant octet first.
      
      integer   32 bit unsigned value, most significant octet first.

      time      32 bit unsigned value, most significant octet first --
                seconds since 00:00:00 UTC, January 1, 1970.  The
                standard Attributes do not use this data type but it is
                presented here for possible use in future attributes.
                
      The minimum message size is 20, maximum size is 4096

   If you are playing with this you may want to look at radtest which comes with freeRadius
   
   """

    def __init__(self, 
                 code=None,
                 request_id=None,
                 length=None,
                 authenticator=None,
                 attrs=[],
                 datagram=None,
                 secret=None,
                 ):
        """
        Many of the initilization parameters are set so that specific packets
        can be created on the fly

        @param code : radius packet type code

        @param id: radius message id
        
        @param len: packet length
        
        @param authenticator: random string used for obfuscation and packet validation
        
        @param auth_digest: a hash to allow verification of the packet
        
        @param secret: the radius secret
        
        @param attr_hash: populate the attribute hash
        
        @param datagram: udp datagram to use for constructing the RadiusMessage object
        

        @type code: unsigned short int 
        
        @type id: unsigned short int
        
        @type len: unsigned int (16bits)
        
        @type authenticator string
        
        @type auth_digest string
        
        @type secret string
        
        @type attr_hash dict
        
        @type datagram string

        """


        self._code = code
        self._id = request_id
        #self._len = length
        self._authenticator = authenticator
        self._auth_digest = None
        self._attrs = attrs
        self._secret = secret
        self._attr_hash = {}

        if datagram is not None:
            # no other initializations allowed, except a secret, if we're
            # passed a datagram

            if request_id is not None or code is not None or length is not None or authenticator is not None or attrs != []:
                raise ValueError("no other initializations except secret allowed when using a datagram to create a radius message object")
            else:
                self._loadFromRadiusDatagram(datagram)

        if self.attrs is not None and isinstance(self.attrs, (list, tuple)):
            for (attr_id,attr_value) in self.attrs:
                self._attr_hash[attr_id] = attr_value

    def copy(self):
        """
        creates a proper/true copy of the Request
        
        useful for a proxy as it can copy the request, then change the secrets,
        and modify any attributes which need changing without impairing
        the original object.
        
        """
        new = RadiusMessage(code=self.code,
                            request_id=self.identifier,
                            length=len(self),
                            authenticator=self.authenticator,
                            attrs=self.attrs,
                            secret=self.secret)
                            
        
        return new
                            

    def __repr__(self):
        """
        This is to help examine problems, this prints out contents
        of the message
        """

        output = """
{
"code": %d,
"identifier": %d,
"len": %d,
"authenticator": %s,
"authdigest": %s,
"attrs": %s,
"attrhash": %s,
"secret": %s,
"encpass": %s,
"clrpass": %s
}
        """ % (self.code,
               self.identifier,
               len(self),
               self.authenticator,
               self._auth_digest,
               repr(self._attrs),
               repr(self._attr_hash),
               self.secret,
               self.encryptedPassword,
               self.password)
        
        return output

        
    def __len__(self):
        """
        recompute the length of the message
        based upon current attributes, etc
        """

        # headers/etc
        new_len = 20
        
        #add length of all attributes
        for key in self._attr_hash:
            new_len += len(self._attr_hash[key])
            new_len += 2 #for the key/value pieces

        return new_len

    def updateAuth(self):
        """
        performs changes needed if the authenticator is updated, e.g.
        if there is a password attribute, it will be reobfuscated
        """
        clear_pass = self.password
        
        if clear_pass is not None:
            password = clear_pass

    def _generateAuthenticator(self):
        with open("/dev/urandom", "rb") as fd:
            result = range(0,MAX_AUTHENTICATOR_LENGTH+1)
            result[0] = '16B'

            for i in range(1,MAX_AUTHENTICATOR_LENGTH+1):
                result[i] = ord(fd.read(1))
            return apply(pack,result)


    def _setAuthenticator(self, auth):
        """
        set or change the authenticator
        
        this will then update internal attributes if required

        @param auth

        @type auth: string; max 16 octets

        """

        if len(auth) > MAX_AUTHENTICATOR_LENGTH:
            raise ValueError("The Authenticator may not be more than %d chars" % MAX_AUTHENTICATOR_LENGTH)

        self._authenticator = auth
        self.updateAuth()

    def _setId(self, id):
        """
        set the id of the packet. This is an arbitrary number between 0 and 255
        to allow the client and server to distinguish between multiple
        requests from the same client.

        @param id
        
        @type id: short int

        """

        if not isinstance(id, (int, long)):
            raise ValueError("id must be an integer radius id code")

        if id < 0 or id > MAX_ID:
            raise ValueError("id must bebetween 0 and %d" % MAX_ID)

        self._id = id
        self.updateAuth()

    def _setCode(self, code):
        """
        Set the radius packet code (type of packet)

        @param code

        @type code: short int
        """
        if not isinstance(code, (int, long)):        
            raise ValueError("code must be an integer radius code")

        if code not in VALID_RADIUS_CODES:
            raise ValueError("id must be a valid radius id code")

        self._code = code
        self.updateAuth()

    def _setAttrs(self, attrs):
        """
        set the attribute list, then populate the attribute hash

        @param attrs 
        
        @type attrs: list

        """
        
        self._attrs = attrs

        self._attr_hash = {}
        
        for (attr_id,attr_value) in self.attrs:
            self._attr_hash[attr_id] = attr_value

        self.updateAuth()

    def getSpecificAttr(self, key):
        """
        return the value of a specific attribute

        @param key

        @type key: short int

        """
        if not isinstance(key, (int, long)):
            raise ValueError("key must be an integer radius attribute code")

        if key not in VALID_RADIUS_ATTRIBUTES:
            raise ValueError("key must be a valid radius attribute code")

        if key in self._attr_hash:
            return self._attr_hash[key]
        else:
            return None

    def setSpecificAttr(self, key, value):
        """
        assign a radius attribute

        this updates the radius attribute dict, then fcalls updateAttrs to flatten it
        """

        if not isinstance(key, (int, long)):
            raise ValueError("key must be an integer radius attribute code")

        if key not in VALID_RADIUS_ATTRIBUTES:
            raise ValueError("key must be a valid radius attribute code")

        if len(value) > MAX_ATTRIBUTE_LENGTH:
            raise ValueError("value longer than %d not supported" % MAX_ATTRIBUTE_LENGTH)

        self._attr_hash[key] = value
        self._updateAttrs()

    def _setSecret(self, secret):
        """ 
        set or change the secret
        
        if the secret is changed, the impacted contents 
        of the message are recomputed

        From RFC 2865:

        Administrative Note

        The secret (password shared between the client and the RADIUS server) 
        SHOULD be at least as large and unguessable as a well- chosen password. 
        It is preferred that the secret be at least 16 octets. This is to ensure 
        a sufficiently large range for the secret to provide protection against 
        exhaustive search attacks. The secret MUST NOT be empty (length 0) since 
        this would allow packets to be trivially forged.

        From google, freeradius used to have a limit of 32 chars, it is now 60.

        apparently many implementations have a limit of 63 chars (at least some cisco gear) 

        from a theoretical standpoint there is no real need for a limit, but the returns
        are minimal due to how it is used

        """

        if len(secret) > MAX_SECRET_LENGTH:
            raise ValueError("the secret may not be more than %d characters, or many things may break" % MAX_SECRET_LENGTH)
        
        clear_pass = self.password
        self._secret = secret

        if clear_pass is not None:
            self.password = clear_pass

        self.updateAuth()

    def _getCode(self):
        return self._code

    def _getId(self):
        return self._id
    
    def _getLen(self):
        return self._len

    def _getAuthenticator(self):
        return self._authenticator

    def _getAuthDigest(self):
        return self._auth_digest

    def _getAttrs(self):
        return self._attrs

    def getAttrHash(self):
        return self._attr_hash

    def _getSecret(self):
        return self._secret

    def _getUsername(self):
        return self.getSpecificAttr(RADIUS_USER_NAME)

    def isAccessRequest(self):
        return self._code == RADIUS_ACCESS_REQUEST

    def isHealthCheckRequest(self):
        """
        this isn't an official packet, this is a made
        up thing with some parameters which
        shouldn't normally be in play
        that tells the calling system to perform
        a basic healthcheck
        """
        try:
            if self._code == RADIUS_ACCT_STATUS and \
                   self._attr_hash[RADIUS_PROXY_STATE] in ["perform_healthcheck","deep_healthcheck","shallow_healthcheck"]:
                return True
            else:
                return False
        except KeyError:
            return False

    def isDeepHealthCheckRequest(self):
        """
        this isn't an official packet, this is a made
        up thing with some parameters which
        shouldn't normally be in play
        that tells the calling system to perform
        a deep healthcheck
        """
        try:
            if self._code == RADIUS_ACCT_STATUS and \
                   self._attr_hash[RADIUS_PROXY_STATE] in ["perform_healthcheck","deep_healthcheck"]:
                return True
            else:
                return False
        except KeyError:
            return False

        
    def makeHealthCheckRequest(self,type=""):
        """
        make the current request a healthcheck
        """
        self._code = RADIUS_ACCT_STATUS

        if type in ["deep","deep_healthcheck"]:
            self._attr_hash = {RADIUS_PROXY_STATE: "deep_healthcheck"}
        elif type in ["shallow","shallow_healthcheck"]:
            self._attr_hash = {RADIUS_PROXY_STATE: "shallow_healthcheck"}
        else:
            self._attr_hash = {RADIUS_PROXY_STATE: "perform_healthcheck"}

    def _updateAttrs(self):
        """ 
        update atributes of the message

        internally, attributes are stored as a dict, this flattens it out into
        a list of tuples for serialization into a udp datagram

        """

        new_attrs = []

        if self.attrs is not None and isinstance(self.attrs, (list, tuple)):
            for key in sorted(self._attr_hash.keys()):
                attr_tuple = (key, self._attr_hash[key])
                new_attrs.append(attr_tuple)

        self._attrs = new_attrs

    def _setUsername(self, username):
        """
        set the username attribute; provided for convenience

        @param username

        @type username: string

        """
        
        if len(username) > MAX_ATTRIBUTE_LENGTH:
            raise ValueError("username exceeds %d bytes" % MAX_ATTRIBUTE_LENGTH)

        self.setSpecificAttr(RADIUS_USER_NAME, username)

    def _setPassword(self, password):
        """
        set the password contained in the message (if it contains one)
        if no authenticator exists (a random string), one is generated
        and set. 

        @params password

        @type password string
        """
        
        if len(password) > MAX_ATTRIBUTE_LENGTH:
            raise ValueError('Password exceeds maximun of %d bytes' % MAX_ATTRIBUTE_LENGTH)            
        
        if self.secret is None:
            raise ValueError('A secret must be defined to set the password')

        if self._authenticator is None:
            self._authenticator = self._generateAuthenticator()
            enc_pass = self._radiusObfuscate(password)

        else:
            enc_pass = self._radiusObfuscate(password)

        self.setSpecificAttr(RADIUS_USER_PASSWORD, enc_pass)

    def _getEncryptedPassword(self):
        return self.getSpecificAttr(RADIUS_USER_PASSWORD)
            
    def _getClearPassword(self):
        """
        decrypt and return the cleartext password
        """

        if RADIUS_USER_PASSWORD in self._attr_hash and self.authenticator is not None and self.secret is not None:
            return self._radiusDeobfuscate(self._attr_hash[RADIUS_USER_PASSWORD])
        else:
            return None

    def getUDPDatagram(self):
        """
        serialize the message into a valid radius udp datagram
        for transmission
        """
        
        if self._authenticator is None:
            self.authenticator = self._generateAuthenticator()
            
        msg = pack('!B B H 16s',
                   self.code,self.identifier,
                   len(self), # Length of entire message
                   self.authenticator)

        for key in self._attr_hash:            
            attr_msg = pack('!B B %ds' \
                       % (len(self._attr_hash[key])),
                            key,len(self._attr_hash[key])+2,self._attr_hash[key])

            msg += attr_msg

        self._auth_digest = md5(msg).digest()
        
        return msg

    def _radiusObfuscate(self,text):
        """
        Obfuscate a password with the secret

        @param text

        @type text: string

        """

        # stolen from http://code.google.com/p/dpkt/source/browse/trunk/dpkt/radius.py
        # with slight changes

        if self.secret is None:
            raise ValueError('A secret must be defined before encrypting data')

        if self.authenticator is None:
            self.authenticator = self._generateAuthenticator()

        # First, pad the password to multiple of 16 octets.
        text += chr(0) * (16 - (len(text) % 16))
        if len(text) > MAX_ATTRIBUTE_LENGTH:
            raise ValueError('Password exceeds maximun of %d bytes' % MAX_ATTRIBUTE_LENGTH)
        result = ''
        last = self.authenticator
        while text:
            # md5sum the shared secret with the authenticator,
            # after the first iteration, the authenticator is the previous
            # result of our encryption.
            hash = md5(self.secret + last).digest()
            for i in range(16):
                result += chr(ord(hash[i]) ^ ord(text[i]))
            # The next iteration will act upon the next 16 octets of the password
            # and the result of our xor operation above. We will set last to
            # the last 16 octets of our result (the xor we just completed). And
            # remove the first 16 octets from the password.
            last, text = result[-16:], text[16:]
        return result

    def _radiusDeobfuscate(self, text):
        """
        Obfuscate a password with the secret

        @param text

        @type text: string

        """

        # stolen from http://code.google.com/p/dpkt/source/browse/trunk/dpkt/radius.py
        # with slight changes

        if self.secret is None:
            raise ValueError('A secret must be defined before decrypting data')

        if self.authenticator is None:
            raise ValueError('An authenticator must be defined before decrypting data')

        result = ''
        last = self.authenticator
        while text:
            # md5sum the shared secret with the authenticator,
            # after the first iteration, the authenticator is the previous
            # result of our encryption.
            hash = md5(self.secret + last).digest()
            for i in range(16):
                result += chr(ord(hash[i]) ^ ord(text[i]))
            # The next iteration will act upon the next 16 octets of the password
            # and the result of our xor operation above. We will set last to
            # the last 16 octets of our result (the xor we just completed). And
            # remove the first 16 octets from the password.
            last, text = result[-16:], text[16:]
            return result.rstrip('\x00')

    def _loadFromRadiusDatagram(self,datagram):
        """
        parse a radius datagram and populate self

        @param datagram

        @type datagram: string (radius udp datagram)
        """

        #get the header
        (r_code,r_id,r_len,r_auth) = unpack('!B B H 16s',datagram[0:20])

        attrs = []
        buf = datagram[20:]

        # pulled from dpkt radius module
        while buf:
            t = ord(buf[0])
            l = ord(buf[1])
            if l< 2:
                break
            d,buf = buf[2:l],buf[l:]
            attrs.append((t,d))    

        self.code = r_code
        self.identifier = r_id
        self._len = r_len
        self.authenticator = r_auth
        self.attrs = attrs


    def checkDatagram(self, datagram):
        """
        check a datagram and verify that the message auth key
        correctly validates it

        @params datagram

        @type datagram: string (radius udp datagram)

        """
        check = datagram[4:20]
        m = md5(datagram[0:4] + self.authenticator + datagram[20:] + self.secret).digest()

        return m == check

    def checkAuth(self, authenticator):
        """
        checking a datagram isn't really sane against a request
        """
        raise NotImplementedError


    code = property(_getCode,_setCode)
    identifier = property(_getId,_setId)
    authenticator = property(_getAuthenticator,_setAuthenticator)
    auth_digest = property(_getAuthDigest)
    secret = property(_getSecret,_setSecret)
    attrs = property(_getAttrs,_setAttrs)
    username = property(_getUsername,_setUsername)
    password = property(_getClearPassword,_setPassword)
    encryptedPassword = property(_getEncryptedPassword,_setPassword)

class RadiusRequest(RadiusMessage):
    """
    this is here for completeness, the methods are (currently)
    the same as the base object

    I'd suggest using this instead of the base class for clarity
    """
    pass

class RadiusResponse(RadiusMessage):
    """
    class to represent a radius authentication response message
    this lets us configure routines to update the length and auth    

    this differs from a request in that the authenticator has a different format

    ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attributes+Secret) where + denotes concatenation
    """

    def __init__(self, 
                 code=None,
                 request_id=None,
                 length=None,
                 authenticator=None,
                 attrs=[],
                 datagram=None,
                 secret=None,
                 request_auth=None):
        """
        Many of the initilization parameters are set so that specific packets
        can be created on the fly
        
        @param code : radius packet type code
        
        @param id: radius message id
        
        @param len: packet length

        @param authenticator: random string used for obfuscation and packet validation

        @param auth_digest: a hash to allow verification of the packet

        @param secret: the radius secret

        @param attr_hash: populate the attribute hash

        @param datagram: udp datagram to use for constructing the RadiusMessage object


        @type code: unsigned short int 

        @type id: unsigned short int
        
        @type len: unsigned int (16bits)
        
        @type authenticator string
        
        @type auth_digest string
        
        @type secret string
        
        @type attr_hash dict
        
        @type datagram string
        """

        self._request_auth = request_auth
        super(self.__class__,self).__init__(code=code,
                                            request_id=request_id,
                                            length=length,
                                            authenticator=authenticator,
                                            attrs=attrs,
                                            datagram=datagram,
                                            secret=secret)

    def copy(self):
        new = RadiusResponse(code=self.code,
                             request_id=self.identifier,
                             length=len(self),
                             authenticator=self.authenticator,
                             attrs=self.attrs,
                             secret=self.secret,
                             request_auth=self.requestAuthenticator)

        return new
        
    def __repr__(self):
        output = """
{
"code": %d,
"identifier": %d,
"len": %d,
"authenticator": %s,
"authdigest": %s,
"attrs": %s,
"attrhash": %s,
"secret": %s,
"encpass": %s,
"clrpass": %s,
"request_auth": %s,
}
        """ % (self.code,
               self.identifier,
               len(self),
               self.authenticator,
               self._auth_digest,
               repr(self._attrs),
               repr(self._attr_hash),
               self.secret,
               self.encryptedPassword,
               self.password,
               self.requestAuthenticator)

        return output

    def getUDPDatagram(self):
        """
        serialize the message into a valid radius udp datagram
        for transmission
        """

        if self.secret is None:
            raise ValueError('A secret must be defined')

        if self.identifier is None:
            raise ValueError('An id must be defined')

        if self.requestAuthenticator is None:
            raise ValueError('A request authenticator must be defined')

        resp_auth = pack('!B B H 16s',
                         self.code,
                         self.identifier,
                         len(self),
                         self.requestAuthenticator)
        
        for key in self._attr_hash:
            resp_auth += pack('!B B %ds' % (len(self._attr_hash[key])),key,len(self._attr_hash[key])+2,self._attr_hash[key])

        resp_auth += pack('!%ds' % (len(self.secret)),self.secret)

        self._auth_digest = md5(resp_auth).digest()

        msg = pack('!B B H 16s', self.code, self.identifier, len(self), self._auth_digest)
            
        for key in self._attr_hash:            
            attr_msg = pack('!B B %ds' \
                       % (len(self._attr_hash[key])),
                            key,len(self._attr_hash[key])+2,self._attr_hash[key])
            msg += attr_msg


        return msg

    def _setRequestAuthenticator(self, request_auth):
        """
        set request authenticator
        
        requests use the authenticator from the requesting packet
        as part of their validation

        this sets it and updates relevant internals

        @param request_auth

        @type request_auth string

        """

        if len(request_auth) > MAX_AUTHENTICATOR_LENGTH:
            raise ValueError("The request authenticator may not be more than %d chars " % MAX_AUTHENTICATOR_LENGTH)

        self._request_auth = request_auth
        self.updateAuth()

    def _getRequestAuthenticator(self):
        return self._request_auth
        
    def checkDatagram(self, datagram):
        """
        check a datagram and verify that the message auth key
        correctly validates it

        @params datagram

        @type datagram: string (radius udp datagram)
        """

        if self.requestAuthenticator is None:
            raise ValueError("no authenticator is set")

        if self.secret is None:
            raise ValueError("no secret is set")

        check = datagram[4:20]
        m = md5(datagram[0:4] + self.requestAuthenticator + datagram[20:] + self.secret).digest()
        
        return m == check

    def checkAuth(self, authenticator):
        """
        check that an authenticator correctly validates this message object

        @params authenticator

        @type athenticator: string
        """
        datagram = self.getUDPDatagram()

        check = datagram[4:20]        
        m = md5(datagram[0:4] + authenticator + datagram[20:] + self.secret).digest()
        
        return check == m

    requestAuthenticator = property(_getRequestAuthenticator,_setRequestAuthenticator)





