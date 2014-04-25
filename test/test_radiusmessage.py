import os
import logging
import json
import re
import unittest
import tempfile
from nose.tools import assert_equal
from nose.tools import assert_not_equal
from nose.tools import assert_raises

import random
import json
import base64

from radiusconstants import *
from radiusmessage import *

def get_random_int(min, max, SET=[]):
    random_int = random.randint(min, max)

    if SET != []:
        while random_int in SET:
            random_int = random.randint(min, max)
    
    return random_int

def get_random_string(len):
    return ''.join( [chr(random.randint(0,255)) for i in xrange(0,len)] )

class RadiusMessageTestcase(unittest.TestCase):

    def test_setcode(self):
        
        rm = RadiusMessage()
        
        for code in VALID_RADIUS_CODES:
            rm.code = code

            assert rm.code == code
            assert rm._getCode() == code
            assert rm._code == code

        nr_exceptions = 0
        nr_tries = 10
        for tries in range(0, nr_tries):
            random_code = get_random_int(-MAX_CODE,MAX_CODE,VALID_RADIUS_CODES)

            with self.assertRaises(ValueError):
                rm.code = random_code

        with self.assertRaises(ValueError):
            rm.code = -1

        with self.assertRaises(ValueError):
            rm.code = 'hello'

    def test_setid(self):
        
        rm = RadiusMessage()
        
        for identifier in range(0,MAX_ID):
            rm.identifier = identifier

            assert rm.identifier == identifier
            assert rm._getId() == identifier
            assert rm._id == identifier

        nr_exceptions = 0
        nr_tries = 10
        for tries in range(0, nr_tries):
            random_id = get_random_int(-MAX_ID,1000,range(0,MAX_ID))

            with self.assertRaises(ValueError):
                rm.identifier = random_id
            
        with self.assertRaises(ValueError):
            rm.identifier = -1

        with self.assertRaises(ValueError):
            rm.identifier = 'hello'

    def test_setspecificattribute(self):
        
        rm = RadiusMessage()
        
        for attribute in VALID_RADIUS_ATTRIBUTES:
            rm.setSpecificAttr(attribute,"test")

            assert rm.getSpecificAttr(attribute) == "test"

        nr_exceptions = 0
        nr_tries = 10
        for tries in range(0, nr_tries):
            random_attribute = get_random_int(-MAX_CODE,MAX_CODE,VALID_RADIUS_ATTRIBUTES)

            self.assertRaises(ValueError,lambda: rm.setSpecificAttr(random_attribute,"test"))
            self.assertRaises(ValueError,lambda: rm.getSpecificAttr(random_attribute))
            


        self.assertRaises(ValueError,lambda: rm.setSpecificAttr(-1,"test"))
        self.assertRaises(ValueError,lambda: rm.getSpecificAttr(-1))

        self.assertRaises(ValueError,lambda: rm.setSpecificAttr(1,get_random_string(MAX_ATTRIBUTE_LENGTH+1)))

        self.assertRaises(ValueError,lambda: rm.setSpecificAttr('hello',get_random_string(MAX_ATTRIBUTE_LENGTH+1)))
        self.assertRaises(ValueError,lambda: rm.getSpecificAttr('hello'))
        
    def test_secret(self):
        rm = RadiusMessage()
        
        assert rm.secret is None
        
        rm.secret=get_random_string(MAX_SECRET_LENGTH)

        with self.assertRaises(ValueError):        
            rm.secret=get_random_string(MAX_SECRET_LENGTH+1)
        
    def test_init_and_copy(self):
        
        b64udp_packets = ['AUUALUCjDOwr0lhuEiMSNUwQ9OEBB3VzZXIxAhJptmuOeOyR3MTdofK42mlu', 'A0UAFHVAi08beo6vYi4E6Da3cVI=', 'AfsAOULqcG+v/xHDwCWvIRNxMXoBB3VzZXIxAhLAESO80gZLbHohVn2bK5w2BAZ/AAEBBQYAAAcU', 'AvsAFLnUDEiD72S+yAQFNWCTBN4=']
        udp_packets = map(base64.b64decode,b64udp_packets)

        rm = RadiusMessage()
        assert len(rm) == 20

        with self.assertRaises(ValueError):
            rm = RadiusMessage(datagram=udp_packets[0],request_id=3)

        rm = RadiusMessage(datagram=udp_packets[2])
        assert len(rm) == 57
        assert len(rm) == rm._len #make sure computed len == imported len

        rm2 = rm.copy()

        assert rm.code == RADIUS_ACCESS_REQUEST
        assert rm.code == rm2.code
        assert rm.identifier == rm2.identifier
        assert rm.authenticator == rm2.authenticator
        assert rm._attr_hash == rm2._attr_hash
        assert len(rm) == len(rm2)
        
        #make sure it is a clone, not a reference
        rm2.code = RADIUS_ACCESS_REJECT
        assert rm2.code == RADIUS_ACCESS_REJECT
        assert rm.code == RADIUS_ACCESS_REQUEST


        rm.username="testuser"
        assert rm2.username != rm.username

        with self.assertRaises(ValueError):
            rm.username=get_random_string(MAX_ATTRIBUTE_LENGTH+1)

        with self.assertRaises(ValueError):
            rm.password="testuser"

        rm.secret = 'testing123'
        rm.password="testuser"
        assert rm2.password != rm.username
        assert rm.encryptedPassword != "testuser"

        with self.assertRaises(ValueError):
            rm.username=get_random_string(MAX_ATTRIBUTE_LENGTH+1)

    def test_authenticator(self):
        rm = RadiusMessage()
        a1 = rm._generateAuthenticator()
        a2 = rm._generateAuthenticator()
        assert a1 != a2
        assert len(a1) == MAX_AUTHENTICATOR_LENGTH
        assert len(a2) == MAX_AUTHENTICATOR_LENGTH
        
        rm.authenticator = get_random_string(MAX_AUTHENTICATOR_LENGTH)
        
        with self.assertRaises(ValueError):
            rm.authenticator = get_random_string(MAX_AUTHENTICATOR_LENGTH+1)

    def test_healthcheck(self):
        rm = RadiusMessage()
        
        assert rm.isHealthCheckRequest() is False
        
        rm.makeHealthCheckRequest()
        assert rm.isHealthCheckRequest() is True
        assert rm._attr_hash == {RADIUS_PROXY_STATE: "perform_healthcheck"}
        
        rm.makeHealthCheckRequest("deep")
        assert rm.isHealthCheckRequest() is True
        assert rm._attr_hash == {RADIUS_PROXY_STATE: "deep_healthcheck"}
        
        rm.makeHealthCheckRequest("shallow")
        assert rm.isHealthCheckRequest() is True
        assert rm._attr_hash == {RADIUS_PROXY_STATE: "shallow_healthcheck"}
        

    def test_packets1(self):
        
        #packets from sniffing some traffic, two requests
        # request one: code1->server; code3->client (reject)
        # request two: code1->server; code2->client (accept)
        
        #testing to make sure we're correctly loading off the wire

        b64udp_packets = ['AUUALUCjDOwr0lhuEiMSNUwQ9OEBB3VzZXIxAhJptmuOeOyR3MTdofK42mlu', 'A0UAFHVAi08beo6vYi4E6Da3cVI=', 'AfsAOULqcG+v/xHDwCWvIRNxMXoBB3VzZXIxAhLAESO80gZLbHohVn2bK5w2BAZ/AAEBBQYAAAcU', 'AvsAFLnUDEiD72S+yAQFNWCTBN4=']
        
        udp_packets = map(base64.b64decode,b64udp_packets)

        rms = []
        rms.append(RadiusMessage(datagram=udp_packets[0]))
        rms.append(RadiusResponse(datagram=udp_packets[1]))
        rms.append(RadiusMessage(datagram=udp_packets[2]))
        rms.append(RadiusResponse(datagram=udp_packets[3]))


        #now check the first packet against known data
        #i don't know the secret for the first two packets
        assert rms[0].identifier == 69
        assert rms[0].code == RADIUS_ACCESS_REQUEST
        assert rms[0].encryptedPassword == 'i\xb6k\x8ex\xec\x91\xdc\xc4\xdd\xa1\xf2\xb8\xdain'
        assert len(rms[0]) == rms[0]._len

        assert rms[0].getAttrHash() == {1: 'user1', 2: 'i\xb6k\x8ex\xec\x91\xdc\xc4\xdd\xa1\xf2\xb8\xdain'}

        self.assertRaises(AttributeError,lambda: rms[0].requestAuthenticator)

        #this was a garbage password and secret, so.. decryption won't be that useful
        
        #check the response
        assert rms[1].identifier == 69
        assert rms[1].code == RADIUS_ACCESS_REJECT
        assert len(rms[1]) == rms[1]._len

        # now check the sane two packets

        assert rms[2].identifier == 251
        assert rms[2].code == RADIUS_ACCESS_REQUEST
        assert rms[2].encryptedPassword == '\xc0\x11#\xbc\xd2\x06Klz!V}\x9b+\x9c6'
        assert rms[2].secret is None
        assert len(rms[2]) == rms[2]._len
        assert rms[2].getAttrHash() == {1: 'user1', 2: '\xc0\x11#\xbc\xd2\x06Klz!V}\x9b+\x9c6', 4: '\x7f\x00\x01\x01', 5: '\x00\x00\x07\x14'}
        assert rms[2].getUDPDatagram() == udp_packets[2]

        rms[2].secret = "testing123"
        assert rms[2].secret == 'testing123'
        assert rms[2].password  == 'supersecret'
        

        #verify response validation
        assert rms[2].checkDatagram(udp_packets[3]) == True

        #change secret, verify password is re-encrypted
        #verify validation fails
        #critical thing for proxy behavior 

        rms[2].secret = "testing456"
        assert rms[2].checkDatagram(udp_packets[3]) == False
        assert rms[2].encryptedPassword == '\x81z@04X\x90Xa3N\x92\x11!r\xcc'
        assert rms[2].password  == 'supersecret'
        assert rms[2].getUDPDatagram() != udp_packets[2]

        # and change back
        rms[2].secret = "testing123"
        assert rms[2].encryptedPassword == '\xc0\x11#\xbc\xd2\x06Klz!V}\x9b+\x9c6'
        assert rms[2].password  == 'supersecret'
        assert rms[2].getUDPDatagram() == udp_packets[2]        

        #check response packet

        assert rms[3].identifier == 251
        assert rms[3].identifier == rms[2].identifier
        assert rms[3].code == RADIUS_ACCESS_ACCEPT
        assert len(rms[3]) == rms[3]._len        
        assert rms[3].getAttrHash() == {}

        self.assertRaises(ValueError, lambda: rms[3].getUDPDatagram() == udp_packets[3])
        rms[3].secret='testing123'

        self.assertRaises(ValueError, lambda: rms[3].getUDPDatagram() == udp_packets[3])
        
        rms[3].requestAuthenticator = rms[2].authenticator

        assert rms[3].getUDPDatagram() == udp_packets[3]        
        assert rms[2].checkDatagram(rms[3].getUDPDatagram()) == True
        assert rms[2].authenticator == rms[3].requestAuthenticator


        #throw in a message back to the client, confirm that works
        rms[3].setSpecificAttr(RADIUS_REPLY_MESSAGE,"message to user")
        assert rms[3].getAttrHash() == {18: 'message to user'}
        assert rms[3].getUDPDatagram() == '\x02\xfb\x00%L\xa0H\n\x9bq\xa5`9\x04\xef\xac\x8d1~\x11\x12\x11message to user'

        
if __name__ == '__main__':
    unittest.main()
