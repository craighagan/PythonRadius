import os
import logging
import json
import re
import unittest
import tempfile
#from nose.tools import assert_equal
#from nose.tools import assert_not_equal
#from nose.tools import assert_raises
import tempfile

from radiusauthenticator import *

class AuthenticatorTest(unittest.TestCase):

    def test_base_authenticate_user(self):
        
        auth=Authenticator()
        with self.assertRaises(NotImplementedError):
            auth.authenticateUser('test','test')
            
class AuthenticatorFalseTest(unittest.TestCase):
    def test_false_authenticate_user(self):

        auth=AlwaysFalse()

        self.assertEqual(auth.authenticateUser('test','test'), False)

class GoogleAuthTest(unittest.TestCase):
    def test_gabase_authenticate_user(self):

        auth=GoogleAuth()

        #test otp
        test_secret = 'NBSWY3DPO5XXE3DE'
        now=1376653367
        self.assertEqual(auth._getTotpToken(test_secret, now), 567458)

        now=1376653523.475096
        self.assertEqual(auth._getTotpToken(test_secret, now), 576474)

        # data store isn't built
        with self.assertRaises(NotImplementedError):
            auth.authenticateUser('test','test')       

class GoogleAuthSQLiteTest(unittest.TestCase):

    @classmethod
    def setUpClass(GoogleAuthSQLiteTest):
        GoogleAuthSQLiteTest.userdbfile = tempfile.NamedTemporaryFile(delete=False).name
        #GoogleAuthSQLiteTest.userdbfile = "/tmp/testgauth"

        GoogleAuthSQLiteTest.auth=GoogleAuthSQLite(GoogleAuthSQLiteTest.userdbfile)

        GoogleAuthSQLiteTest.auth.putUserToken(username='testotp',token='NBSWY3DPO5XXE3DE')
        GoogleAuthSQLiteTest.auth.putUserToken(username='testfix',passprefix='toomanysecrets',user_type='P')


    @classmethod
    def tearDownClass(GoogleAuthSQLiteTest):
        try:
            os.unlink(GoogleAuthSQLiteTest.userdbfile)
            os.unlink(GoogleAuthSQLiteTest.userdbfile+"-journal")
        except OSError:
            pass
        
    def test_gasqlite_store(self):

        #creating this should initialize the store
        #auth=GoogleAuthSQLite(GoogleAuthSQLiteTest.userdbfile)

        with self.assertRaises(ValueError):
            self.auth.putUserToken(username='testotp',token='')
            self.auth.putUserToken(username='testotp',token='thisshouldfail')
            self.auth.putUserToken(username='testfix',token='toomanysecrets',user_type='P')
            
        r=self.auth.getUserTokens('testotp')
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0][:4], (u'testotp', u'OTP', u'', u'NBSWY3DPO5XXE3DE'))

        r=self.auth.getUserTokens('testfix')
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0][:4], (u'testfix', u'P', u'toomanysecrets', u''))
        
        self.auth.putUserToken(username='testfix',passprefix='zorg',user_type='P')
        r=self.auth.getUserTokens('testfix')
        self.assertEqual(len(r), 2)

        #results ordered by creation time
        self.assertEqual(r[0][:4], (u'testfix', u'P', u'zorg', u''))
        self.assertEqual(r[1][:4], (u'testfix', u'P', u'toomanysecrets', u''))

        (username, user_type, passprefix,token,created,not_before,not_after) = r[0]
        self.auth.deleteUserTokens(username=username,user_type=user_type,not_before=not_before,not_after=not_after)
        r=self.auth.getUserTokens('testfix')
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0][:4], (u'testfix', u'P', u'toomanysecrets', u''))
        
    def test_gasqlite_authenticate_user(self):
        now = 1376653367
        self.assertTrue(self.auth.authenticateUser('testotp','567458',now=now))
        self.assertFalse(self.auth.authenticateUser('testotp','123456',now=now))

        now = 1376653523.475096
        self.assertFalse(self.auth.authenticateUser('testotp','567458',now=now))
        self.assertTrue(self.auth.authenticateUser('testotp','576474',now=now))
        self.assertFalse(self.auth.authenticateUser('testotp','123456',now=now))

        self.assertTrue(self.auth.authenticateUser('testfix','toomanysecrets'))
        self.assertFalse(self.auth.authenticateUser('testfix','somethingelse'))
        


    
if __name__ == '__main__':    
    unittest.main()
