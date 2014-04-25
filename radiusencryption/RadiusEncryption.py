
from Crypto import Random
from Crypto.Cipher import AES
import base64

import hashlib

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE) 
unpad = lambda s : s[0:-ord(s[-1])]

class AESCipher:
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

class DataEncryptor(object):

    def __init__(self, passphrase, key=None):

        if key is not None:
            self.key = key
        elif passphrase is None:
            raise ValueError("you must specify an encryption passphrase")
        else:
            self.key = hashlib.sha256(passphrase).digest()

        self.encryptor = AESCipher(self.key)

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, encrypted_data):
        return self.encryptor.decrypt(encrypted_data)
