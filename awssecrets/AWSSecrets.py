
import radiusencryption

class AWSKeys(object):
    """
    wrap up an aws access key

    store it slightly obfuscated in memory to avoid
    accidentally revealing keys

    This could be used to persist the keys in an encrypted
    manner via a slight tweak
    """
    def __init__(self, aws_access_key,aws_secret_key):

        if aws_access_key is None or aws_secret_key is None:
            raise ValueError

        self._aws_access_key = self._encode(aws_access_key)
        self._aws_secret_key = self._encode(aws_secret_key)

    def _encode(self, key):
        return radiusencryption.obfuscate(key)

    def _decode(self, ekey):
        return radiusencryption.deobfuscate(ekey)

    def _getSecretKey(self):
        return self._decode(self._aws_secret_key)

    def _getAccessKey(self):
        return self._decode(self._aws_access_key)

    def _setSecretKey(self, aws_secret_key):
        self._aws_secret_key = self._encode(aws_secret_key)

    def _setAccessKey(self, aws_access_key):
        self._aws_access_key = self._encode(aws_access_key)

    aws_access_key = property(_getAccessKey,_setAccessKey)
    aws_secret_key = property(_getSecretKey,_setSecretKey)

