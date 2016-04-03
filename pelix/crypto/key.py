from OpenSSL import crypto


# Module version
__version_info__ = (0, 1, 0)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"

class Key:

    TYPE_RSA = crypto.TYPE_RSA
    TYPE_DSA = crypto.TYPE_DSA

    def __init__(self):
        self._pkey = crypto.PKey()
        self._type = None

    def generate_key(self, keyType, bits):
        self._pkey.generate_key(keyType, bits)
        self._type = keyType

    def bits(self):
        return self._pkey.bits()

    def type(self):
        return self._type

    def sign(self, data, digest):
        return crypto.sign(self._pkey, data, digest)
