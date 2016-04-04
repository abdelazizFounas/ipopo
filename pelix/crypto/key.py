from OpenSSL import crypto


# Module version
__version_info__ = (0, 1, 0)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"

class Key:
    """
    Represents a DSA or RSA key pair
    """

    TYPE_RSA = crypto.TYPE_RSA
    """ The key is of type RSA """
    
    TYPE_DSA = crypto.TYPE_DSA
    """ The key is of type DSA """

    def __init__(self):
        """
        Sets up the key pair. 
        """
        self._pkey = crypto.PKey()
        self._type = None

    def generate_key(self, keyType, bits):
        """
        Generates a key pair (private and public keys) into this object

        :param keyType: the type of the key pair (either TYPE_RSA or TYPE_DSA)
        """
        self._pkey.generate_key(keyType, bits)
        self._type = keyType

    def bits(self):
        return self._pkey.bits()

    def type(self):
        return self._type

    def sign(self, data, digest):
        return self._pkey.sign(self._pkey, data, digest)

    def dump_publickey(self):
        return crypto.dump_publickey(crypto.FILETYPE_PEM, self._pkey)
