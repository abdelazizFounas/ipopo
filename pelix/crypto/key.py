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

        :param keyType: The type of the key pair (either TYPE_RSA or TYPE_DSA)
        :param bits: The length of the key
        """
        self._pkey.generate_key(keyType, bits)
        self._type = keyType

    def bits(self):
        """
        Returns the length of the key in bits
        """
        return self._pkey.bits()

    def type(self):
        """
        Returns the type of the key (either TYPE_RSA or TYPE_DSA)
        """
        return self._type

    def sign(self, data, digest):
        """
        Signs a data string using this key and a message digest algorithm
        (for example, sha1 or md5)
        """
        return crypto.sign(self._pkey, data, digest)

    def dump_public(self):
        """
        Dumps the public key of this key pair into a buffer string encoded with the PEM format
        """
        return crypto.dump_publickey(crypto.FILETYPE_PEM, self._pkey)

    def dump_private(self, 	cipher=None, passphrase=None):
    	"""
        Dumps the public key of this key pair into a buffer string encoded with the PEM format
        """
        return crypto.dump_privatekey(crypto.FILETYPE_PEM, self._pkey, cipher, passphrase)

    def load_public(buf):
    	"""
        Loads a public key from a buffer
        """
        key = Key()
        _k = crypto.load_publickey(crypto.FILETYPE_PEM, buf)
        key._pkey = _k
        return key

    def load_private(buf, passphrase=None):
    	"""
        Loads a private key from a buffer
        """
        key = Key()
        _k = crypto.load_private(crypto.FILETYPE_PEM, buf, passphrase)
        key._pkey = _k
        return key

