from pelix.crypto.entity import Entity
from pelix.crypto.key import Key

from OpenSSL import crypto


# Module version
__version_info__ = (0, 1, 0)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"


class CSR:

    def __init__(self):
        self._req = crypto.X509Req()
        self._key = crypto.PKey()
        self._subject = Entity()

    def generate_CSR(key, subject):
        csr = CSR()
        csr._key = key._pkey
        csr._subject = subject
        return csr

    def set_pubkey(self, key):
        self._req.set_pubkey(key._pkey)

    def get_pubkey(self):
        x509key = self._key
        ret = Key()
        ret._pkey = x509key
        return ret

    def set_version(self, version):
        self._req.set_version(version)

    def get_version(self):
        return self._req.get_version()

    def get_subject(self):
        return self._subject

        
