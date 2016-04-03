from OpenSSL import crypto


# Module version
__version_info__ = (0, 6, 4)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"


class CSR:

    def generate_CSR(Key key, Entity requester):
        raise NotImplementedError
