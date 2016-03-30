from OpenSSL import crypto


# Module version
__version_info__ = (0, 6, 4)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"


TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA

class Key:

	def __init__(self):
		self._pkey = crypto.PKey()

	def generate_key(type, bits):
		if type == crypto.TYPE_RSA:
			type = TYPE_RSA
		elif type == crypto.TYPE_DSA:
			type = TYPE_DSA
		self._pkey.generate_key(type, bits)

	def  bits():
		return self._pkey.bits()

	def type():
		return self._pkey.type()