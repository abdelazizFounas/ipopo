from OpenSSL import crypto


# Module version
__version_info__ = (0, 6, 4)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"


class Entity:

	def __init__(self, countryName="", stateOrProvinceName="", localityName="", 
				 organizationName="", organizationalUnitName="", 
				 commonName="", email=""):
		self.C = countryName
		self.ST = stateOrProvinceName
		self.L = localityName
		self.O = organizationName
		self.OU = organizationalUnitName
		self.CN = commonName
		self.emailAddress = email

	def get_countryName(self):
		return self.C

	def get_stateOrProvinceName(self):
		return self.ST

	def get_localityName(self):
		return self.L

	def get_organizationName(self):
		return self.O

	def get_organizationalUnitName(self):
		return self.OU

	def get_commonName(self):
		return self.CN

	def get_emailAddress(self):
		return self.emailAddress

	def set_countryName(self, countryName):
		self.C = countryName

	def set_stateOrProvinceName(self, stateOrProvinceName):
		self.ST = stateOrProvinceName

	def set_localityName(self, localityName):
		self.L = localityName

	def set_organizationName(self, organizationName):
		self.O = organizationName

	def set_organizationalUnitName(self, organizationalUnitName):
		self.OU = organizationalUnitName

	def set_commonName(self, commonName):
		self.CN = commonName

	def set_emailAddress(self, email):
		self.emailAddress = email