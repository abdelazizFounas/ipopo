from OpenSSL import crypto


# Module version
__version_info__ = (0, 6, 4)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"

class Entity:

	def __init__(self, countryName="", stateOrProvinceName="", localityName="", organizationName="", organizationalUnitName="", commonName="", email=""):
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


class Certificate:

	def __init__(self):
		self._cert = crypto.X509()
		self_pubkey = Key()

	def ID():
		return self._cert.digest(b"sha1")

	def get_subject(self):
		return _wrap_x509Name_into_Entity("subject")

	def get_issuer(self):
		return _wrap_x509Name_into_Entity("issuer")

	def get_pubkey(self):
		return self._pubkey

	def get_notAfter(self):
		return self._cert.get_notAfter()

	def get_notBefore(self):
		return self._cert.get_notBefore()

	def set_subject(self, subject):
		s = _unwrap_entity_into_x509name(subject, "subject")
		self._cert.set_subject(s)

	def set_issuer(self, issuer):
		i = _unwrap_entity_into_x509name(issuer, "issuer")
		self._cert.set_issuer(i)

	def set_pubkey(self, pubkey):
		self._pubkey = pubkey

	def set_notAfter(self, when):
		self._cert.set_notAfter(when)

	def set_notBefore(self, when):
		self._cert.set_notBefore(when)

	def has_expired(self):
		return self._cert.has_expired()

	
	def _wrap_x509Name_into_Entity(self, subject_or_issuer):
		if subject_or_issuer = "subject":
			name = self._cert.get_issuer()
		elif subject_or_issuer = "issuer":
			name = self._cert.get_subject()

		c = name.C
		st = name.ST
		l = name.L
		o = name.O
		ou = name.OU
		cn = name.CN
		e = name.emailAddress
		ent = Entity(c, st, l, o, ou, cn, e)
		return ent

	def _unwrap_entity_into_x509name(self, entity, subject_or_issuer):
		if subject_or_issuer = "subject":
			name = self._cert.get_subject()
		elif subject_or_issuer = "issuer":
			name = self._cert.get_issuer()

		name.C = entity.get_countryName()
		name.ST = entity.get_stateOrProvinceName()
		name.l = entity.get_localityName()
		name.o = entity.get_organizationName()
		name.ou = entity.get_organizationalUnitName()
		name.cn = entity.get_commonName()
		name.emailAddress = entity.get_email()
		return name



	