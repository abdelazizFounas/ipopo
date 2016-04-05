from pelix.crypto.entity import Entity
from pelix.crypto.key import Key

from OpenSSL import crypto


# Module version
__version_info__ = (0, 1, 0)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"


class Certificate:

    def __init__(self):
        self._cert = crypto.X509()
        self._pubkey = Key()

    def ID(self):
        return self._cert.get_subject().hash()

    def get_subject(self):
        return self._wrap_x509Name_into_Entity("subject")

    def get_issuer(self):
        return self._wrap_x509Name_into_Entity("issuer")

    def get_pubkey(self):
        return self._pubkey

    def get_notAfter(self):
        return self._cert.get_notAfter()

    def get_notBefore(self):
        return self._cert.get_notBefore()

    def get_version(self):
        return self._cert.get_version()

    def get_serial_number(self):
        return self._cert.get_serial_number()

    def set_subject(self, subject):
        s = self._unwrap_entity_into_x509name(subject, "subject")
        self._cert.set_subject(s)

    def set_issuer(self, issuer):
        i = self._unwrap_entity_into_x509name(issuer, "issuer")
        self._cert.set_issuer(i)

    def set_pubkey(self, pubkey):
        self._pubkey = pubkey
        self._cert.set_pubkey(pubkey._pkey)

    def set_notAfter(self, when):
        self._cert.set_notAfter(when)

    def set_notBefore(self, when):
        self._cert.set_notBefore(when)

    def set_version(self, version):
        self._cert.set_version(version)

    def set_serial_number(self, serial):
        self._cert.set_serial_number(serial) 

    def has_expired(self):
        return self._cert.has_expired()

    def sign(self, pubkey, digest):
        self._cert.sign(pubkey._pkey, digest)

    def dump(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, self._cert)

    def load(buf):
        cert = Certificate()
        key = Key()
        _x509 = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
        cert._cert = _x509
        subject = cert._wrap_x509Name_into_Entity("subject")
        issuer = cert._wrap_x509Name_into_Entity("issuer")
        key._pkey = _x509.get_pubkey()
        cert.set_subject(subject)
        cert.set_issuer(issuer)
        cert.set_pubkey(key)
        cert.set_notAfter(_x509.get_notAfter())
        cert.set_notBefore(_x509.get_notBefore())
        cert.set_version(_x509.get_version())
        cert.set_serial_number(_x509.get_serial_number())
        return cert

    def _wrap_x509Name_into_Entity(self, subject_or_issuer):
        if subject_or_issuer == "subject":
            name = self._cert.get_subject()
        elif subject_or_issuer == "issuer":
            name = self._cert.get_issuer()

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
        if subject_or_issuer == "subject":
            name = self._cert.get_subject()
        elif subject_or_issuer == "issuer":
            name = self._cert.get_issuer()

        name.C = entity.get_countryName()
        name.ST = entity.get_stateOrProvinceName()
        name.L = entity.get_localityName()
        name.O = entity.get_organizationName()
        name.OU = entity.get_organizationalUnitName()
        name.CN = entity.get_commonName()
        name.emailAddress = entity.get_emailAddress()
        return name
