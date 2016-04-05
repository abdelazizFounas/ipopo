from OpenSSL import crypto


# Module version
__version_info__ = (0, 1, 0)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"


class Entity:
    """
    Represents a certification entity (either an issuer or a certification subject)
    """

    def __init__(self, countryName="", stateOrProvinceName="", localityName="",
                 organizationName="", organizationalUnitName="",
                 commonName="", email=""):
        """
        Sets up the entity

        :param countryName
        :param stateOrProvinceName
        :param localityName
        :param organizationName
        :param organizationalUnitName
        :param commonName
        :param email
        """ 
        self.C = countryName
        self.ST = stateOrProvinceName
        self.L = localityName
        self.O = organizationName
        self.OU = organizationalUnitName
        self.CN = commonName
        self.emailAddress = email

    def get_countryName(self):
        """
        Returns the country name
        """
        return self.C

    def get_stateOrProvinceName(self):
        """
        Returns the state or province name
        """
        return self.ST

    def get_localityName(self):
        """
        Returns the locality name
        """
        return self.L

    def get_organizationName(self):
        """
        Returns the organization name
        """
        return self.O

    def get_organizationalUnitName(self):
        """
        Returns the organizational unit name
        """
        return self.OU

    def get_commonName(self):
        """
        Returns the common name
        """
        return self.CN

    def get_emailAddress(self):
        """
        Returns the email address
        """
        return self.emailAddress

    def set_countryName(self, countryName):
        """
        Sets the country name
        """
        self.C = countryName

    def set_stateOrProvinceName(self, stateOrProvinceName):
        """
        Sets the state or province name
        """
        self.ST = stateOrProvinceName

    def set_localityName(self, localityName):
        """
        Sets the locality name
        """
        self.L = localityName

    def set_organizationName(self, organizationName):
        """
        Sets the organization name
        """
        self.O = organizationName

    def set_organizationalUnitName(self, organizationalUnitName):
        """
        Sets the organizational unit name
        """
        self.OU = organizationalUnitName

    def set_commonName(self, commonName):
        """
        Sets the common name
        """
        self.CN = commonName

    def set_emailAddress(self, email):
        """
        Sets the email address
        """
        self.emailAddress = email
