#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
iPOPO PKI

Private Key Infrastructure

:author: Thomas Calmant
:copyright: Copyright 2015, Thomas Calmant
:license: Apache License 2.0
:version: 0.6.4

..

    Copyright 2015 Thomas Calmant

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""

# Standard library
import logging

# Keystore
from pelix.crypto.basickeystore import BasicKeyStore
from pelix.crypto.keystore import KeyStore
# OS
import os

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


class PKI(object):
    """
    Represents a PKI. (Private Key Infrastructure). It manages certificates authorities
    """

    def __init__(self, path):
        """
        Load a pki stored at the given location. It loads two keystore. The first one contains the certificates handled by the pki and the second one contains the certification authorities.

        :param aPath: Location of the pki to load
        """
        self._keystore = None
        self._path = None
        self._authorities = None
        self._revokedCa = "ca_revoked"
        self._revokedCert = "cert_revoked"

        # Store _path, adding a trailing slash if not present
        if path.endswith('/'):
            self._path = path
        else:
            self._path = path + '/'

        # Loading or creating the keystore
        if not os.path.exists(self._path + 'ks'):
            os.makedirs(self._path + 'ks')
        self._keystore = BasicKeyStore(self._path + 'ks')

        # Loading or creation the authorities
        if not os.path.exists(self._path + 'ca'):
            os.makedirs(self._path + 'ca')
        self._authorities = BasicKeyStore(self._path + 'ca')

        # Create revoked CA and revoked Cert files
        open(self._path + self._revokedCa, 'a')
        open(self._path + self._revokedCert, 'a')


    def addAuthority(self, cert, name):
        """
        Add an authority to the pki.

        :param name: Name of the authority
        :param cert: Certificate to use
        """
        self._authorities.addCert(cert, name)

    def getAuthority(self, name):
        """
        Retrieve the certificate linked to the authority previously added to the pki.

        :param name: Name of the authority
        :return: Certificate
        """
        return self._authorities.getCert(name)

    def removeAuthority(self, name):
        """
        Remove an authority in the PKI

        :param name: Name of the authority
        """
        self._authorities.removeCert(name)

    def revokeAuthority(self, name):
        """
        Revoke the certificate authority named :name:

        :param name: name of the certificate autority to revoke
        """
        ca = self.getAuthority(name)
        if ca is not None:
            with open(self._path + self._revokedCa, 'a') as f:
                f.write(ca.getId() + '\n')

    def getRevokedAuthorities(self):
        """
        Get the list of id of revoked authorities
        :return: list of revoked
        """
        auths = []
        with open(self._path + self._revokedCa, 'r') as f:
            for line in f:
                id = line.rstrip('\n')
                auths.append(id)
        return auths

    def addCertificate(self, cert, name=None):
        """
        Add a certificate to the pki.

        :param name: Name of the certificate
        :param cert: Certificate to use
        """
        self._keystore.addCert(cert, name)

    def getCertificate(self, id):
        """
        Retrieve the certificate linked to the authority previously added to the pki.

        :param id: id of the certificate
        :return: Certificate
        """
        return self._keystore.getCert(id)

    def removeCertificate(self, id):
        """
        Remove a certificate in the PKI

        :param id: id of the certificate
        """
        self._keystore.removeCert(id)

    def revokeCertificate(self, id):
        """
        Revoke the certificate identified by :id: in the pki
        :param id: id of the certificate to revoke
        """
        cert = self._keystore.getCert(id)
        if cert is not None:
            with open(self._path + self._revokedCert, 'a') as f:
                f.write(str(id) + '\n')

    def getRevokedCertificates(self):
        """
        Get the list of id of revoked certificates
        :return: list of revoked
        """
        certs = []
        with open(self._path + self._revokedCert, 'r') as f:
            for line in f:
                id = line.rstrip('\n')
                certs.append(id)
        return certs

    def verify(self, cert):
        """
        Verify the certificate

        :return: True if the ceriticate was issued by one of the authorities and certificate is not revoked
        """
        raise NotImplementedError
