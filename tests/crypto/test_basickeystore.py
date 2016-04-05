#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Tests the basic keystore
"""

# Pelix
from pelix.crypto.basickeystore import BasicKeyStore
from pelix.crypto.certificate import Certificate
from pelix.crypto.entity import Entity
from pelix.crypto.key import Key

# Standard library
import threading
try:
    import unittest2 as unittest
except ImportError:
    import unittest

# ------------------------------------------------------------------------------

__version__ = "1.0.0"

# ------------------------------------------------------------------------------

class BasicKeystoreTest(unittest.TestCase):
    """
    Tests the basic keystore
    """
    def testBasic(self):
        # Creation of a BasicKeyStore to test it
        self.ks = BasicKeyStore('./testBKS')

        # The path given to the BasicKeyStore should now exist
        self.assertTrue(os.path.exists('./testBKS'), "Keystore folder was not created")

        # Create a certificate object
        self.cert = Certificate()

        # Fill the certificate with not important information (we just need to test the BasicKeyStore)
        self.key = Key()
        self.key.generate_key(Key.TYPE_RSA, 1024)
        self.issuer = Entity("LB", "Hello", "World", "org", "orgunit", "common", "hello.world@gmail.com")
        self.subject = Entity("FR", "Drome", "Loriol", "Elipce", "E", "name", "name@name.com")
        self.cert.set_subject(self.subject)
        self.cert.set_issuer(self.issuer)
        self.cert.set_pubkey(self.key)
        self.cert.set_notAfter(b'20170207053015')
        self.cert.set_notBefore(b'20160207053015')
        self.cert.set_version(10)
        self.cert.set_serial_number(12345)

        # Create a new key to sign the certificate with
        self.key2 = Key()
        self.key2.generate_key(Key.TYPE_RSA, 1024)

        # Sign the certificate with the latter key
        self.cert.sign(self.key2, 'sha1')

        # Add the created and filled certificate to the BasicKeyStore
        self.ks.addCert(self.cert)

        # A new file should be present in the path of the BasicKeyStore
        self.assertTrue(os.path.exists('./testBKS/'+cert.ID()+'.pem'), "Certificate was not dumped on disk")

        # Retrive the certificate added to the BasicKeyStore
        self.cert2 = self.ks.getCert(self.cert.getId())

        # The ID of the certificate added to the BasicKeyStore and the one retrieved should be equal
        self.assertTrue(cert.ID() == cert2.ID(), "The retrieved cert is not the same")
