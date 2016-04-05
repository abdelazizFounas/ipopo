#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Tests the basic keystore
"""

# Pelix
from pelix.crypto.basickeystore import BasicKeyStore
from pelix.crypto.certificate import Certificate
from pelix.crypto.entity import Entity

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
        self.ks = BasicKeyStore('./testBKS')

        self.assertTrue(os.path.exists('./testBKS'), "Keystore folder was not created")

        self.cert = Certificate()
        self.ent = Entity("FR", "Drome", "Loriol", "Elipce", "E", "name", "name@name.com")
        self.cert.set_subject(self.ent)

        self.ks.addCert(self.cert)

        self.assertTrue(os.path.exists('./testBKS/'+cert.ID()+'.pem'), "Certificate was not dumped on disk")

        self.cert2 = self.ks.getCert(self.cert.getId())

        self.assertTrue(cert.ID() == cert2.ID(), "The retrieved cert is not the same")
