#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Tests the basic keystore
"""

# Pelix
from pelix.crypto.basickeystore import BasicKeyStore

# Standard library
import threading
try:
    import unittest2 as unittest
except ImportError:
    import unittest

# ------------------------------------------------------------------------------

__version__ = "1.0.0"

# ------------------------------------------------------------------------------


class DummyCertificates(object):
    """
    Dummy certificates
    """
    def __init__(self):
        # Topic of the last received event
        self.data = 'data'
        self.aId = 'aId'
    def getId(self):
        return self.aId
    def __str__(self):
        return 'CERTIFICAT : ' + self.data + ' ' + self.aId

# ------------------------------------------------------------------------------


class BasicKeystoreTest(unittest.TestCase):
    """
    Tests the basic keystore
    """
    def testBasic(self):
        self.ks = BasicKeyStore('.')
        self.cert = DummyCertificates()
        print(self.cert)
        self.ks.addCert(self.cert)
        self.cert2 = self.ks.getCert(self.cert.getId())
        print(self.cert2)
