#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Tests the basic keystore
"""

# Pelix
from pelix.crypto import BasicKeyStore

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
        self.data = 'certicatipopo'
        self.aId = 'ident'

    def getId():
        return self.aId

    def __str__():
        return 'CERTIFICAT : ' + self.data + ' ' + self.aId

# ------------------------------------------------------------------------------


class BasicKeystoreTest(unittest.TestCase):
    """
    Tests the basic keystore
    """
    def testBasic(self):
        self.ks = BasicKeyStore('.')
        self.cert = DummyCertificates()
        self.ks.addCert(self.cert)
        self.cert2 = self.ks.getCert(self.cert.getId())
        print(self.cert2.__str__())
