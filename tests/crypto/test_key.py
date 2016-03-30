#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Tests the key service
"""

# Pelix
from pelix.crypto.key import Key

import OpenSSL

# Standard library
try:
    import unittest2 as unittest
except ImportError:
    import unittest

# ------------------------------------------------------------------------------

__version__ = "1.0.0"

# ------------------------------------------------------------------------------

class KeyTest(unittest.TestCase):

	def testGenerate(self):
		self.key = Key()
		self.key.generate_key(Key.TYPE_RSA, 256)
		self.assertEqual(self.key._pkey.type(), OpenSSL.crypto.TYPE_RSA, "Key type does not match")
		self.assertEqual(self.key._pkey.bits(), self.key.bits(), "Key bit count does not match")



if __name__ == "__main__":
    # Set logging level
    import logging
    logging.basicConfig(level=logging.DEBUG)

    suite = unittest.TestLoader().loadTestsFromTestCase(KeyTest)
    unittest.TextTestRunner(verbosity=3).run(suite)