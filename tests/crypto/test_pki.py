#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Tests the pki
"""

# Pelix
from pelix.crypto.pki import PKI

# Standard library
import os
try:
    import unittest2 as unittest
except ImportError:
    import unittest


# ------------------------------------------------------------------------------

__version__ = "1.0.0"

# ------------------------------------------------------------------------------

# Creation of the function randomword used to generated random string
import random, string

def randomword(length):
   return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(length))



class DummyCertificates(object):
    """
    Dummy certificates
    """
    def __init__(self, id, data):
        # Topic of the last received event
        self.data = id
        self.aId = data
    def getId(self):
        return self.aId
    def __str__(self):
        return 'CERTIFICAT : ' + self.data + ' ' + str(self.aId)

# ------------------------------------------------------------------------------


class PKITest(unittest.TestCase):

    def testCreatePKI(self):
        """
        Test the creation of a PKI
        Verify that the two directories in the PKI are created
        """
        path = '/tmp/pkis/' + randomword(8)
        pki = PKI(path)

        # Verify that the dirs ca and ks exists
        self.assertTrue(os.path.exists(path + '/ks'),
                        "Keystore folder was not created")
        self.assertTrue(os.path.exists(path + '/ca'),
                        "Authorities folder was not created")


    def testAuthorities(self):
        """
        Tests that the authorities addition, removal and revocation works
        """
        path = '/tmp/pkis/' + randomword(8)
        pki = PKI(path)

        # Creation of 3 authorities in pki
        auths = []
        for i in range(0,3):
            auth = DummyCertificates(i, randomword(25))
            authName = 'auth'+str(i)
            auths.append(auth)
            pki.addAuthority(auth, authName)

        errorMsgIn = 'Authority should have been in pki'
        errorMsgOut = 'Authority should not have been in pki'
        errorMsgRevoked = 'Authority should have been in revoked list'

        # Test the 3 authorities are in pki
        self.assertEqual(auths[0], pki.getAuthority('auth0'), errorMsgIn)
        self.assertEqual(auths[1], pki.getAuthority('auth1'), errorMsgIn)
        self.assertEqual(auths[2], pki.getAuthority('auth2'), errorMsgIn)

        # remove auth2
        # Test auth0 & auth1 still in pki and auth2 isn't
        pki.removeAuthority("auth2")
        self.assertEqual(auths[0], pki.getAuthority('auth0'), errorMsgIn)
        self.assertEqual(auths[1], pki.getAuthority('auth1'), errorMsgIn)
        self.assertIsNone(pki.getAuthority('auth2'), errorMsgOut)

        # Revoke auth1
        # Test auth0 and auth1 still in pki, auth2 isn't and auth1 and auth1 in
        # revoked list
        pki.revokeAuthority("auth1")
        self.assertEqual(auths[0], pki.getAuthority('auth0'), errorMsgIn)
        self.assertEqual(auths[1], pki.getAuthority('auth1'), errorMsgIn)
        self.assertIsNone(pki.getAuthority('auth2'), errorMsgOut)
        revokedList = pki.getRevokedAuthorities()
        self.assertTrue(auths[1].getId() in revokedList, errorMsgRevoked)

        # Revoke auth0
        # Test auth0 and auth1 still in pki, auth2 isn't and auth1 and auth0 in
        # revoked list
        pki.revokeAuthority("auth0")
        self.assertEqual(auths[0], pki.getAuthority('auth0'), errorMsgIn)
        self.assertEqual(auths[1], pki.getAuthority('auth1'), errorMsgIn)
        self.assertIsNone(pki.getAuthority('auth2'), errorMsgOut)
        revokedList = pki.getRevokedAuthorities()
        self.assertTrue(auths[0].getId() in revokedList, errorMsgRevoked)
        self.assertTrue(auths[1].getId() in revokedList, errorMsgRevoked)

    def testCertificates(self):
        """
        Tests that the certificates addition, removal and revocation works
        """
        path = '/tmp/pkis/' + randomword(8)
        pki = PKI(path)

        # Creation of 3 authorities in pki
        certs = []
        for i in range(0,3):
            cert = DummyCertificates(i, randomword(25))
            certs.append(cert)
            pki.addCertificate(cert)

        errorMsgIn = 'Certificate should have been in pki'
        errorMsgOut = 'Certificate should not have been in pki'
        errorMsgRevoked = 'Certificate should have been in revoked list'

        # Test the 3 certificates are in pki
        self.assertEqual(certs[0], pki.getCertificate(certs[0].getId()),
                        errorMsgIn)
        self.assertEqual(certs[1], pki.getCertificate(certs[1].getId()),
                        errorMsgIn)
        self.assertEqual(certs[2], pki.getCertificate(certs[2].getId()),
                        errorMsgIn)

        # remove cert2
        # Test cert0 & cert1 still in pki and cert2 isn't
        pki.removeCertificate(certs[2].getId())
        self.assertEqual(certs[0], pki.getCertificate(certs[0].getId()),
                        errorMsgIn)
        self.assertEqual(certs[1], pki.getCertificate(certs[1].getId()),
                        errorMsgIn)
        self.assertIsNone(pki.getCertificate(certs[2].getId()), errorMsgOut)

        # Revoke cert1
        # Test cert0 and cert1 still in pki, cert2 isn't and cert 1 in revoked
        # list
        pki.revokeCertificate(certs[1].getId())
        self.assertEqual(certs[0], pki.getCertificate(certs[0].getId()),
                        errorMsgIn)
        self.assertEqual(certs[1], pki.getCertificate(certs[1].getId()),
                        errorMsgIn)
        self.assertIsNone(pki.getCertificate(certs[2].getId()), errorMsgOut)
        revokedList = pki.getRevokedCertificates()
        self.assertTrue(certs[1].getId() in revokedList, errorMsgRevoked)

        # Revoke cert0
        # Test cert0 and cert1 still in pki, cert2 isn't and cert1 and cert0 in
        # revoked list
        pki.revokeCertificate(certs[0].getId())
        self.assertEqual(certs[0], pki.getCertificate(certs[0].getId()),
                        errorMsgIn)
        self.assertEqual(certs[1], pki.getCertificate(certs[1].getId()),
                        errorMsgIn)
        self.assertIsNone(pki.getCertificate(certs[2].getId()), errorMsgOut)
        revokedList = pki.getRevokedCertificates()
        self.assertTrue(certs[0].getId() in revokedList, errorMsgRevoked)
        self.assertTrue(certs[1].getId() in revokedList, errorMsgRevoked)


    def testVerify(self):
        """
        Tests that the verification of certificates
        """
        pass

    def testLoadPKI(self):
        """
        Tests that the certificates addition, removal and revocation works
        """
        pass
        # Creation of a pki
        # add 2 certificate
        # revoke one
        # add 2 auth
        # revoke one
        # Test the pki is what we think it is
        # Load pki
        # Test again

if __name__ == "__main__":
    # Set logging level
    import logging
    logging.basicConfig(level=logging.DEBUG)

    suite = unittest.TestLoader().loadTestsFromTestCase(PKITest)
    unittest.TextTestRunner(verbosity=3).run(suite)
