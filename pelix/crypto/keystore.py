#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
iPOPO keystore

Provides a keystore interface
"""

# Standard library
import logging

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


class KeyStore:
    """
    Interface of a KeyStore. It manages a dictionnary of certificates and persistence on the disk
    """

    def __init__(self, aPath):
        """
        Create an object KeyStore representing a created one on the disk or creates one on the disk

        :param aPath: Location of the KeyStore to load or to create
        """
        self.pPath = aPath

    def getPath(self):
        """
        Retrieve the path of the location of the BasicKeyStore

        :return: The path
        """
        pass

    def addCert(self, aCert, aName = None):
        """
        Add a certicate object with a special name aName or the ID of the certicate itself

        :param aCert: The certificate to add
        :param aName: Special name at None by default
        """
        pass

    def getCert(self, aId):
        """
        Retrieve the certificate with aID as ID of the cert

        :param aID: ID of the certificate
        :return: The certificates
        """
        pass

    def removeCert(self, aId):
        """
        Remove the certificate with aID as ID of the cert

        :param aID: ID of the certificate
        """
        pass

    def restoreFromDisk(self):
        """
        Restore the KeyStore of the disk if already created
        """
        pass

    def getIds(self):
        """
        Retrieve the list of the all the certificates's IDs

        :return: The IDs
        """
        pass
