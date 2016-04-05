#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
iPOPO keystore

Provides a basic keystore
"""

# Standard library
from pelix.crypto.keystore import KeyStore
import logging
import os

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

class BasicKeyStore(KeyStore):
    """
    Represents a BasicKeyStore. It manages a dictionnary of certificates and persistence on the disk
    """

    def __init__(self, aPath):
        """
        Create an object BasicKeyStore representing a created one on the disk or creates one on the disk

        :param aPath: Location of the BasicKeyStore to load or to create
        """

        # Preparation of the path to use for the location
        if aPath.endswith('/') :
            self.pPath = aPath
        else :
            self.pPath = aPath+'/'

        # If the path does not exists, we need to create it
        if not os.path.exists(self.pPath) :
            try:
                os.makedirs(self.pPath)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(path):
                    pass
                else:
                    raise

        # Creation of the dictionnary of certificates
        self.dCert = {}

        # Restore the BasicKeyStore from the disk
        self.restoreFromDisk()

    def getPath(self):
        """
        Retrieve the path of the location of the BasicKeyStore

        :return: The path
        """
        return self.pPath

    def addCert(self, aCert, aName = None):
        """
        Add a certicate object with a special name aName or the ID of the certicate itself

        :param aCert: The certificate to add
        :param aName: Special name at None by default
        """
        # We take the ID to give to the certificate
        if aName == None :
            name = str(aCert.ID())
        else :
            name = aName
        # We add the certificate to the dictionnary
        self.dCert[name] = aCert
        # Now add this certificate to the disk for persistence
        # To the path and file extension ".pem" we open the file with binary and writing options
        with open(self.pPath+name+'.pem', 'w') as file:
            # Serialize the certificate
            buffer = aCert.dump();
            file.write(buffer)
            # Close the file
            file.close()

    def getCert(self, aId):
        """
        Retrieve the certificate with aID as ID of the cert

        :param aID: ID of the certificate
        :return: The certificates
        """
        return self.dCert.get(aId)

    def removeCert(self, aId):
        """
        Remove the certificate with aID as ID of the cert

        :param aID: ID of the certificate
        """
        # Delete de certificate of the dictionnary
        del self.dCert[aId]
        # Delete the corresponding persistent file on the disk
        os.remove(self.pPath+aId+'.pem')

    def restoreFromDisk(self):
        """
        Restore the BasicKeyStore of the disk if already created
        """
        # List of all files of the path
        lFiles = os.listdir(self.pPath)
        # For each name of file
        for dir in lFiles:
            # If it's a file (not a directory)
            if os.path.isfile(self.pPath+dir) :
                # If the extension of the file is ".pem"
                if os.path.splitext(dir)[1] == '.pem' :
                    # We need to open the file with binary and reading options
                    with open(self.pPath+dir, 'r') as file:
                        # Last we deserialize the file
                        buffer = file.read()
                        cert = Certificate.load(buffer)
                        self.dCert.addCert(cert, os.path.splitext(dir)[0])
                        # We close the file
                        file.close()

    def getIds(self):
        """
        Retrieve the list of the all the certificates's IDs

        :return: The keys of the dictionnary
        """
        return self.dCert.keys()
