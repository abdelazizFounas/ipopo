#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
iPOPO keystore

Provides a keystore interface
"""

# Standard library
from pelix.crypto import KeyStore
import logging
import pickle
import os

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


class BasicKeyStore(KeyStore):
    def __init__(self, aPath):
        self.pPath = aPath
        self.dCert = {}

    def getPath():
        return self.pPath

    def addCert(aCert):
        self.dCert[aCert.getId()] = aCert
        with open(self.pPath+aCert.getId()+'.pem', 'wb') as file:
            pickler = pickle.Pickler(file)
            pickler.dump(aCert)

    def getCert(aId):
        return self.dCert.get(aId)

    def removeCert(aId):
        del self.dCert[aId]
        os.remove(self.pPath+aId+'.pem')

    def restoreFromDisk():
        lFiles = os.listdir(self.pPath)
        for dir in lFiles:
            if os.path.isfile(self.pPath+dir) :
                if os.path.splitext(dir)[1] == '.pem' :
                    with open(self.pPath+dir, 'rb') as file:
                        unpickler = pickle.Unpickler(file)
                        self.dCert[os.path.splitext(dir)[0]] = unpickler.load()
