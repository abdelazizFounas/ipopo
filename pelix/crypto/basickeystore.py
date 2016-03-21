#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
iPOPO keystore

Provides a keystore interface
"""

# Standard library
from pelix.crypto.keystore import KeyStore
import logging
import pickle
import os

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


class BasicKeyStore(KeyStore):
    def __init__(self, aPath):
        if aPath.endswith('/') :
            self.pPath = aPath
        else :
            self.pPath = aPath+'/'

        if not os.path.exists(self.pPath) :
            try:
                os.makedirs(self.pPath)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(path):
                    pass
                else:
                    raise

        self.dCert = {}
        self.restoreFromDisk()

    def getPath(self):
        return self.pPath

    def addCert(self, aCert, aName = None):
        if aName == None :
            name = aCert.getId()
        else :
            name = aName
        self.dCert[name] = aCert
        with open(self.pPath+name+'.pem', 'wb') as file:
            pickler = pickle.Pickler(file)
            pickler.dump(aCert)
            file.close()

    def getCert(self, aId):
        return self.dCert.get(aId)

    def removeCert(self, aId):
        del self.dCert[aId]
        os.remove(self.pPath+aId+'.pem')

    def restoreFromDisk(self):
        lFiles = os.listdir(self.pPath)
        for dir in lFiles:
            if os.path.isfile(self.pPath+dir) :
                if os.path.splitext(dir)[1] == '.pem' :
                    with open(self.pPath+dir, 'rb') as file:
                        unpickler = pickle.Unpickler(file)
                        self.dCert[os.path.splitext(dir)[0]] = unpickler.load()
                        file.close()

    def getIds(self):
        return self.dCert.keys()
