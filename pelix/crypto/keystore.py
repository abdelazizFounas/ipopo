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
    def __init__(self, aPath):
        self.pPath = aPath

    def getPath(self):
        pass

    def addCert(self, aCert):
        pass

    def getCert(self, aId):
        pass

    def removeCert(self, aId):
        pass

    def restoreFromDisk(self):
        pass
