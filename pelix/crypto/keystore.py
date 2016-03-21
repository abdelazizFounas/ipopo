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

    def getPath():
        pass

    def addCert(aCert):
        pass

    def getCert(aId):
        pass

    def removeCert(aId):
        pass

    def restoreFromDisk():
        pass
