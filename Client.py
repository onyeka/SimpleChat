__author__ = 'onyekaigabari'

class User(object):
    def __init__(self, name, address):
        self.username = name
        self.authenticated = False
        self.address = address
        self.sessionKey = None
        self.iv = None
        self.sessionKeyHash = None
        self.publicKey = None


    def getAddress(self):
        return self.address

    def getInitializationVector(self):
        return self.iv

    def getName(self):
        return self.username

    def getPublicKey(self):
        return self.publicKey

    def getSessionKey(self):
        return self.sessionKey

    def getSessionKeyHash(self):
        return self.sessionKeyHash

    def setPublicKey(self, publicKey):
        self.publicKey = publicKey

    def setSessionKeyAndHash(self, sessionKey, sessionKeyHash):
        self.sessionKey = sessionKey
        self.sessionKeyHash = sessionKeyHash

    def setInitializationVector(self, iv):
        self.iv = iv
