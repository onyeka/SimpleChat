__author__ = 'onyekaigabari'

class Client(object):
    def __init__(self, name, address):
        self.name = name
        self.loggedIn = True
        self.address = address

    def getName(self):
        return self.name

    def getAddress(self):
        return self.address

    def setSessionKey(self, sessionKey):
        self.sessionKey = sessionKey

    def getSessionKey(self):
        return self.sessionKey

    def setInitializationVector(self, iv):
        self.iv = iv

    def getInitializationVector(self):
        return self.iv
