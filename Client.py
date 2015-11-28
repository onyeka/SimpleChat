__author__ = 'onyekaigabari'

class Client(object):
    def __init__(self, name, address):
        self.username = name
        self.loggedIn = True
        self.address = address

    def getName(self):
        return self.username

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
