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


    def get_address(self):
        return self.address

    def get_initialization_vector(self):
        return self.iv

    def get_name(self):
        return self.username

    def get_public_key(self):
        return self.publicKey

    def get_session_key(self):
        return self.sessionKey

    def get_session_key_hash(self):
        return self.sessionKeyHash

    def set_public_key(self, publicKey):
        self.publicKey = publicKey

    def set_session_key_and_hash(self, sessionKey, sessionKeyHash):
        self.sessionKey = sessionKey
        self.sessionKeyHash = sessionKeyHash

    def set_initialization_vector(self, iv):
        self.iv = iv
