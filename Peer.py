class Peer(object):
    def __init__(self, name, address, key=None, iv=None):
        self.peername = name
        self.authenticated = False
        self.address = address
        #self.shared_key = None
        self.iv = iv
        self.shared_key = key
        self.b = None

    def get_address(self):
        return self.address

    def get_client_b(self):
        return self.b

    def get_initialization_vector(self):
        return self.iv

    def get_peer_name(self):
        return self.peername

    def is_authenticated(self):
        return self.authenticated

    #def get_public_key(self):
        #return self.public_key

    def get_shared_key(self):
        return self.shared_key

    #def set_public_key(self, public_key):
        #self.public_key = public_key

    def set_authenticated_flag(self, flag):
        self.authenticated = flag

    def set_client_b(self, key):
        self.b = key

    def set_shared_key(self, shared_key):
        self.shared_key = shared_key

    def set_initialization_vector(self, iv):
        self.iv = iv