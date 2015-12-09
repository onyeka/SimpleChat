class Peer(object):
    def __init__(self, name, address, public_key):
        self.peername = name
        self.authenticated = False
        self.address = address
        self.shared_key = None
        self.iv = None
        self.public_key = public_key

    def get_address(self):
        return self.address

    def get_initialization_vector(self):
        return self.iv

    def get_peer_name(self):
        return self.peername

    def get_public_key(self):
        return self.public_key

    def get_shared_key(self):
        return self.shared_key

    def set_public_key(self, public_key):
        self.public_key = public_key

    def set_shared_key(self, shared_key):
        self.shared_key = shared_key

    def set_initialization_vector(self, iv):
        self.iv = iv