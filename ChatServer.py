from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from ConfigParser import SafeConfigParser
import socket, logging, sys, Client

class ChatServer(object):
    """ Usage: prints out how to use the server
    """
    Usage = 'usage: \tpython ChatServer.py\n' \
    '\t-h: prints this help message and exit'
    config = SafeConfigParser()
    config.read('simplechat.cfg')
    port = config.getint('SectionOne', 'Port')
    MSG_LEN = config.getint('SectionOne', 'MsgLen')
    def __init__(self):
        self.clients = {}
        self.count = 0

        # get server's private key
        self.private_key = self.getPrivateKey()

        # open up server socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_address = (socket.gethostbyname(socket.gethostname()), ChatServer.port)
            self.sock.bind(self.server_address)
            print "Initialized UDP Server....", self.server_address
        except RuntimeError, e:
            print "Initializing server socket failed: ", e

    def getPrivateKey(self):
        try:
            with open("server_private_key.pem", 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            return private_key
        except IOError as e :
            print " couldn't read server private key:", e
            sys.exit(-1)

    # Handles messages sent from clients
    def handleClientMessages(self, msg, client):
        logging.debug(" message received: %s", msg)

    # Receives messages sent from clients
    def receiveClientMessages(self):
        msg, addr = self.sock.recvfrom(ChatServer.MSG_LEN)
        isClientKnown = self.clients.has_key(addr)
        if(isClientKnown):
            client = self.clients.get(addr)
            if(client == None):
                logging.debug("couldn't retrieve client")
                return
            decrypted_msg = self.decryptUsingSymetricKey(client.getSessionKey(),
                                                         client.getInitializationVector(),
                                                         msg)
            self.handleClientMessages(decrypted_msg, client)
        else:
            """
            TODO: perform challenge and create client object if client is valid
            """
            print "it's a new client!!"

    def encryptUsingPublicKey(self, key, data):
        print "Using public key to encrypt the data"
        cipher_text = key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return cipher_text


    def encyptUsingSymetricKey(self, key, iv, data):
        print "Using shared key to encrypt data"
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return ct


    def createToken(self, client1, client2):
        print "Create token for the clients to talk to each other"


    def decryptUsingPrivateKey(self, key, cipher):
        print "Decrypt the data using private key"
        data = key.decrypt(
            cipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )


    def decryptUsingSymetricKey(self, key, iv, ct):
        print "Decrypt using the shared key"
        cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(ct) + decryptor.finalize()
        return plain_text


    # generates and returns the private and public keys.
    def generatePublicPrivateKeys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        public_key = private_key.public_key()
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        pem_public = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Just writing them into files for now, we can decide where and how to store them, maybe just use variables?
        with open("server_private_key.txt", "w") as f:
            f.write(str(pem))

        with open("server_public_key.txt", "w") as f:
            f.write(str(pem_public))

        # Making the function also return them in case we want to store in variables.
        return pem, pem_public

    def main(self, argv):
        if len(argv) >= 1:
            if(argv[0] != '-h'):
                print "Error!! Invalid argument(s) used"
            print ChatServer.Usage
        else:
            self.receiveClientMessages()


if __name__ == "__main__":
    chatServer = ChatServer()
    chatServer.main(sys.argv[1:])