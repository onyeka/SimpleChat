from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os, socket, logging, sys, Client

class ChatServer(object):
    def __init__(self):
        self.clients = {}
        self.count = 0
        self.port = 9060
        self.MSG_LEN = 2048

        # get server's private key
        self.private_key = ChatServer.getPrivateKey()

        # open up server socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_address = (socket.gethostbyname(socket.gethostname()), self.port)
            self.sock.bind(self.server_address)
            logging.debug("Initialized UDP Server.... %s", self.server_address)
        except RuntimeError, e:
            logging.debug("Initializing server socket failed: %s", os.strerror(e.errno))

    def getPrivateKey(self):
        # open up files
        try:
            with open("server_private_key.txt", 'rb') as f:
                private_key = f.read()
                f.close()
                return private_key
        except IOError as e :
            logging.debug(" couldn't get server private key: Error: %s", e)
            sys.exit(-1)

    # Handles messages sent from clients
    def handleClientMessages(self, msg, client):
        logging.debug(" message received: %s", msg)

    # Receives messages sent from clients
    def receiveClientMessages(self):
        msg, addr = self.sock.recvfrom(ChatServer.MSGLEN)
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
        # setup logging
        logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-10s) %(message)s')
        chatServer = ChatServer()
        chatServer.main(argv[1:])
