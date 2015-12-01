from ConfigParser import SafeConfigParser
import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
import os
import sys


class ChatClient(object):
    """ Usage: prints out how to use the chat client
    """
    USAGE = 'usage: \tpython ChatClient.py -sip <server ip> -sp <server port>'
    '\t-h: prints this help message and exit'

    # Read parameters from config file
    config = SafeConfigParser()
    config.read('client.cfg')
    salt = config.getint('SectionOne', 'Salt')
    hKey = config.getint('SectionOne', 'HKey')
    MSG_LEN = config.getint('SectionOne', 'MsgLen')

    def __init__(self, ipAddr, port):
        self.serverAddr = ipAddr
        self.port = port
        self.count = 3 # only 3 login attempts are allowed
        self.isAuthenticated = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def login(self):
        while(self.count != 0):
            self.count -= 1
            self.username = input("Please enter your username: ")
            print "username: ", self.username
            password = input("Please enter your password: ")
            print "password: ", self.password
            pwdHash = self.generatePasswordHash(password)
            self.isAuthenticated = self.authenticateMe(pwdHash)
            if(self.isAuthenticated == True):
                print "===============================\n" \
                      " Welcome {}! Happy Chatting!!! \n".format(self.username), \
                      "===============================\n"
                break
            else:
                print " Error!! username or password is invalid, please try again\n"

        if(self.count == 0):
            print " Exceeded number of trials...Good bye!"
            sys.exit(-1)
        else:
            return self.isAuthenticated

    def authenticateMe(self):
        print "authenticate with chat server and set up session key"

    def receiveMessages(self):
        print "receive messages..."

    def encryptUsingPublicKey(self, key, data):
        print "Use private key to encrypt the data"
        cipher_text = key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return cipher_text

    def encyptUsingSymetricKey(self, key, data):
        print "Use shared key to encrypt data"
        backend = default_backend()
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return ct


    def ListOfClients(self):
        print "Get list of clients from server"

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

    def decryptUsingSymetricKey(self, key):
        print "Decrypt using the shared key"


    # generates and returns the private and public keys.
    def generatePublicPrivateKeys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        public_key = private_key.public_key()
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        pem_public = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Just writing them into files for now, we can decide where and how to store them, maybe just use variables?
        with open("client_private_key.txt", "w") as f:
            f.write(str(pem))

        with open("client_public_key.txt", "w") as f:
            f.write(str(pem_public))

        # Making the function also return them in case we want to store in variables.
        return pem, pem_public

    def generatePasswordHash(self, password):
        h = hmac.HMAC(ChatClient.hKey, hashes.SHA256(), backend=default_backend())
        h.update(ChatClient.salt+password)
        pwdHash = h.finalize()
        print " password Hash: ", pwdHash
        return pwdHash

def main(argv):
    if (len(argv) != 4) or (argv[0] != "-sip" and argv[2] != "-sp"):
        print "Error!! Invalid argument(s) used"
        print ChatClient.USAGE
    else:
        try:
            ipAddr = argv[1]
            port = int(argv[3])
        except IOError as e:
            print "couldn't get ip address or port:", e
            sys.exit(-1)

        # create the client and spawn a thread to
        # receive data continuously from the server/clients
        chatClient = ChatClient(ipAddr, port)

        # login
        if(chatClient.login() == True):
            #Not sure we need to use a thread
            thread = threading.Thread(name='Messages', target=chatClient.receiveMessages)
            thread.start()
        # wait for user to give us input
        while True:
            print("Type your messages:")
            msg = input("Type your messages: ")
            #chatClient.send_msg(msg)

if __name__ == "__main__":
    main(sys.argv[1:])