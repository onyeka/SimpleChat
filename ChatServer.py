from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from ConfigParser import SafeConfigParser
import socket, logging, sys, Client, random, CryptoLib

class ChatServer(object):
    """ Usage: prints out how to use the server
    """
    USAGE = 'usage: \tpython ChatServer.py\n' \
    '\t-h: prints this help message and exit'
    config = SafeConfigParser()
    config.read('server.cfg')
    port = config.getint('SectionOne', 'Port')
    MSG_LEN = config.getint('SectionOne', 'MsgLen')
    generator = config.getint('SectionOne', 'Generator')
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

    def sendMessage(self, msg, addr):
        ret = False
        try:
            self.sock.sendto(msg, addr)
            ret = True
        except Exception, e:
            print "send message failed: ", e
        return ret

    # gives a tuple with the response to be gotten,
    # the challenge to send and the accompanying number to be sent
    def challengeResponse(self):
        # generate a sufficiently large random number
        num = random.randrange(100000, 1000000)
        # generate a random number to subtract from it
        firstFew = random.randrange(1000, 10000)
        firstFew = num - firstFew
        # create the challenge hash
        challenge = CryptoLib.generateKeyHash(str(num))
        return num, challenge, firstFew

    # Handles messages sent from clients
    def handleClientMessages(self, msg, knownClient, addr):
        print " message received: '%s'" % msg
        msgContents = msg.split(":")

        if msgContents[0] == "AUTH":
            self.challengeAnswer, challenge, firstFew = self.challengeResponse()
            msg = str(challenge) + ":" + str(firstFew)
            print "sending AUTH Ans: %d, challenge: %d, firstFew: %d, msg: %s" % \
                  (self.challengeAnswer, int(challenge, 16), firstFew, msg)
            self.sendMessage(msg, addr)
        elif msgContents[0] == "SOLV":
            if int(msgContents[1]) == self.challengeAnswer:
                print " solved!!!! %s, ans: %s, user: %s" % \
                      (msgContents[1], self.challengeAnswer, msgContents[2])
                client = Client.User(msgContents[2], addr)
                self.clients[addr] = client
        elif msgContents[0] == "CONT":
            clientContribution = msgContents[1]
            #**************************************************
            # Start authentication procedure (Augmented PDM)
            #**************************************************
            b = CryptoLib.generateRandomKey(16)
            # retrieve the safe prime for the user
            primeTag = 'P' + (self.clients[addr]).getName()
            p = ChatServer.config.getint('SectionTwo', primeTag)
            print "prime for client: %s ==> %s" % (primeTag, p)
            # generate server contribution (2^b mod p) to send to server
            serverContribution = pow(ChatServer.generator, b, p)

            # retrieve the password hash for the user
            pwdHashTag = 'W' + (self.clients[addr]).getName()
            # 2^W mod p
            pwdHash = ChatServer.config.getint('SectionTwo', pwdHashTag)

            # 2^ab mod p
            sharedKey1 = CryptoLib.generateSecretKey(clientContribution, b, p)
            # 2^bW mod p
            sharedKey2 = CryptoLib.generateSecretKey(pwdHash, b, p)
            sessionKey = str(sharedKey1) + ":" + str(sharedKey2)
            print "Server: sharedKey1: %s, sharedKey2: %s, sessionKey: %s" % (sharedKey1,
                                                                      sharedKey2, sessionKey)
            # HASH(2^ab mod p, 2^bW modp)
            sessionKeyHash = CryptoLib.generateKeyHash(sessionKey)
            if knownClient is not None:
                knownClient.setSessionKeyAndHash(sessionKey, sessionKeyHash)
                msg = serverContribution + ":" + sessionKeyHash
                self.sendMessage(msg, addr)
            else:
                print "Server: unknown client!!!"
        else:
            print "Server: unknown message: ", msg

    # Receives messages sent from clients
    def receiveClientMessages(self):
        msg, addr = self.sock.recvfrom(ChatServer.MSG_LEN)
        isClientKnown = self.clients.has_key(addr)
        if(isClientKnown):
            client = self.clients.get(addr)
            if(client == None):
                print "couldn't retrieve client"
                return
            if client.getSessionKey() is None:
                decrypted_msg = CryptoLib.decryptUsingPrivateKey(self.private_key, msg)
            else:
                decrypted_msg = self.decryptUsingSymetricKey(client.getSessionKey(),
                                                             client.getInitializationVector(),
                                                             msg)

            self.handleClientMessages(decrypted_msg, client, addr)
        else:
            print "it's a potential client!!"
            self.handleClientMessages(msg, None, addr)

    def encyptUsingSymetricKey(self, key, iv, data):
        print "Using shared key to encrypt data"
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return ct


    def createToken(self, client1, client2):
        print "Create token for the clients to talk to each other"

def main(argv):
    if len(argv) >= 1:
        if(len(argv) == 1 and argv[0] != '-h'):
            print "Error!! Invalid argument(s) used"
        print ChatServer.USAGE
    else:
        chatServer = ChatServer()
        if(chatServer != None):
            while True:
                chatServer.receiveClientMessages()

if __name__ == "__main__":
    main(sys.argv[1:])