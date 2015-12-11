from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from ConfigParser import SafeConfigParser
import socket, sys, Client, random, CryptoLib

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
        self.DBG = False

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
        if self.DBG is True:print " message received: '%s'" % msg
        msgContents = msg.split(":")

        if msgContents[0] == "AUTH":
            if knownClient is not None:
                print "client has already been Authenticated, ignore message..."
            else:
                self.challengeAnswer, challenge, firstFew = self.challengeResponse()
                response = str(challenge) + ":" + str(firstFew)
                self.sendMessage(response, addr)
        elif msgContents[0] == "CONTRIBUTION":
            if int(msgContents[1]) == self.challengeAnswer:
                if self.DBG is True: print "solved challenge!!!"
                for existingClients in self.clients.values():
                    if existingClients.get_name() == msgContents[2]:
                        print "client already exists, removing old client..."
                        msg = "DISCONNECTED:"
                        msg = CryptoLib.encyptUsingSymmetricKey(existingClients.get_session_key(),
                                                                existingClients.get_initialization_vector(),
                                                                msg)
                        self.sendMessage(msg, existingClients.get_address())
                        self.clients.pop(existingClients.get_address())

                # create and add new client to list
                client = Client.User(msgContents[2], addr)
                self.clients[addr] = client
                #**************************************************
                # Start authentication procedure (Augmented PDM)
                #**************************************************
                clientContribution = msgContents[3]
                b = CryptoLib.generateRandomKey(16)
                # retrieve the safe prime for the user
                primeTag = 'P' + (self.clients[addr]).get_name()
                try:
                    p = ChatServer.config.getint('SectionTwo', primeTag)
                except Exception, e:
                    print "couldn't get prime...: ", e
                    self.clients.pop(addr)
                    return
                # generate server contribution (2^b mod p) to send to server
                serverContribution = pow(ChatServer.generator, int(b.encode('hex'), 16), p)

                # retrieve the password hash for the user
                pwdHashTag = 'W' + (self.clients[addr]).get_name()

                # 2^W mod p
                try:
                    pwdHashExp = ChatServer.config.getint('SectionTwo', pwdHashTag)
                except Exception, e:
                    print "couldn't get pwd hash...: ", e
                    self.clients.pop(addr)
                    return

                #print "2^W mod p for client, pwdHashTag:%s ==> pwdHashExp:%s" % (pwdHashTag, pwdHashExp)

                # 2^ab mod p
                sharedKey1 = CryptoLib.generateSecretKey(int(clientContribution),
                                                     int(b.encode('hex'), 16), p)
                # 2^bW mod p
                sharedKey2 = CryptoLib.generateSecretKey(pwdHashExp, int(b.encode('hex'), 16), p)

                sessionKey = (str(sharedKey1) + str(sharedKey2))[0:16]
                #print "Server: sharedKey1: %s, sharedKey2: %s, sessionKey: %s" % (sharedKey1,
                #                                                      sharedKey2, sessionKey)
                # HASH(2^ab mod p, 2^bW modp)
                sessionKeyHash = CryptoLib.generateKeyHash(sessionKey)
                if self.clients.get(addr) is not None:
                    self.clients.get(addr).set_session_key_and_hash(sessionKey, sessionKeyHash)
                    iv = CryptoLib.generateRandomKey(8).encode('hex')
                    self.clients.get(addr).set_initialization_vector(iv)
                    response = str(serverContribution) + ":" + sessionKeyHash + ":" + iv
                    if self.DBG: print "====== sending: ", response
                    self.sendMessage(response, addr)
                    return
            else:
                print "Invalid client!!!"

        elif msgContents[0] == "DISCONNECTING":
            msg = "DISCONNECTED:"
            msg = CryptoLib.encyptUsingSymmetricKey(self.clients[addr].get_session_key(),
                                                    self.clients[addr].get_initialization_vector(), msg)
            self.sendMessage(msg, addr)
            self.clients.pop(addr)

        elif msgContents[0] == "VALIDATE":
            if knownClient is not None and knownClient.get_session_key_hash() == msgContents[1]:
                knownClient.set_public_key(msgContents[3])
                msgContents[2] = int(msgContents[2]) +1
                response = "ACKNOWLEDGE:" + str(msgContents[2])
                response = CryptoLib.encyptUsingSymmetricKey(knownClient.get_session_key(),
                                                             knownClient.get_initialization_vector(),
                                                             response)
                self.sendMessage(response, knownClient.get_address())
                # client is fully authenticated
                knownClient.set_authenticated = True
            else:
                if self.clients.has_key(knownClient.get_address()):
                    self.clients.pop(knownClient.get_address())

        elif msgContents[0] == "CONP":
            peer_to_connect = msgContents[1]
            client1_address = knownClient.getAddress()
            client1_key = knownClient.getPublicKey()
            client2_address = None
            client2_key = None
            client1_shared_key = knownClient.getSessionKey()
            for address in self.clients:
                if self.clients[address].getName() == peer_to_connect:
                    client2_address = address
                    client2_key = self.clients[address].getPublicKey()
            if client2_address is not None:
                self.create_token(client1_address,client2_address,client1_key,client2_key, client1_shared_key)
            else:
                msg = "unknown client requested"
                msg = CryptoLib.encyptUsingSymmetricKey(client1_shared_key, knownClient.getInitializationVector(), msg)
                self.sendMessage(msg, client1_address)

        elif msgContents[0] == "list":
            if knownClient is not None and knownClient.get_session_key() is not None:
                response = ""
                for client in self.clients.values():
                    response = response + client.get_name() + ","
                print " list of clients: ", response
                response = CryptoLib.encyptUsingSymmetricKey(knownClient.get_session_key(),
                                                             knownClient.get_initialization_vector(),
                                                             response)
                self.sendMessage(response, knownClient.get_address())
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
            if client.get_session_key() is None and client.get_initialization_vector() is None:
                decrypted_msg = CryptoLib.decryptUsingPrivateKey(self.private_key, msg)
            else:
                decrypted_msg = CryptoLib.decryptUsingSymetricKey(client.get_session_key(),
                                                             client.get_initialization_vector(), msg)

            self.handleClientMessages(decrypted_msg, client, addr)
        else:
            if self.DBG: print "it's a potential client!!"
            self.handleClientMessages(msg, None, addr)

    # Should create 2 tokens, joined by ":" and encrypted with the shared key of the user requesting
    # the communication and send it to the user. The tokens contain 3 parts, the user address, the
    # user port and the public key of the user.
    def create_token(self, user1_address, user2_address, user1_key, user2_key, key):
        token1 = user1_address + ":" + user1_key
        token2 = user2_address + ":" + user2_key
        token = token1 + "," + token2
        # TODO: server needs to store the client information into the clients dictionary (maybe key on username?)
        token = CryptoLib.encyptUsingSymmetricKey(key, self.clients[user1_address].getInitializationVector(), token)
        self.sendMessage(token, user1_address)


def main(argv):
    if len(argv) >= 1:
        if(len(argv) == 1 and argv[0] != '-h'):
            print "Error!! Invalid argument(s) used"
        print ChatServer.USAGE
    else:
        chatServer = ChatServer()
        if(chatServer != None):
            while True:
                try:
                    chatServer.receiveClientMessages()
                except (KeyboardInterrupt, SystemExit):
                    print "Got keyboard or system exit interrupt"
                    break

if __name__ == "__main__":
    main(sys.argv[1:])
