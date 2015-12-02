from ConfigParser import SafeConfigParser
import socket
import threading

import CryptoLib
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
    prime = config.getint('SectionOne', 'PM')
    MSG_LEN = config.getint('SectionOne', 'MsgLen')
    generator = config.getint('SectionOne', 'Generator')

    def __init__(self, ipAddr, port):
        self.serverAddr = ipAddr
        self.port = port
        self.count = 3 # only 3 login attempts are allowed
        self.isAuthenticated = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peers = {}

        self.serverPublicKey = self.getServerPublicKey()
        if(self.serverPublicKey == -1):
            sys.exit(-1)

    def login(self):
        while(self.count != 0):
            self.count -= 1
            self.username = input("Please enter your username: ")
            print "username: ", self.username
            password = input("Please enter your password: ")
            print "password: ", self.password
            pwdHash = CryptoLib.generateSaltedPasswordHash(ChatClient.hKey,
                                                           ChatClient.salt,
                                                           password)
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

    def receiveMessage(self):
        data, addr = self.sock.recvfrom(ChatClient.MSG_LEN)
        return data

    def sendMessage(self, msg, addr, port):
        ret = False
        try:
            self.sock.sendto(msg, (addr, port))
            ret = True
        except Exception, e:
            print "send message failed: ", e
        return ret

    def authenticateMe(self, pwdHash):
        print "authenticate with chat server and set up session key"
        ret = False
        if(self.serverPublicKey != None):
            # step 1: send authentication message
            msg = "Authenticate:"
            if(self.sendMessage(msg, self.serverAddr, self.port) == False):
                return ret

            # step 2: receive challenge
            challenge = self.receiveMessage()

            # step 3: handle challenge and generate response as well as
            # Diffie Hellman contribution
            # TODO: handle challenge received and generate response
            clientContribution = CryptoLib.generateDHContribution(ChatClient.generator,
                                                                  ChatClient.prime)

            # step 4: encrypt client contribution and send response
            clientCipher = CryptoLib.encryptUsingPublicKey(self.serverPublicKey,
                                                           clientContribution)
            msg = "Response:todo:%s:%s" % (self.username, clientCipher)
            if(self.sendMessage(msg, self.serverAddr, self.port) == False):
                return ret

            # step 5: receive server contribution and hash
            serverContribution = self.receiveMessage()

            # step 6: TODO: calculate session key and hash

            # step 7: send server client's public key
            ret = True
        return ret

    def peerConnection(self, peerUsername, msg):
        print "connect to peer: ", peerUsername

    def receiveMessages(self):
        print "receive messages..."

    def ListOfClients(self):
        print "Get list of clients from server"

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
            msg = input("Type your messages to the server: ")
            msgSplit = msg.split()
            if(len(msgSplit) == 1):
                if(msgSplit[0] == 'list'):
                    chatClient.ListOfClients()
            elif(len(msgSplit) == 3):
                if(msgSplit[0] == 'send'):
                    ret = chatClient.peerConnection(msgSplit[1], msgSplit[2])
                    if(ret == True):
                        print "connected to peer"

if __name__ == "__main__":
    main(sys.argv[1:])