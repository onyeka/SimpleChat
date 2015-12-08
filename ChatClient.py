from ConfigParser import SafeConfigParser
import socket
import threading

import CryptoLib
import sys
import genPrime


class ChatClient(object):
    """ Usage: prints out how to use the chat client
    """
    USAGE = 'usage: \tpython ChatClient.py -sip <server ip> -sp <server port>'
    '\t-h: prints this help message and exit'

    # Read parameters from config file
    config = SafeConfigParser()
    config.read('client.cfg')
    salt = config.get('SectionOne', 'Salt')
    hKey = config.get('SectionOne', 'HKey')
    #prime = config.getint('SectionOne', 'PM')
    MSG_LEN = config.getint('SectionOne', 'MsgLen')
    generator = config.getint('SectionOne', 'Generator')

    def __init__(self, ipAddr, port):
        self.serverAddr = ipAddr
        self.port = port
        self.count = 3 # only 3 login attempts are allowed
        self.isAuthenticated = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5.0)
        self.peers = {}

        self.serverPublicKey = CryptoLib.getPublicKey('server_public_key.pem')
        if(self.serverPublicKey == -1):
            sys.exit(-1)

    def login(self):
        while self.count != 0:
            self.count -= 1
            self.username = raw_input("Please enter your username: ")
            print "username: ", self.username
            self.password = raw_input("Please enter your password: ")
            self.pwdHash = CryptoLib.generateSaltedPasswordHash(ChatClient.hKey,
                                                           ChatClient.salt,
                                                           self.password)
            print "password: %s, pwdHash: %s " % (self.password, self.pwdHash)
            self.isAuthenticated = self.authenticate_me(self.pwdHash)
            if self.isAuthenticated is True:
                print "===============================\n" \
                      " Welcome {}! Happy Chatting!!! \n".format(self.username), \
                      "===============================\n"
                break
            else:
                print " Error!! username or password is invalid, please try again\n"

        if self.count == 0:
            print " Exceeded number of trials...Good bye!"
            sys.exit(-1)
        else:
            return self.isAuthenticated

    def receive_response(self):
        data = None
        addr = None
        try:
            data, addr = self.sock.recvfrom(ChatClient.MSG_LEN)
        except socket.timeout, e:
            print "Error: ", e
        return data

    def send_message(self, msg, addr, port):
        ret = False
        try:
            self.sock.sendto(msg, (addr, port))
            ret = True
        except Exception, e:
            print "send message failed: ", e
        return ret

    # Challenge solving function
    def solve_challenge(self, challenge, num):
        print " challenge: %s, num: %s" % (challenge, num)

        response = int(CryptoLib.generateKeyHash(str(num)), 16)
        while response != challenge:
            num += 1
            response = int(CryptoLib.generateKeyHash(str(num)), 16)
            #print " challenge: %x, hash: %x" % (challenge, response)

        return num

    def authenticate_me(self, pwdHash):
        print "authenticate with chat server and set up session key"
        ret = False
        if self.serverPublicKey is not None:
            # step 1: send authentication message
            msg = "AUTH:"
            if not self.send_message(msg, self.serverAddr, self.port):
                return ret

            # step 2: receive challenge and starting number
            serverResponse = self.receive_response()
            if(serverResponse is None): return ret
            challengeAndStartingNum = serverResponse.split(":")
            challenge = int(challengeAndStartingNum[0],16)
            startingNum = int(challengeAndStartingNum[1])

            # step 3: solve challenge and generate response to server
            response = self.solve_challenge(challenge, startingNum)
            msg = "SOLV:" + str(response) + ":" + self.username
            print " Challenge was: %s, Number was: %s" % (challenge, response)
            if self.send_message(msg, self.serverAddr, self.port) is False:
                return ret

            #**************************************************
            # Start authentication procedure (Augmented PDM)
            #**************************************************
            a = CryptoLib.generateRandomKey(16)
            # retrieve the safe prime for the user
            p = genPrime.genp(self.username, self.password)

            # step 4: encrypt client contribution and send response
            #clientCipher = CryptoLib.encryptUsingPublicKey(self.serverPublicKey,
            #                                               clientContribution)
            # msg = "Response:todo:%s:%s" % (self.username, clientCipher)
            #if self.send_message(msg, self.serverAddr, self.port) is False:
            #    return ret

            # generate client contribution (2^a mod p) to send to server
            clientContribution = pow(ChatClient.generator, int(a.encode('hex'), 16), p)
            msg = CryptoLib.encryptUsingPublicKey(self.serverPublicKey,
                                                  "CONT:" + str(clientContribution))
            if not self.send_message(msg, self.serverAddr, self.port):
                return ret

            # step 5: receive server contribution and shared key hash
            serverResponse = self.receive_response()
            if(serverResponse is None): return ret
            serverContributionAndHash = serverResponse.split(":")
            serverContribution = serverContributionAndHash[0]
            serverSessionKeyHash = serverContributionAndHash[1]

            # step 6: calculate session key and hash
            W = pwdHash
            # 2^ab mod p
            sharedKey1 = CryptoLib.generateSecretKey(int(serverContribution),
                                                     int(a.encode('hex'), 16), p)
            # 2^bW mod p
            sharedKey2 = CryptoLib.generateSecretKey(int(serverContribution), int(W, 16), p)
            print "===== W: ", W
            sessionKey = (str(sharedKey1) + str(sharedKey2))[0:16]
            print "sharedKey1: %s, sharedKey2: %s, sessionKey: %s, len: %d" % \
                  (sharedKey1, sharedKey2, sessionKey, len(sessionKey))

            # HASH(2^ab mod p, 2^bW modp)
            sessionKeyHash = CryptoLib.generateKeyHash(sessionKey)
            if(serverSessionKeyHash == sessionKeyHash):
                self.sessionKey = sessionKey
                self.sessionID = serverContributionAndHash[2]
                print"====== sessionID : ", self.sessionID

            # step 7: send hash of encrypted session key and public key to server
                self.clientPrivateKey, self.clientPublicKey = CryptoLib.generatePublicPrivateKeys()
                validateServer = CryptoLib.generateRandomKey(16)

                msg = "VALD:" + sessionKeyHash + ":" + self.clientPublicKey + ":" + validateServer
                msg = CryptoLib.encyptUsingSymmetricKey(self.sessionKey, self.sessionID,
                                                        msg)
                if not self.send_message(msg, self.serverAddr, self.port):
                    return ret

                # server signals that client has been fully authenticated
                response = self.receive_response()
                serverResponse = response.split(":")
                if serverResponse[0] == "ACK" and serverResponse[1] == validateServer:
                    ret = True

            # End of authentication with server.

        return ret

    def peer_connection(self, peerUsername, msg):
        ret = False
        print "connect to peer: ", peerUsername
        peerCipher = CryptoLib.encyptUsingSymmetricKey(self.sessionKey,
                                                   self.sessionID, peerUsername)
        msg = "connect:%s:%s" % self.sessionID, peerCipher
        if not self.send_message(msg, self.serverAddr, self.port):
                return ret
        ticket = self.receive_response()

    def receive_chat_messages(self):
        print "receive messages..."

    def list_of_clients(self):
        print "Get list of clients from server"
        msg = "list:"
        self.send_message(msg,self.serverAddr, self.port)
        response = self.receive_response()
        print "list of clients: ", response

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

        # create the client, login and spawn a thread to
        # receive data continuously from the server/clients
        chatClient = ChatClient(ipAddr, port)

        try:
            # login
            if chatClient.login() is True:
                # Not sure we need to use a thread
                thread = threading.Thread(name='Messages', target=chatClient.receive_messages)
                thread.start()
            # wait for user to give us input
            while True:
                try:
                    msg = raw_input("Type your messages to the server: ")
                    msgSplit = msg.split()
                    if len(msgSplit) == 1:
                        if msgSplit[0] == 'list':
                            chatClient.list_of_clients()
                    elif len(msgSplit) == 3:
                        if msgSplit[0] == 'send':
                            ret = chatClient.peer_connection(msgSplit[1], msgSplit[2])
                            if ret is True:
                                print "connected to peer"
                except (KeyboardInterrupt, SystemExit):
                    print "Got keyboard or system exit interrupt"
                    break
        except (KeyboardInterrupt, SystemExit):
            print "Got keyboard or system exit interrupt"
            return

if __name__ == "__main__":
    main(sys.argv[1:])