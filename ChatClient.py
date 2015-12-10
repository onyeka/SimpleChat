from ConfigParser import SafeConfigParser
import socket
import threading

import CryptoLib
import sys
import genPrime, Peer
import random

class ChatClient(object):
    """ Usage: prints out how to use the chat client
    """
    USAGE = 'usage: \tpython ChatClient.py -sip <server ip> -sp <server port>'
    '\t-h: prints this help message and exit'
    DBG = False

    # Read parameters from config file
    config = SafeConfigParser()
    config.read('client.cfg')
    salt = config.get('SectionOne', 'Salt')
    hKey = config.get('SectionOne', 'HKey')
    #prime = config.getint('SectionOne', 'PM')
    MSG_LEN = config.getint('SectionOne', 'MsgLen')
    generator = config.getint('SectionOne', 'Generator')
    PeerPrime = config.getint('SectionOne', 'PeerPrime')

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
            self.password = raw_input("Please enter your password: ")
            self.pwdHash = CryptoLib.generateSaltedPasswordHash(ChatClient.hKey,
                                                           ChatClient.salt,
                                                           self.password)
            if ChatClient.DBG is True:
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
        """
        Reads messages from socket
        :return: data read
        """
        try:
            data, addr = self.sock.recvfrom(ChatClient.MSG_LEN)
        except socket.timeout, e:
            print "Error: ", e
        return data

    def send_message(self, msg, addr, port):
        """
        Sends message through socket
        :param msg: message to be sent
        :param addr: address of receiver
        :param port: port of receiver
        :return: True/False
        """
        ret = False
        try:
            self.sock.sendto(msg, (addr, port))
            ret = True
        except Exception, e:
            print "send message failed: ", e
        return ret

    # Challenge solving function
    def solve_challenge(self, challenge, num):
        """
        Solve challenge set by server
        :param challenge: server challenge
        :param num: starting value
        :return: number
        """
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

    # def peer_connection(self, peerUsername, msg):
    #     ret = False
    #     print "connect to peer: ", peerUsername
    #     peerCipher = CryptoLib.encyptUsingSymmetricKey(self.sessionKey,
    #                                                self.sessionID, peerUsername)
    #     msg = "connect:%s:%s" % (self.sessionID, peerCipher)
    #     if not self.send_message(msg, self.serverAddr, self.port):
    #             return ret
    #     ticket = self.receive_response()

    def receive_peer_messages(self):
        print "receive messages..."

    def list_of_clients(self):
        print "Get list of clients from server"
        msg = "list:"
        self.send_message(msg,self.serverAddr, self.port)
        response = self.receive_response()
        print "list of clients: ", response

    # Called when this client wants to talk to another client
    def peer_request(self, username):
        ret = False
        # choose a random iv

        # concat iv with connect to msg and the username of the user to be connected to
        msg = "CONP:" + username

        # step 1: Request Server for the tickets
        msg = CryptoLib.encyptUsingSymmetricKey(self.sessionKey, self.sessionID, msg)
        if not self.send_message(msg, self.serverAddr, self.port):
            return ret

        # Step 2: receive the combined ticket from the server and split it into two parts
        combined_ticket = self.receive_response()
        combined_ticket = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID, combined_ticket)
        if combined_ticket == "unknown client requested":
            print combined_ticket
            return False
        combined_ticket = combined_ticket.split(",")
        user_ticket = combined_ticket[0]
        peer_ticket = combined_ticket[1]

        # decrypt the token for this client and unpack it.
        # Each ticket should contain the address, port and public key of the client concat using ,'s
        user_ticket = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID, user_ticket)
        user_ticket = user_ticket.split(":")
        peer_address = user_ticket[0]
        peer_public_key = user_ticket[1]

        # create peer object
        peer = Peer.Peer(username, peer_address, peer_public_key)

        # Step 3: message to talk to peer, should be handled by main function.
        # Encrypt and send peer its ticket
        msg = "CONR," + self.username + "," + peer_ticket
        msg = CryptoLib.encryptUsingPublicKey(peer_public_key, msg)
        if not self.send_message(msg, peer_address[0], peer_address[1]):
            return ret

        # Step 4: Receive and send contribution for shared key
        peer_contribution = self.receive_response()
        peer_contribution = CryptoLib.decryptUsingPrivateKey(self.clientPrivateKey, peer_contribution)
        a = CryptoLib.generateRandomKey(32)
        peer_session_id = CryptoLib.generateRandomKey(16)
        client_contribution = pow(2, a, self.PeerPrime)
        msg = str(client_contribution) + ":" + peer_session_id
        msg = CryptoLib.encryptUsingPublicKey(peer_public_key, msg)
        if not self.send_message(msg, peer_address[0], peer_address[1]):
            return ret

        # construct shared key and set iv and shared key to peer object
        shared_key = pow(peer_contribution, a, self.PeerPrime)
        peer.set_initialization_vector(peer_session_id)
        peer.set_shared_key(shared_key)

        # Step 5: Challenge response (Two way authentication) - user receives challenge, user increments and sends
        # back response which is again incremented and sent back to user. All of this is done using the symmetric
        # key encryption with the shared key.
        challenge = self.receive_response()
        challenge = int(CryptoLib.decryptUsingSymetricKey(shared_key, peer_session_id, challenge))
        challenge += 1
        response = CryptoLib.encyptUsingSymmetricKey(shared_key, peer_session_id, challenge)
        if not self.send_message(response, peer_address[0], peer_address[1]):
            return ret
        response = self.receive_response()
        response = CryptoLib.decryptUsingSymetricKey(shared_key, peer_session_id, response)

        # If authentication is successful, add the peer to list of connected peers
        if response == challenge + 1:
            self.peers[username] = peer
            return True

        return False

    # Called when this client is requested by another client (msg[0] = "CONR")
    # The msg is decrypted into the ticket and username and they are passed to this function
    def peer_response(self, key, ticket, peer_username):
        # Step 1: Decrypt and split the ticket to get the information of the client
        ret = False
        ticket = CryptoLib.decryptUsingSymetricKey(key, self.sessionID, ticket)
        ticket = ticket.split(":")
        peer_address = ticket[0]
        peer_public_key = ticket[1]
        peer = Peer.Peer(peer_username, peer_address, peer_public_key)

        # Step 2: Generate and send contribution
        b = CryptoLib.generatePublicPrivateKeys(32)
        msg = pow(2, b, self.PeerPrime)
        msg = CryptoLib.encryptUsingPublicKey(peer_public_key, msg)
        if not self.send_message(msg, peer_address[0], peer_address[1]):
            return ret

        # Step 3: Recieve peer contribution and iv and unpack it
        peer_contribution = self.receive_response()
        peer_contribution = CryptoLib.decryptUsingPrivateKey(self.clientPrivateKey, peer_contribution)
        peer_contribution = peer_contribution.split(":")
        peer_session_id = peer_contribution[1]
        peer_contribution = peer_contribution[0]

        # Construct shared key
        shared_key = pow(peer_contribution, b, self.PeerPrime)

        # Step 4: Challenge Response (Two way authentication) - user sends challenge, client increments and sends
        # back response which is again incremented and sent back to user. All of this is done using the symmetric
        # key encryption with the shared key.
        challenge = random.randrange(1, 100000)
        challenge = CryptoLib.encyptUsingSymmetricKey(shared_key, peer_session_id, challenge)
        if not self.send_message(challenge, peer_address[0], peer_address[1]):
            return ret
        response = self.receive_response()
        response = CryptoLib.decryptUsingSymetricKey(shared_key, peer_session_id, response)

        # If authentication is successful, add the peer to list of connected peers and send back response
        if response == challenge + 1:
            response += 1
            response = CryptoLib.encyptUsingSymmetricKey(shared_key, peer_session_id, response)
            if not self.send_message(response, peer_address[0], peer_address[1]):
                return ret
            peer.set_initialization_vector(peer_session_id)
            peer.set_shared_key(shared_key)
            self.peers[peer_username] = peer
            return True

        return False


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
        # receive data continuously from the clients
        chatClient = ChatClient(ipAddr, port)

        try:
            # login
            if chatClient.login() is True:
                # Not sure we need to use a thread
                thread = threading.Thread(name='Messages', target=chatClient.receive_peer_messages)
                thread.start()

            # wait for user to give us input
                while True:
                    try:
                        msg = raw_input("Type Your Messages: ")
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