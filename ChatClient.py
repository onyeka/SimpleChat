from ConfigParser import SafeConfigParser
import socket
import threading
import select

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
    peerPrime = config.getint('SectionOne', 'PeerPrime')
    peerGenerator = config.getint('SectionOne', 'PeerGenerator')

    def __init__(self, ipAddr, port):
        self.serverAddr = ipAddr
        self.port = port
        self.count = 3 # only 3 login attempts are allowed
        self.isAuthenticated = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(3.0)
        self.peers = {}
        self.DBG = False

        self.serverPublicKey = CryptoLib.getPublicKey('server_public_key.pem')
        if(self.serverPublicKey == -1):
            sys.exit(-1)

    def getSocket(self):
        return self.sock

    def disconnectClient(self):
        if self.isAuthenticated == True:
            msg = "DISCONNECTING:"
            self.send_encrypted_message(msg)

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
        data = None
        address = None
        try:

            #print "===== receive_response: LOCKING ====="
            data, address = self.sock.recvfrom(ChatClient.MSG_LEN)
        except socket.timeout, e:
            #print "Main Thread Error: ", e
            address = None
        #finally:
            #print "===== receive_response: RELEASING ====="
        return data

    def send_encrypted_message(self, msg):
        """
        Sends encrypted message through socket
        :param msg: message to be sent
        :return: True/False
        """
        ret = False
        try:
            msg = CryptoLib.encyptUsingSymmetricKey(self.sessionKey, self.sessionID, msg)
            self.sock.sendto(msg, (self.serverAddr, self.port))
            ret = True
        except Exception, e:
            print "send message failed: ", e
        return ret

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
        if self.DBG:
            print " challenge: %s, num: %s" % (challenge, num)

        response = int(CryptoLib.generateKeyHash(str(num)), 16)
        while response != challenge:
            num += 1
            response = int(CryptoLib.generateKeyHash(str(num)), 16)
            #print " challenge: %x, hash: %x" % (challenge, response)

        return num

    def authenticate_me(self, pwdHash):
        #print "authenticate with chat server and set up session key"
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

            #**************************************************
            # Start authentication procedure (Augmented PDM)
            #**************************************************
            # step 3: solve challenge and send APDM contribution
            challenge_response = self.solve_challenge(challenge, startingNum)

            a = CryptoLib.generateRandomKey(16)
            # retrieve the safe prime for the user
            p = genPrime.genp(self.username, self.password)

            # step 4: generate client contribution (2^a mod p) and send challenge response,
            # client user name and contribution to server Note: no need to encrypt because eavesdropper
            # cannot compute 2^W mod p
            client_contribution = pow(ChatClient.generator, int(a.encode('hex'), 16), p)
            msg = "CONTRIBUTION:" + str(challenge_response) + ":" + self.username + ":" + str(client_contribution)
            #msg = CryptoLib.encryptUsingPublicKey(self.serverPublicKey, msg)
            if not self.send_message(msg, self.serverAddr, self.port):
                return ret

            # step 5: receive server contribution and shared key hash
            serverResponse = self.receive_response()
            if(serverResponse is None):
                print "failed to receive response from server"
                return ret

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
            #print "===== W: ", W
            sessionKey = (str(sharedKey1) + str(sharedKey2))[0:16]
            if self.DBG:
                print "sharedKey1: %s, sharedKey2: %s, sessionKey: %s, len: %d" % \
                  (sharedKey1, sharedKey2, sessionKey, len(sessionKey))

            # HASH(2^ab mod p, 2^bW modp)
            sessionKeyHash = CryptoLib.generateKeyHash(sessionKey)
            if(serverSessionKeyHash == sessionKeyHash):
                self.sessionKey = sessionKey
                self.sessionID = serverContributionAndHash[2]
                if self.DBG:
                    print"====== session keys match!! sessionID %s, len: %d " % \
                     (self.sessionID, len(self.sessionID))

            # step 7: send hash of encrypted session key and public key to server
                self.clientPrivateKey, self.clientPublicKey = CryptoLib.generatePublicPrivateKeys()
                validateServer = int(CryptoLib.generateRandomKey(16).encode("hex"), 16)

                #msg = "VALIDATE:" + sessionKeyHash + ":" + self.clientPublicKey + ":" + validateServer
                msg = "VALIDATE:" + sessionKeyHash + ":" + str(validateServer) + ":" + self.clientPublicKey

                msg = CryptoLib.encyptUsingSymmetricKey(self.sessionKey, self.sessionID,
                                                        msg)
                if not self.send_message(msg, self.serverAddr, self.port):
                    return ret

                # server signals that client has been fully authenticated
                response = self.receive_response()
                if response is None:
                    print "Error!!! didn't receive response from server"
                    return ret
                response = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID, response)
                response = response.split(":")
                if self.DBG is True:
                    print "validateServer: %s, serverResponse: %s" % (str(validateServer),
                                                                  response[1])
                if response[0] == "ACKNOWLEDGE" and \
                    int(validateServer + 1 == int(response[1])):
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

    def list_of_clients(self):
        print "Get list of clients from server"
        msg = "list:"
        msg = CryptoLib.encyptUsingSymmetricKey(self.sessionKey, self.sessionID, msg)
        self.send_message(msg,self.serverAddr, self.port)
        print
        response = self.receive_response()
        if response is not None:
            response = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID, response)
        print "list of clients: ", response

    # Called when this client wants to talk to another client
    def authenticate_peer(self, username):
        ret = False
        # choose a random iv

        # send server the username of the client we want to chat with
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
        if combined_ticket is None:
            print "Error!!! Didn't receive ticket from server"
            return ret

        combined_ticket = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID,
                                                            combined_ticket).split(",")
        user_ticket = combined_ticket[0]
        peer_ticket = combined_ticket[1]

        # decrypt the token for this client and unpack it.
        # Each ticket should contain the address, port and public key of the client concat using ,'s
        user_ticket = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID, user_ticket)
        user_ticket = user_ticket.split(":")
        peer_address = user_ticket[0]
        peer_tmp_shared_key = user_ticket[1]
        if user_ticket[2] != username:
            print "Error!!! wrong peer received!!!"
            return ret

        peer_tmp_iv = user_ticket[3]

        # create peer object
        peer = Peer.Peer(username, peer_address)

        # Step 3: message to talk to peer encrypted with key given by the server
        # message to peer contains peer's ticket
        msg = "REQUEST_PEER_CONNECTION:" + self.username + ":" + peer_ticket
        msg = CryptoLib.encyptUsingSymmetricKey(peer_tmp_shared_key, peer_tmp_iv, msg)
        if not self.send_message(msg, peer_address[0], peer_address[1]):
            return ret

        # Step 4: Receive peer's contribution for DH key
        response = self.receive_response()
        if response is None:
            print "Error!!! Didn't receive contribution from peer: ", username
            return ret
        peer_contribution = CryptoLib.decryptUsingSymetricKey(peer_tmp_shared_key, peer_tmp_iv, response)

        # Step 5: Generate and send contribution for DH key as well as the initialization vector
        a = CryptoLib.generateRandomKey(32)
        peer_session_id = CryptoLib.generateRandomKey(16)
        client_contribution = pow(self.peerGenerator, a, self.peerPrime)
        msg = "PEER_CONTRIBUTION:" + str(client_contribution) + ":" + peer_session_id
        msg = CryptoLib.encyptUsingSymmetricKey(peer_tmp_shared_key, peer_tmp_iv, msg)
        if not self.send_message(msg, peer_address[0], peer_address[1]):
            return ret

        # Now construct the shared key and set iv and shared key to peer object
        shared_key = pow(peer_contribution, a, self.peerPrime)

        # Step 6: Challenge response (Two way authentication) - user receives challenge, user increments and sends
        # back response which is again incremented and sent back to user. All of this is done using the symmetric
        # key encryption with the shared key.
        challenge = self.receive_response()
        if challenge is None:
            print "Error!!! Didn't receive challenge from peer"
            return ret
        challenge = int(CryptoLib.decryptUsingSymetricKey(shared_key, peer_session_id, challenge))
        challenge += 1

        msg = "PEER_CHALLENGE:" + challenge
        msg = CryptoLib.encyptUsingSymmetricKey(shared_key, peer_session_id, msg)
        if not self.send_message(msg, peer_address[0], peer_address[1]):
            return ret

        response = self.receive_response()
        if response is None:
            print "Error!!! Didn't receive response from peer"
            return ret
        response = CryptoLib.decryptUsingSymetricKey(shared_key, peer_session_id, response)

        # If authentication is successful, add the peer to list of connected peers
        if response == challenge + 1:
            peer.set_initialization_vector(peer_session_id)
            peer.set_shared_key(shared_key)
            peer.set_authenticated_flag(True)
            self.peers[username] = peer
            return True

        return False

    def receive_peer_messages(self):
        """
        Reads messages from socket
        :return: data read
        """
        try:
            msg, addr = self.sock.recvfrom(ChatClient.MSG_LEN)
            if self.peers.has_key(addr):
                peer = self.peers.get(addr)
                response = CryptoLib.decryptUsingSymetricKey(peer.get_shared_key(),
                                                             peer.get_initialization_vector(), msg)
                response = response.split(":")
                if response[0] == "PEER_CONTRIBUTION":
                    peer_contribution = response[1]
                    if response[2] is None:
                        print "Error: didn't receive IV"
                    else:
                        peer.set_initialization_vector(response[2])
                        shared_key = pow(peer_contribution, peer.get_client_b(), self.peerPrime)
                        peer.set_shared_key(shared_key)
                        challenge = CryptoLib.generateRandomKey(16)
                        msg = CryptoLib.encyptUsingSymmetricKey(peer.get_shared_key(),
                                                                peer.get_initialization_vector(), challenge)
                        self.send_message(msg, peer.get_address()[0], peer.get_address()[1])
                else:
                    print "Error: unknown message sent!!!"
            elif addr == (self.serverAddr, self.port):
                response = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID, msg)
                response = response.split(":")
                if response[0] == "DISCONNECTED":
                    print " Server Disconnected us... Good bye!"
                    sys.exit(0)

        except socket.timeout, e:
            #print "Thread Error: ", e
            msg = None

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
        msg = pow(2, b, self.peerPrime)
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
        shared_key = pow(peer_contribution, b, self.peerPrime)

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
            self.peers[peer_address] = peer
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

                # wait for user to give us input
                while True:
                    try:
                        print "Type Your Message: "
                        rlist, wlist, elist = select.select([sys.stdin, chatClient.getSocket()], [], [])
                        for event in rlist:
                            if event == chatClient.getSocket():
                                chatClient.receive_peer_messages()
                            else:
                                msg = sys.stdin.readline()
                                msgSplit = msg.split()
                                if len(msgSplit) == 1:
                                    if msgSplit[0] == 'list':
                                        chatClient.list_of_clients()
                                    elif msgSplit[0] == 'bye':
                                        chatClient.disconnectClient()
                                elif len(msgSplit) == 3:
                                    if msgSplit[0] == 'send':
                                        ret = chatClient.peer_connection(msgSplit[1], msgSplit[2])
                                        if ret is True:
                                            print "connected to peer"
                    except (KeyboardInterrupt, SystemExit):
                        print "Got keyboard or system exit interrupt"
                        chatClient.disconnectClient()
                        break
        except (KeyboardInterrupt, SystemExit):
            #print "Got keyboard or system exit interrupt"
            chatClient.disconnectClient()
            return

if __name__ == "__main__":
    main(sys.argv[1:])
