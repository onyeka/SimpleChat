from ConfigParser import SafeConfigParser
import socket
import threading
import select
import CryptoLib
import sys
import genPrime, Peer
import random


shutdown = False

class ChatClient(object):
    """ Usage: prints out how to use the chat client
    """
    USAGE = 'usage: \tpython ChatClient.py -sip <server ip> -sp <server port>'
    '\t-h: prints this help message and exit'
    CHAT_USAGE = 'valid messages: \t list' \
                 '\t send USER MESSAGE' \
                 '\t bye'
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
        self.DBG = True

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
    def peer_communication(self, tLock, peer_name, peer_msg):
        #with tLock:
            try:
                for address in self.peers:
                    if self.peers[address].get_peer_name() == peer_name:
                        peer_address = self.peers[address].get_address()
                        self.send_message(peer_msg, peer_address[0], peer_address[1])

                print "====== authenticate PEER first, MSG: ", peer_msg
                ret = False

                # send server the peer name of the client we want to chat with
                msg = "CONNECT_PEER:" + peer_name

                # step 1: Request Server for the tickets
                msg = CryptoLib.encyptUsingSymmetricKey(self.sessionKey, self.sessionID, msg)
                if not self.send_message(msg, self.serverAddr, self.port):
                    return ret

                # Step 2: receive the combined ticket from the server and split it into two parts
                combined_ticket = self.receive_response()
                if combined_ticket is None:
                    print "failed to get ticket from server"
                    return

                print "got combined ticket", combined_ticket

                combined_ticket = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID, combined_ticket)
                print "\n decrypted combined ticket", combined_ticket
                combined_ticket = combined_ticket.split("###")
                peer_key = combined_ticket[0]
                peer_iv = combined_ticket[1]
                peer_address = (combined_ticket[2], int(combined_ticket[3]))
                print "peer_address: ", peer_address
                peer_ticket = combined_ticket[4]

                print "=========== got all parts requesting client connection"
                print "peer ticked:", peer_ticket

                # create peer object
                peer = Peer.Peer(peer_name, peer_address)

                # Step 3: send peer ticket to peer and wait for response. Note:
                # the ticket is already encrypted so peer should know how to decrypt it
                if not self.send_message(peer_ticket, peer_address[0], peer_address[1]):
                    return ret

                response = self.receive_response()
                if response is None:
                    print "Error!!! Didn't receive contribution from peer: ", peer_name
                    return ret

                # Step 4: handle peer response and begin authentication
                response = CryptoLib.decryptUsingSymetricKey(peer_key, peer_iv, response)
                ##print "========recieved peer contribution response:", response
                response = response.split(":")
                if response[0] == "PEER_CONNECT_RESPONSE":
                    peer_contribution = response[1]

                    # Step 5: Generate shared key and DH contribution
                    a = CryptoLib.generateRandomKey(32).encode('hex')
                    client_contribution = pow(self.peerGenerator, int(a, 16), self.peerPrime)

                    peer_session_key = pow(int(peer_contribution), int(a, 16), self.peerPrime)
                    peer_session_id = CryptoLib.generateRandomKey(8).encode("hex")

                    msg = "PEER_CONTRIBUTION:" + str(client_contribution) + ":" + peer_session_id
                    #print "++++++++ sending client contribution: ", msg
                    msg = CryptoLib.encyptUsingSymmetricKey(peer_key, peer_iv, msg)

                    if not self.send_message(msg, peer_address[0], peer_address[1]):
                        return ret

                    # Step 6: Receive peer's challenge and IV
                    response = self.receive_response()
                    if response is None:
                        print "Error!!! Didn't receive challenge from peer: ", peer_name
                        return ret

                    #print "+++++++++ key: %s, iv: %s" % (str(peer_session_key),peer_session_id)
                    response = CryptoLib.decryptUsingSymetricKey(str(peer_session_key), peer_session_id, response)
                    response = response.split(":")
                    if response[0] == "PEER_CHALLENGE":
                        challenge = int(response[1])
                        challenge += 1
                        msg = "PEER_CHALLENGE_RESPONSE:" + str(challenge)
                        msg = CryptoLib.encyptUsingSymmetricKey(str(peer_session_key),
                                                                peer_session_id, msg)

                        if not self.send_message(msg, peer_address[0], peer_address[1]):
                            return ret

                        # Step 7: Receive peer's acknowledgement and save peer info
                        response = self.receive_response()
                        if response is None:
                            print "Error!!! Didn't receive acknowledgement from peer: ", peer_name
                            return ret
                        response = CryptoLib.decryptUsingSymetricKey(str(peer_session_key), peer_session_id, response)
                        response = response.split(":")
                        if response[0] == "PEER_ACKNOWLEDGE":
                            peer.set_peer_session_key(str(peer_session_key))
                            peer.set_initialization_vector(peer_session_id)
                            self.peers[peer_address] = peer
                            print "=======recieved acknowledgement sending message across, MSG: ", peer_msg
                            peer_msg = CryptoLib.encyptUsingSymmetricKey(str(peer_session_key), peer_session_id, peer_msg)
                            if not self.send_message(peer_msg, peer_address[0], peer_address[1]):
                                return ret
                            ret = True
                    else:
                        print "Error!!! didn't receive challenge response from peer"
                        return ret
            finally:
                l = "hello"
                #tLock.release()

    def receive_peer_messages(self, tLock):
        """
        Reads messages from socket
        :return: data read
        """
        #with tLock:
        try:

            msg, addr = self.sock.recvfrom(ChatClient.MSG_LEN)
            if self.peers.has_key(addr):
                peer = self.peers.get(addr)
                msg = CryptoLib.decryptUsingSymetricKey(peer.get_peer_session_key(),
                                                             peer.get_initialization_vector(), msg)
                print "%s Says:\t %s" % (peer.get_peer_name(), msg)
            elif addr == (self.serverAddr, self.port):
                    response = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID, msg)
                    response = response.split(":")
                    if response[0] == "DISCONNECTED":
                        print " Server Disconnected us... Good bye!"
                        sys.exit(0)
            else:
                print "TICKET: ", msg
                # msg = msg.split(",")
                #try:
                    # verified = CryptoLib.verifyMessage(msg[0], msg[1], self.serverPublicKey)
                    # print "=======signature verification:", verified
                response = CryptoLib.decryptUsingSymetricKey(self.sessionKey, self.sessionID, msg)

                #except Exception, e:
                    #print " Error received: ", e

                response = response.split("###")
                print "=======token after decryption:", response
                if response[0] == "PEER_CONNECT_REQUEST":
                        ret = False
                        temp_key = response[1]
                        temp_iv = response[2]
                        peer_address = (response[3], int(response[4]))
                        peer_name = response[5]

                        # Step 1: Generate DH contribution
                        b = CryptoLib.generateRandomKey(32).encode('hex')
                        my_contribution = pow(self.peerGenerator, int(b, 16), self.peerPrime)
                        msg = "PEER_CONNECT_RESPONSE:" + str(my_contribution)
                        print "========sending peer contribution: ", msg
                        msg = CryptoLib.encyptUsingSymmetricKey(temp_key, temp_iv, msg)
                        if not self.send_message(msg, peer_address[0], peer_address[1]):
                            return ret
                        # Step 2: Receive connecting client's DH contribution
                        response = self.receive_response()
                        if response is None:
                            print "Error!!! Didn't receive contribution from peer "
                            return ret

                        response = CryptoLib.decryptUsingSymetricKey(temp_key, temp_iv, response)
                        response = response.split(":")
                        if response[0] == "PEER_CONTRIBUTION":
                            peer_contribution = response[1]
                            peer_iv = response[2]
                            print "======= response: ", response
                            peer_session_key = pow(int(peer_contribution), int(b, 16), self.peerPrime)
                            print "=======  session key: %s, iv: %s" % (str(peer_session_key), peer_iv)
                            challenge = random.randrange(1,1000)
                            msg = "PEER_CHALLENGE:" + str(challenge)
                            msg = CryptoLib.encyptUsingSymmetricKey(str(peer_session_key), peer_iv, msg)
                            print "====sending peer challenge: ", msg
                            if not self.send_message(msg, peer_address[0], peer_address[1]):
                                return ret

                            response = self.receive_response()
                            if response is None:
                                print "Error!!! Didn't receive a response for challenge from peer: ", peer_name
                                return ret
                            response = CryptoLib.decryptUsingSymetricKey(str(peer_session_key), peer_iv, response)
                            response = response.split(":")
                            print "VVVVVV Response: ", response
                            if not response[0] == "PEER_CHALLENGE_RESPONSE" and int(response[1]) == challenge + 1:
                                return ret
                            print "====response is correct sending acknowledgement"
                            msg = "PEER_ACKNOWLEDGE:"
                            msg = CryptoLib.encyptUsingSymmetricKey(str(peer_session_key), peer_iv, msg)
                            if not self.send_message(msg, peer_address[0], peer_address[1]):
                                return ret
                            client_msg = self.receive_response()
                            print "===== peer message: ", client_msg
                            if client_msg is not None:
                                client_msg = CryptoLib.decryptUsingSymetricKey(str(peer_session_key),
                                                                               peer_iv, client_msg)
                            #print "=====> message from %s : %s" %(peer_address, client_msg)

                            # create peer object
                            peer = Peer.Peer(peer_name, peer_address)
                            peer.set_peer_session_key(peer_session_key)
                            peer.set_initialization_vector(peer_iv)
                            self.peers[peer_address] = peer
                            print "%s Says:\t %s" % (peer.get_peer_name(), client_msg)
                else:
                    print "Wrong msg type error"

                #except Exception, e:
                    #print " Error received: ", e

        except socket.timeout, e:
            #print "Thread Error: ", e
            msg = None
            #finally:
                #print "THREADING FINISHED!!!"
                #tLock.release()

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
    tLock = threading.Lock()
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
                                #s = chatClient.getSocket()
                                chatClient.receive_peer_messages(tLock)
                                #rT = threading.Thread(target=chatClient.receive_peer_messages(tLock), args=(tLock, s))
                                #print "======= got socket message, thead"
                                #rT.start()
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
                                        print "======= got send message from client: ", msgSplit
                                        chatClient.peer_communication(tLock, msgSplit[1], msgSplit[2])
                                        #cT = threading.Thread(target=chatClient.peer_communication(tLock, msgSplit[1], msgSplit[2]))
                                        #cT.start()
                                else:
                                    print "Invalid message: ", msg
                                    print chatClient.CHAT_USAGE

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
    tLock = threading.Lock()
