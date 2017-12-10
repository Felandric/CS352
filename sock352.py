# -*- coding: utf-8 -*-
import binascii
import socket as syssock
import struct
import sys
import random
import errno

import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# the public and private keychains in hex format
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format
global publicKeys
global privateKeys

# the encryption flag set to 0xEC
global ENCRYPT
ENCRYPT = 236

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}

SOCK352_SYN = 0x01
SOCK352_FIN = 0x02
SOCK352_ACK = 0x04
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0xA0

SOCK352_BUFFER_FULL = 0xFF

MTU = 64000
header_len = struct.calcsize('!BBBBHHLLQQLL')

def init(udpportTx, udpportRx):
    global Txport                 # transmitting port
    global Rxport                 # receiving port

    # when arguments are set to 0, use default port number
    if udpportRx == 0:
        udpportRx = 27182
    if udpportTx == 0:
        udpportTx = 27182

    Txport = udpportTx
    Rxport = udpportRx


def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex
    global publicKeys
    global privateKeys

    if (filename):
        try:
            keyfile_fd = open(filename, "r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if (len(words) >= 4) and (words[0].find("#") == -1):
                    host = words[1]

                    # added this to correct resolving of localhost
                    if host == "127.0.0.1":
                        host = "localhost"

                    port = words[2]
                    keyInHex = words[3]
                    if words[0] == "private":
                        privateKeysHex[(host, port)] = keyInHex
                        privateKeys[(host, port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif words[0] == "public":
                        publicKeysHex[(host, port)] = keyInHex
                        publicKeys[(host, port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception, e:
            print ("error: opening keychain file: %s %s" % (filename, repr(e)))
    else:
        print ("error: No filename presented")

    return publicKeys, privateKeys


class socket:

    def __init__(self):
        self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
        self.client_addr = None
        self.serv_addr = None
        self.last_pkt_recvd = None
        self.isConnected = False
        self.udpPkt_hdr_data = struct.Struct('!BBBBHHLLQQLL')
        self.amServer = None

        #PART 2
        self.isEncrypted = False
        self.box = None
        self.nonce_flag = 0

        #PART 3
        self.window_size = 32000
        self.buffer = bytearray(32000)
        self.buffer_index = 0
        return

    def bind(self, address):    # server call, address is a 2-tuple of (IP address, port number)
        self.sock.bind((address[0], int(Rxport)))           # establish receiving port
        return

    def connect(self, *args):     # client call, address is a 2-tuple of (IP address, port number)
        self.amServer = False
        self.sock.settimeout(0.2)
        address = args[0]

        # Call Bind()
        self.serv_addr = (address[0], int(Txport))  # changed from Rx
        self.sock.bind(('', int(Rxport)))  # changed from Tx

        if len(args) >= 2:
            if args[1] == ENCRYPT:
                self.isEncrypted = True
                client_private_key = privateKeys[('*', '*')]
                server_public_key = publicKeys[(self.serv_addr[0], str(self.serv_addr[1]))]
                self.box = Box(client_private_key, server_public_key)
                opt_ptr = 0b1
        else:
            opt_ptr = 0b0

        # Create SYN Header
        version = 0x1
        flags = SOCK352_SYN
        #opt_ptr = 0
        protocol = 0
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        checksum = 0
        source_port = 0
        dest_port = 0
        sequence_no = random.randint(1, sys.maxint)
        ack_no = 0
        window = 0
        payload_len = 0

        # Send SYN Packet (A)
        SYN_Packet = self.udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum, source_port,
                                               dest_port, sequence_no, ack_no, window, payload_len)
        
        # resend request if timeout occurs while waiting for ack
        acked = False
        while not acked:
            try:
                self.sock.sendto(SYN_Packet, self.serv_addr)
                print("Connection request sent")
                ack = self.sock.recvfrom(header_len)[0]
                acked = True
            except syssock.timeout:
                #print("Timeout occurred. Resending...")
                pass
        
        # Receive SYN ACK (B)
        self.last_pkt_recvd = struct.unpack('!BBBBHHLLQQLL', ack)
        #print("Server response received")
        if self.last_pkt_recvd [1] == SOCK352_RESET:
            print("Connection Refused")
            pass
        elif self.last_pkt_recvd [1] == SOCK352_SYN | SOCK352_ACK:
            print("Connection Successful")
            self.window_size = 32000 # PART 3
            pass
        else:
            #print("Server response invalid")
            pass
        return

    def listen(self, backlog):  # server call
        return

    def accept(self, *args):  # server call
        self.amServer = True
        self.sock.settimeout(None)

        # Receive the SYN Packet (A)
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        
        SYN_Packet, self.client_addr = self.sock.recvfrom(int(header_len))
        if self.client_addr[0] == '127.0.0.1':
            self.client_addr = ('localhost', self.client_addr[1])

        if len(args) > 0:
            if args[0] == ENCRYPT:
                self.isEncrypted = True
                server_private_key = privateKeys[('*', '*')]
                client_public_key = publicKeys[(self.client_addr[0], str(self.client_addr[1]))]
                self.box = Box(server_private_key, client_public_key)
                opt_ptr = 0b1
        else:
            opt_ptr = 0b0

        self.last_pkt_recvd = struct.unpack('!BBBBHHLLQQLL', SYN_Packet)
        print("Connection request received")

        # Send SYN ACK (B)
        version = 0x1
        flags = 0
        if self.isConnected:
            flags = SOCK352_RESET
        else:
            flags = SOCK352_SYN | SOCK352_ACK
            self.isConnected = True
        #opt_ptr = 0
        protocol = 0
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        checksum = 0
        source_port = 0
        dest_port = 0
        sequence_no = self.last_pkt_recvd[8] + 1
        ack_no = 0
        window = 32000
        payload_len = 0
        connection_response = self.udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                                    source_port, dest_port, sequence_no, ack_no, window, payload_len)
        self.sock.sendto(connection_response, self.client_addr)  # send initial packet over the connection
        print("Server response sent")
        return self, self.client_addr

    def close(self):
        self.sock.settimeout(0.2)
        # Send FIN Packet
        version = 0x1
        flags = SOCK352_FIN
        opt_ptr = 0
        protocol = 0
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        checksum = 0
        source_port = 0
        dest_port = 0
        sequence_no = self.last_pkt_recvd[8] + 1
        ack_no = 0
        window = 0
        payload_len = 0
        connection_response = self.udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                                        source_port, dest_port, sequence_no, ack_no, window,
                                                        payload_len)
                                                        
        ack = None
        acked = False
        while not acked:
            try:
                if self.amServer == True:
                    self.sock.sendto(connection_response, self.client_addr)
                elif self.amServer == False:
                    self.sock.sendto(connection_response, self.serv_addr)
                #print("Termination request sent")
                ack = self.sock.recvfrom(header_len)[0]
                acked = True
            except syssock.timeout:
                #print("Timeout occurred. Resending...")
                pass                                           
            except syssock.error as error:
                if error.errno == 10054:
                    break
                else:
                    raise
       
        # Receive FIN ACK
        if (ack != None):
            FIN_ACK = struct.unpack('!BBBBHHLLQQLL', ack)
            if FIN_ACK[1] == SOCK352_FIN:
                flags |= SOCK352_ACK
                self.sock.close()
                #print("Connection terminated")
            else:
                #print("Server response invalid")
                pass
        else:
            self.sock.close()
        return

    #this 🅱oesn't 🅱ork
    def send(self, buffer):
        if len(buffer) == 0:
            return 0

        # send server request for window size
        update = self.udpPkt_hdr_data.pack(0x1, 0, 0, 0, header_len, 0, 0, 0, 0, 0, self.window_size, 0)
        self.sock.sendto(update, self.serv_addr)
        #print("Window size request sent...")


        #receive update on current window size
        update = None
        update = self.sock.recvfrom(header_len)[0]
        self.last_pkt_recvd = struct.unpack('!BBBBHHLLQQLL', update)
        self.window_size = self.last_pkt_recvd[10]
        #print("Response received. Window Size: %i B" % (self.window_size))

        # send update on whether or not send is possible
        if self.window_size < len(buffer):
            update = self.udpPkt_hdr_data.pack(0x1, SOCK352_BUFFER_FULL, 0, 0, header_len, 0, 0, 0, 0, 0, self.window_size, 0)
            self.sock.sendto(update, self.serv_addr)
            print("Send size: %i B. Window too small. Sending smaller packet..." %(len(buffer)))
            return socket.send(self, buffer[0:self.window_size]) # TODO
        else:
            update = self.udpPkt_hdr_data.pack(0x1, SOCK352_ACK, 0, 0, header_len, 0, 0, 0, 0, 0, self.window_size, 0)
            self.sock.sendto(update, self.serv_addr)

        print("Send size: %i B. Window is good. Sending packet..." % (len(buffer))),
        #buffer = buffer[:4000]  # added to solve fragmentation problem

        #PART 2 CODE
        if self.isEncrypted == True:
            if self.nonce_flag == 0:
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                buffer = self.box.encrypt(buffer, nonce)
                self.nonce_flag = 1
            else:
                buffer = self.box.encrypt(buffer)
            opt_ptr = 0b1
        else:
            opt_ptr = 0b0

        sequence_no = self.last_pkt_recvd[8] + 1
        ack_no = 0
        window = 0
        payload_len = len(buffer)
        bytessent = 0

        # packs header data into a string suitable to be sent over transmitting socket
        header = self.udpPkt_hdr_data.pack(0x1, 0, opt_ptr, 0, header_len, 0, 0, 0, sequence_no, ack_no, window, payload_len)

        # resend packets if timeout occurs while waiting for ack
        acked = False
        while not acked:
            try:
                bytessent = self.sock.sendto((header + buffer), self.serv_addr)
                #print("%i byte payload sent. SEQNO = %d. Awaiting ACK..." % (len(buffer), sequence_no))
                ack = self.sock.recvfrom(header_len)[0]
                acked = True
            except syssock.timeout:
                #print("Timeout occurred. Resending...")
                pass

        # receive ACK
        self.last_pkt_recvd = struct.unpack('!BBBBHHLLQQLL', ack)
        if (self.last_pkt_recvd[1] == SOCK352_ACK) and (self.last_pkt_recvd[9] == sequence_no):
            print("ACK received")
            self.window_size = self.last_pkt_recvd[10] # PART 3, update window size
            #print("%i byte payload sent. Buffer occupancy: %i" % (bytessent, 32000-self.window_size))
            pass
        else:
            #print("Response invalid")
            pass
        bytessent = bytessent - header_len

        if self.isEncrypted == True:
            bytessent -= 40

        return bytessent

    def recv(self, nbytes):
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        print("%i B requested." %(nbytes)),
        
        # receive client request for window size
        update = self.sock.recvfrom(header_len)[0]
        self.last_pkt_recvd = struct.unpack('!BBBBHHLLQQLL', update)
        if (self.last_pkt_recvd[1] != SOCK352_FIN):
        
            #print("Window size request received")
            # respond with current window size
            update = self.udpPkt_hdr_data.pack(0x1, 0, 0, 0, header_len, 0, 0, 0, 0, 0, self.window_size, 0)
            self.sock.sendto(update, self.client_addr)
            #print("Response sent. Window Size: %i B" % (self.window_size))

            # await sender response on whether they can send, or to read from buffer as is
            update = self.sock.recvfrom(header_len)[0]
            self.last_pkt_recvd = struct.unpack('!BBBBHHLLQQLL', update)
            if self.last_pkt_recvd[1] == SOCK352_BUFFER_FULL:
                bytes_read = self.buffer[0:nbytes]
                self.window_size -= nbytes
                print("Window size: %i B. Send too large. Reading from buffer..." %(self.window_size)),
                return bytes_read

            # PART 2 CODE
            if self.isEncrypted == True:
                nbytes += 40

            header_len = struct.calcsize('!BBBBHHLLQQLL')
            # receive packet
            
            packet = self.sock.recvfrom(8192 + header_len)[0]        # PART 3, MAX packet size sent by client
            
            self.last_pkt_recvd = struct.unpack('!BBBBHHLLQQLL', packet[:header_len]) # read header
            payload = packet[header_len:header_len+self.last_pkt_recvd[11]]  # extract payload

            if self.isEncrypted == True:
                payload = self.box.decrypt(payload)
                opt_ptr = 0b1
                nbytes -=40
            else:
                opt_ptr = 0b0

            #PART 3
            #insert data into buffer and increment buffer index
            self.buffer[self.buffer_index:self.buffer_index + self.last_pkt_recvd[11]] = payload
            self.buffer_index += self.last_pkt_recvd[11]
            #print("Buffer occupancy: %i, payload length: %i, read size: %i" % (32000-self.window_size, len(payload), nbytes))
            self.window_size = self.window_size - len(payload) + nbytes
            # send ACK
            # print("%i byte payload received. SEQNO = %d. Sending ACK..." % (payload_len, ack_no))
            sequence_no = self.last_pkt_recvd[8] + 1
            ack_no = self.last_pkt_recvd[8]
            window =  self.window_size
            payload_len = header_len
            ACK = self.udpPkt_hdr_data.pack(0x1, SOCK352_ACK, opt_ptr, 0, header_len, 0, 0, 0, sequence_no, ack_no, window, payload_len)
            self.sock.sendto(ACK, self.client_addr)
        
        # PART 3
        bytes_read = self.buffer[0:nbytes]
        self.buffer[0:nbytes] = []
        self.buffer_index -= nbytes
        print("%i B read" %(nbytes))
        return str(bytes_read)
