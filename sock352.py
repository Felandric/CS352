# -*- coding: utf-8 -*-
import binascii
import socket as syssock
import struct
import sys
import random

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

SOCK352_SYN = 0x01
SOCK352_FIN = 0x02
SOCK352_ACK = 0x04
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0xA0


def init(udpportTx, udpportRx):
    global Txport                 # transmission port
    global Rxport                 # receiving port

    # when arguments are set to 0, use default port number
    if udpportRx == 0:
        udpportRx = 27182
    if udpportTx == 0:
        udpportTx = 27182

    Txport = udpportTx
    Rxport = udpportRx

class socket:

    def __init__(self):
        self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM) # defines underlying UDP socket for the protocol
        return
    
    def bind(self, address):  # server call, address is a 2-tuple of (IP address, port number)
        # print(address[0], Rxport)
        self.sock.bind((address[0], int(Rxport)))   # establish receiving port
        return

    def connect(self, address):  # client call, address is a 2-tuple of (IP address, port number)
        self.sock.bind(('', int(Txport)))
        sock352PktHdrData = '!BBBBHHLLQQLL' # defines format of packet header data
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        version = 0x1
        flags = SOCK352_SYN
        opt_ptr = 0
        protocol = 0 
        checksum = 0 
        source_port = 0
        dest_port = 0
        ack_no = 0
        window = 0
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        payload_len = 0
        sequence_no = random.randint(1, sys.maxint)
        header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len)
        
        self.sock.sendto(header, (address[0], int(Rxport)))
        return 
    
    def listen(self, backlog):  # server should receive info about client address&port, then +
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        init_packet, self.clientaddress = self.sock.recvfrom(header_len)
        packet_header = struct.unpack('!BBBBHHLLQQLL', init_packet)
        return

    def accept(self):  # server
        print(self.clientaddress)
        (clientsocket, address) = (self, self.clientaddress)  # change this to your code
        return (clientsocket, address)
    
    def close(self):   # fill in your code here
        self.sock.close()
        return 

    def send(self, buffer): # client
        bytessent = self.sock.send(buffer)     # fill in your code here 
        return bytessent

    def recv(self, nbytes):  # server
        bytesreceived = self.sock.recv(nbytes)     # fill in your code here
        return bytesreceived
