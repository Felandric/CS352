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


def init(udp_port1, udp_port2):   # initialize your UDP socket here
    global Txport
    global Rxport
    if udp_port2 == 0:
        udp_port2 = 27182
    if udp_port1 == 0:
        udp_port1 = 27182
    Txport = udp_port1
    Rxport = udp_port2
     
    
class socket:
    
    def __init__(self):
        self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
        return
    
    def bind(self, address):  # server, address = (IP address, port number)
        print(address[0], Rxport)
        self.sock.bind((address[0], int(Rxport)))
        return

    def connect(self, address):  # client, address = (IP address, port number)
        self.sock.bind(('', int(Txport)))
        
        sock352PktHdrData = '!BBBBHHLLQQLL'
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
        sequence_no = random.randint(1, sys.maxint)  # REEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
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
