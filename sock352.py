# -*- coding: utf-8 -*-
import binascii
import socket as syssock
import struct
import sys
import random

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

SOCK352_SYN     = 0x01
SOCK352_FIN     = 0x02
SOCK352_ACK     = 0x04
SOCK352_RESET   = 0x08
SOCK352_HAS_OPT = 0xA0

def init(UDPportTx,UDPportRx):   # initialize your UDP socket here 
    global Txport
    global Rxport
    if UDPportRx == 0:
        UDPportRx = 27182
    if UDPportTx == 0:
        UDPportTx = 27182
    Txport = UDPportTx
    Rxport = UDPportRx
     
    
class socket:
    
    def __init__(self):  # fill in your code here 
        self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
        return
    
    def bind(self,address): #server
        print(address[0], Rxport)
        self.sock.bind((address[0], int(Rxport)))
        return 

    def connect(self,address):  #client # fill in your code here 
        print(address[0], Txport)
        self.sock.bind((address[0], int(Txport)))
        
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
        sequence_no = random.randint(1, sys.maxint)
        header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len)
        
        self.sock.send(header)
        return 
    
    def listen(self,backlog): #server should receive info about client address&port, then 
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        self.sock.recv(header_len)
        return

    def accept(self): #server 
        (clientsocket, address) = self.sock.accept()  # change this to your code 
        return (clientsocket, address)
    
    def close(self):   # fill in your code here
        self.sock.close()
        return 

    def send(self,buffer): #client
        bytessent = self.sock.send(buffer)     # fill in your code here 
        return bytesent 

    def recv(self,nbytes): #server
        bytesreceived = self.sock.recv(nbytes)     # fill in your code here
        return bytesreceived 


    

