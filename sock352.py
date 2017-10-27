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
    global Txport                 # transmitting port
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
        self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
        # self.sock.settimeout(0.2)
        self.client_addr = None
        self.serv_addr = None
        self.last_pkt_recvd = None
        self.isConnected = False
        self.udpPkt_hdr_data = struct.Struct('!BBBBHHLLQQLL')
        
        return
    
    def bind(self, address):    # server call, address is a 2-tuple of (IP address, port number)
        self.sock.bind((address[0], int(Rxport)))           # establish receiving port
        return

    def connect(self, address):     # client call, address is a 2-tuple of (IP address, port number)
        # Call Bind()
        self.serv_addr = (address[0], int(Rxport))
        self.sock.bind(('', int(Txport)))

        # Create SYN Header
        version = 0x1
        flags = SOCK352_SYN
        opt_ptr = 0
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
        self.sock.sendto(SYN_Packet, self.serv_addr)
        print("Connection request sent")

        # TODO Start Timeout

        # Receive SYN ACK (B)
        SYN_ACK = struct.unpack('!BBBBHHLLQQLL', self.sock.recvfrom(header_len)[0])
        print("Server response received")
        if SYN_ACK[1] == SOCK352_RESET:
            print("Connection Refused")
        elif SYN_ACK[1] == SOCK352_SYN | SOCK352_ACK:
            print("Connection Successful")
        else:
            print("Server response invalid")
        return 
    
    def listen(self, backlog):  # server call
        return

    def accept(self):  # server call
        # Receive the SYN Packet (A)
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        SYN_Packet, self.client_addr = self.sock.recvfrom(int(header_len))
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
                                                    source_port, dest_port, sequence_no, ack_no, window, payload_len)
        self.sock.sendto(connection_response, self.client_addr)  # send initial packet over the connection
        print("Server response sent")
        return self, self.client_addr
    
    def close(self):
        self.sock.close()
        return 

    def send(self, buffer): # TODO
        if len(buffer) < 64000: #smol send
            version = 0x1
            flags = 0
            opt_ptr = 0
            protocol = 0
            checksum = 0
            source_port = 0
            dest_port = 0
            ack_no = 0
            window = 0
            header_len = struct.calcsize('!BBBBHHLLQQLL')
            payload_len = len(buffer)
            sequence_no = self.last_pkt_recvd[8] + 1

            # packs header data into a string suitable to be sent over transmitting socket
            header = self.udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                                        source_port, dest_port, sequence_no, ack_no, window, payload_len)
            self.sock.sendto((header + buffer), self.serv_addr)  # send packet 
        else: #large send, divide into packets of 64k
            num_pkts = int(len(buffer) / 64000)
            
        bytessent = self.sock.send(buffer)     # fill in your code here
        return bytessent

    def recv(self, nbytes):  # TODO
        bytesreceived = self.sock.recv(nbytes)     # fill in your code here
        return bytesreceived
