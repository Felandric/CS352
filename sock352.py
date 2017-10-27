# -*- coding: utf-8 -*-
import binascii
import socket as syssock
import struct
import sys
import random
import time

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
        self.amServer = None

        return

    def bind(self, address):    # server call, address is a 2-tuple of (IP address, port number)
        self.sock.bind((address[0], int(Rxport)))           # establish receiving port
        return

    def connect(self, address):     # client call, address is a 2-tuple of (IP address, port number)
        self.amServer = False

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
        # print("Connection request sent")

        # TODO Start Timeout

        # Receive SYN ACK (B)
        self.last_pkt_recvd = struct.unpack('!BBBBHHLLQQLL', self.sock.recvfrom(header_len)[0])
        # print("Server response received")
        if self.last_pkt_recvd [1] == SOCK352_RESET:
            print("Connection Refused")
        elif self.last_pkt_recvd [1] == SOCK352_SYN | SOCK352_ACK:
            print("Connection Successful")
        else:
            print("Server response invalid")
        return

    def listen(self, backlog):  # server call
        return

    def accept(self):  # server call
        self.amServer = True

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
        # print("Server response sent")
        return self, self.client_addr

    def close(self):
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
        if self.amServer == True:
            self.sock.sendto(connection_response, self.client_addr)
        elif self.amServer == False:
            self.sock.sendto(connection_response, self.serv_addr)
        # print("Termination request sent")

        #TODO start timeout

        # Receive FIN ACK
        FIN_ACK = struct.unpack('!BBBBHHLLQQLL', self.sock.recvfrom(header_len)[0])
        if FIN_ACK[1] == SOCK352_FIN:
            flags |= SOCK352_ACK
            self.sock.close()
            print("Connection terminated")
        else:
            print("Server response invalid")
        return

    def send(self, buffer): # TODO implement fragmentation handling
        version = 0x1
        flags = 0
        opt_ptr = 0
        protocol = 0
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        checksum = 0
        source_port = 0
        dest_port = 0
        sequence_no = self.last_pkt_recvd[8] + 1
        ack_no = 0
        window = 0
        payload_len = len(buffer)

        # packs header data into a string suitable to be sent over transmitting socket
        header = self.udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                           source_port, dest_port, sequence_no, ack_no, window, payload_len)

        if self.amServer == True:
            bytessent = self.sock.sendto((header + buffer), self.client_addr)
        elif self.amServer == False:
            bytessent = self.sock.sendto((header + buffer), self.serv_addr)
        print("%i byte payload sent. Awaiting ACK..." % len(buffer))

        # receive ACK
        ACK = struct.unpack('!BBBBHHLLQQLL', self.sock.recvfrom(header_len)[0])
        if (ACK[1] == SOCK352_ACK) & (ACK[9] == sequence_no):
            print("ACK received")
        else:
            print("Response invalid")

        #TODO implement timers

        return bytessent

    def recv(self, nbytes):  # TODO implement fragmentation handling
        header_len = struct.calcsize('!BBBBHHLLQQLL')

        # receive packet
        packet = self.sock.recvfrom(64000 + header_len)[0]
        self.last_pkt_recvd = struct.unpack('!BBBBHHLLQQLL', packet[:header_len]) # read header
        payload = packet[header_len:header_len+self.last_pkt_recvd[11]]  # extract payload

        # send ACK
        version = 0x1
        flags = SOCK352_ACK
        opt_ptr = 0
        protocol = 0
        header_len = struct.calcsize('!BBBBHHLLQQLL')
        checksum = 0
        source_port = 0
        dest_port = 0
        sequence_no = self.last_pkt_recvd[8] + 1
        ack_no = self.last_pkt_recvd[8]
        window = 0
        payload_len = header_len

        ACK = self.udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                           source_port, dest_port, sequence_no, ack_no, window, payload_len)

        if self.amServer == True:
            ACK = self.sock.sendto(ACK, self.client_addr)
        elif self.amServer == False:
            ACK = self.sock.sendto(ACK, self.serv_addr)
        # print("%i byte payload received. Sending ACK..." % nbytes)

        # TODO implement timers
        return payload
