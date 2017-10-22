
import binascii
import socket as syssock
import struct
import sys

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

def init(UDPportTx,UDPportRx):   # initialize your UDP socket here 
    global Tx
    global Rx
    global Txport
    global Rxport
    if UDPportRx == 0:
        UDPportRx = 27182
    if UDPportTx == 0:
        UDPportTx = 27182
    Txport = UDPportTx
    Rxport = UDPportRx
    Tx = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    Rx = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
     
    
class socket:
    
    def __init__(self):  # fill in your code here 
        return
    
    def bind(self,address):
        Tx.bind(address, Txport)
        Rx.bind(address, Rxport)
        return 

    def connect(self,address):  # fill in your code here 
        Tx.connect(address)
        Rx.connect(address)
        return 
    
    def listen(self,backlog):
        return

    def accept(self):
        (clientsocket, address) = (1,1)  # change this to your code 
        return (clientsocket,address)
    
    def close(self):   # fill in your code here 
        return 

    def send(self,buffer):
        bytessent = 0     # fill in your code here 
        return bytesent 

    def recv(self,nbytes):
        bytesreceived = 0     # fill in your code here
        return bytesreceived 


    

