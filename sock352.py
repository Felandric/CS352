
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
     
    
class socket:
    
    def __init__(self):  # fill in your code here 
        self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
        return
    
    def bind(self,address): #server
        print(address[0], Rxport)
        self.sock.bind((address[0], int(Rxport)))
        return 

    def connect(self,address):  #client # fill in your code here 

        self.sock.connect((address[0], Txport))
        return 
    
    def listen(self,backlog): #server
        self.sock.listen(backlog)
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


    

