# -*- coding: utf-8 -*-
import binascii
import socket as syssock
import struct
import sys
import random

import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

buffer = bytearray(30)
buffer = bytearray('ABCDEFGHIJKLMNOPQRSTUVWXYZ')

string = "12345"
for c in string:
    buffer.append(c)

print(len(buffer))
print(buffer)
buffer[0:10] = []
print(buffer)
print(len(buffer))