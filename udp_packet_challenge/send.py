import pickle
import socket
import time
import random
from struct import *
from locked_dict import locked_dict
from Crypto.Hash import SHA256

random.seed(0x1337)


with open('payload_dump.bin') as f:
    payloads = pickle.load(f)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
count = 0

for payload in payloads:
    count += 1


    sock.sendto(payload, ('127.0.0.1', 1337))
    time.sleep(0.001)

"""     if count == 2:
        break """
print count
sock.close()

