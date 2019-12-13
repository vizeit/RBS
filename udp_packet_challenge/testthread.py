import SocketServer
from struct import *
import time
from Crypto.Hash import SHA256
import threading
import zlib

thlock = threading.RLock()

gpacketprevcrc = 0

with open("cat.jpg", "rb") as catfile:
    ctdata = catfile.read()

# define a subclass of UDPServer
class MyUDPHandler(SocketServer.DatagramRequestHandler):

    def setup(self):
    
        return SocketServer.DatagramRequestHandler.setup(self)

    def handle(self):
        
        self.packetproc()
        
        
    def finish(self):

        return SocketServer.DatagramRequestHandler.finish(self)
    
    def packetproc(self):
        #global gpacketprevcrc
        dt = self.request[0].strip()
        pid, pseq, xkey, nochsum = unpack('!IIHH', dt[:12])

        if hex(pid) == '0x42' and ((nochsum * 4) + 12 + 64) == len(dt):
            #extract 64 bytes digital signature
            DigSig = dt[(nochsum * 4) + 12:(nochsum * 4) + 12 + 64]

            #extract data packet to verify the signature
            spacket = dt[:-64]
            #calculate SHA256 hash of the received packet
            hashofpacket = SHA256.new(spacket).hexdigest()

            #extract Long value of digital signature
            dsg = int(DigSig.encode('hex'), 16)

            #open public key from the provide file
            with open("key.bin", "rb") as key_file:
                n_bytes = key_file.read(64)
                e_bytes = key_file.read(3)

            #extract Long value of mod and exp from the public key
            mod = int(n_bytes.encode('hex'), 16)
            exp = int(e_bytes.encode('hex'), 16)

            #remove padding and extract hash 
            hashfromSig = format('%x' % pow(dsg, exp, mod))[-64:]

            #Validate digital signature
            if hashofpacket != hashfromSig:
                with open("verification_failures.log", "a") as ver_log:
                    ver_log.write("%s\n%d\n%s\n%s\n\n" % (hex(pid), pseq, hashfromSig, hashofpacket))

            #create repeating XOR key 4 bytes long to extract original CRC DWORD
            repxkey = int ((bytes(dt[8:10]) + bytes(dt[8:10])).encode('hex'), 16)

            #extract number of checksums based on 'nochsum' from the packet
            crcs = unpack('!' + str(nochsum) + 'I', dt[12:(nochsum * 4) + 12])

def crcproc():
    while True:
        pass
            
if __name__ == "__main__":
    server_IP       = "127.0.0.1"
    server_port     = 1337
    serverAddress   = (server_IP, server_port)

    t = threading.Thread(target=crcproc,name='crcproc')
    t.start()

    serverUDP = SocketServer.ThreadingUDPServer(serverAddress, MyUDPHandler)
    serverUDP.serve_forever()