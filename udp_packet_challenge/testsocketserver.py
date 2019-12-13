import socket
import threading
import SocketServer
from multiprocessing import Process, Queue
import sys
from struct import *
from Crypto.Hash import SHA256
import zlib
import argparse
import json
import time

class UDPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        data = self.request[0]
        msgq.put(data)

def crcProc(npacketid, crctoprocess, prevcrcseq, ctdata):
    if bool(crctoprocess)==True:
        #print len(crctoprocess)
        #extract last processed seq for a package
        lpid = npacketid
        lastpseq = prevcrcseq[lpid]

        lsdictkeyprev = lpid + str(lastpseq)
        lsdictkeycurr = lpid + str(lastpseq+1)

        #print "%s %s %d" % (lsdictkeyprev, lsdictkeycurr, len(crctoprocess))

        while(lsdictkeyprev in crctoprocess and lsdictkeycurr in crctoprocess):
            #print "%s %s" % (lsdictkeyprev, lsdictkeycurr)
            lcrcprev = crctoprocess[lsdictkeyprev][1]
            lcrccurr = crctoprocess[lsdictkeycurr][1]
            lseqcurr = crctoprocess[lsdictkeycurr][0]

            lcalcrc = (zlib.crc32(ctdata, lcrcprev) & 0xFFFFFFFF)

            if lcalcrc != lcrccurr:
                lcrccurr = lcalcrc
                with open("checksum_failures.log", "a") as chk_log:
                    chk_log.write("%s\n%d\n%d\n%x\n%x\n\n" % (lpid, lseqcurr, (lastpseq + 1), lcrccurr, lcalcrc))
                
            del crctoprocess[lsdictkeyprev]
            crctoprocess[lsdictkeycurr][1] = lcrccurr
            lastpseq = lastpseq+1
            prevcrcseq[lpid] = lastpseq
            lsdictkeyprev = lpid + str(lastpseq)
            lsdictkeycurr = lpid + str(lastpseq+1)                   



def processpacket(msgqueue):
    #initial CRC to track the last processed CRC for a packet
    prevcrcseq = dict()
    prevcrcseq['0x42'] = 0
    #empty dict of CRCs to be processed format: packetidseqno:crc
    crctoprocess = dict()
    starttime = time.time()
    with open("cat.jpg", "rb") as catfile:
        ctdata = catfile.read()
    while True:
        if not msgqueue.empty():
            dt = msgqueue.get()
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

                #add them to 'crctoprocess' dictionary
                lcount = 0
                for c in crcs:
                    dictkey = hex(pid) + str(pseq+lcount)
                    dictvalue = [pseq, (c ^ repxkey)]
                    crctoprocess[dictkey] = dictvalue
                    lcount = lcount + 1
                crcProc(hex(pid),crctoprocess, prevcrcseq, ctdata)
        elif len(crctoprocess) == 1:
            totaltime = time.time() - starttime
            print "Total time to process the packets %d" % totaltime



if __name__ == "__main__":
    
    try:
        print "Starting server, press Ctrl+c to exit"
        msgq = Queue()
        stopproc = False
        p = Process(target=processpacket, args=(msgq,))
        p.start()
        HOST, PORT = "127.0.0.1", 1337

        udpserver = SocketServer.UDPServer((HOST, PORT), UDPRequestHandler)
        udpserver.serve_forever()
    except KeyboardInterrupt:
        p.terminate()
        sys.exit(0)

    
