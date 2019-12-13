import socket
from struct import *
from Crypto.Hash import SHA256
import zlib
import threading
import argparse
import json
import sys
import time
import SocketServer
from multiprocessing import Process, Queue
import os
import signal

parser = argparse.ArgumentParser(description='Start UDP Server')


parser.add_argument('--keys',help='Public key per packet',type=json.loads)
parser.add_argument('--binaries',help='Source binary per packet',type=json.loads)
parser.add_argument('-d',help='Delay (in seconds) to write to log',type=int)
parser.add_argument('-p',help='Port to receive packets',type=int)


if __name__ == "__main__":

    args = parser.parse_args()

    #extract command line argument
    if args.keys != None and args.binaries != None and args.d >= 0 and args.p > 0:
        dtkeys = dict(args.keys)
        dtbinaries = dict(args.binaries)
        nlogdelay = args.d
        nport = args.p
    else:
        print "Invalid command line parameters or no parameters specified\nPlease type -h for help"
        sys.exit(0)   

#UDP server handler, SocketServer class
class UDPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        data = self.request[0]
        msgq.put(data)

#Function to calculate and validate CRC per random packet
def crcProc(npacketid, crctoprocess, prevcrcseq, ctdata, nlogdelay):
    try:
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

                lcalcrc = (zlib.crc32(ctdata[lpid], lcrcprev) & 0xFFFFFFFF)

                if lcalcrc != lcrccurr:
                    logChecksum = ""
                    logChecksum = format("%s\n%d\n%d\n%x\n%x\n\n" % (lpid, lseqcurr, (lastpseq + 1), lcrccurr, lcalcrc))
                    lcrccurr = lcalcrc
                    tchklog = threading.Thread(target=chklogProc,name='chklogProc', args=[logChecksum, nlogdelay,])
                    tchklog.start()
                    
                del crctoprocess[lsdictkeyprev]
                crctoprocess[lsdictkeycurr][1] = lcrccurr
                lastpseq = lastpseq+1
                prevcrcseq[lpid] = lastpseq
                lsdictkeyprev = lpid + str(lastpseq)
                lsdictkeycurr = lpid + str(lastpseq+1)   
    except KeyboardInterrupt:
        raise KeyboardInterrupt                


#Process to receive each UDP packet, validate 
def processpacket(msgqueue, dtkeys, dtbinaries, nlogdelay):
    try:
        #initial CRC to track the last processed CRC for a packet
        prevcrcseq = dict()
        #empty dict of CRCs to be processed format: packetidseqno:crc
        crctoprocess = dict()
        #starttime = time.time()
        ctdata = dict()
        for argpacket in dtbinaries:
            prevcrcseq[argpacket] = 0
            with open(dtbinaries[argpacket], "rb") as catfile:
                ctdata[argpacket] = catfile.read()
        while True:
            if not msgqueue.empty():
                dt = msgqueue.get()
                pid, pseq, xkey, nochsum = unpack('!IIHH', dt[:12])
                if hex(pid) in dtkeys and ((nochsum * 4) + 12 + 64) == len(dt):

                    #extract 64 bytes digital signature
                    DigSig = dt[(nochsum * 4) + 12:(nochsum * 4) + 12 + 64]

                    #extract data packet to verify the signature
                    spacket = dt[:-64]
                    #calculate SHA256 hash of the received packet
                    hashofpacket = SHA256.new(spacket).hexdigest()

                    #extract Long value of digital signature
                    dsg = int(DigSig.encode('hex'), 16)

                    #open public key from the provide file
                    with open(dtkeys[hex(pid)], "rb") as key_file:
                        n_bytes = key_file.read(64)
                        e_bytes = key_file.read(3)

                    #extract Long value of mod and exp from the public key
                    mod = int(n_bytes.encode('hex'), 16)
                    exp = int(e_bytes.encode('hex'), 16)

                    #remove padding and extract hash 
                    hashfromSig = format('%x' % pow(dsg, exp, mod))[-64:]

                    #Validate digital signature
                    if hashofpacket != hashfromSig:
                        logVerfication = ""
                        logVerfication = format("%s\n%d\n%s\n%s\n\n" % (hex(pid), pseq, hashfromSig, hashofpacket))
                        tverlog = threading.Thread(target=verlogProc,name='verlogProc', args=[logVerfication, nlogdelay,])
                        tverlog.start()

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
                    crcProc(hex(pid),crctoprocess, prevcrcseq, ctdata, nlogdelay)
            #elif len(crctoprocess) == 1:
                #totaltime = time.time() - starttime
                #print "Total time to process the packets %d" % totaltime
    except KeyboardInterrupt:
        exit(0)


def verlogProc(dt, nlogdelay):
    if threading != None and any((i.name == "MainThread") and i.is_alive() for i in threading.enumerate()): 
        time.sleep(nlogdelay)
        if len(dt) and dt != "":
            #print("about to write to the veri log %s" % dt)
            with open("verification_failures.log", "a") as ver_log:
                ver_log.write(dt)
    else:
        exit()

def chklogProc(dt, nlogdelay):
    if threading != None and any((i.name == "MainThread") and i.is_alive() for i in threading.enumerate()):
        time.sleep(nlogdelay)
        if len(dt) and dt != "":
            #print("about to write to the chk log %s" % dt)
            with open("checksum_failures.log", "a") as chk_log:
                chk_log.write(dt)
    else:
        exit()

if __name__ == "__main__":
    
    try:
        print "Starting UDP server, press Ctrl+c to exit"
        msgq = Queue()
        #start process for packets
        p = Process(target=processpacket, args=(msgq, dtkeys, dtbinaries, nlogdelay,))
        p.start()
        #start UDP server
        HOST, PORT = "127.0.0.1", nport
        udpserver = SocketServer.UDPServer((HOST, PORT), UDPRequestHandler)
        udpserver.serve_forever()
    except KeyboardInterrupt:
        while p.is_alive():
            pass
        udpserver.shutdown()
        udpserver.server_close()
        os._exit(0)
