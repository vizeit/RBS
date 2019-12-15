from multiprocessing import Process, Manager
import time
import sys


def f(l, n):
    try:
        while True:
            if len(l) < 100:
                l[n] = n
                n = n +1
    except KeyboardInterrupt:
        print "exiting f"
        
def f2():
    try:
        manager = Manager()
        bloop = True
        l = manager.dict()
        count = 0
        #print "Before creating process"
        p = Process(target=f, args=(l, count))
        p.start()
        while bloop:
            if len(l) > 0:
                if bool(l) and count in l:
                    print l[count]
                    del l[count]
                elif len(l) != 0:
                    #print "key %d not found" % count
                    #print l
                    p.terminate()
                    break
                count = count + 1
    except KeyboardInterrupt:
        print "exiting f2"


if __name__ == '__main__':
    try:
        p = Process(target=f2)
        p.start()
        while True:
            pass
    except KeyboardInterrupt:
        print "interrupt in main"
        sys.exit(0)
    

