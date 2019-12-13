from multiprocessing import Process, Manager

def f(l, n):
    l.append(n+1)
    l.append(n+2)

if __name__ == '__main__':
    manager = Manager()

    l = manager.list()
    

    p = Process(target=f, args=(l, 0))
    p.start()
    p.join()
    print l

    p = Process(target=f, args=(l, 2))
    p.start()
    p.join()
    print l



