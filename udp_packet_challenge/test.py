from Crypto.PublicKey import RSA
from struct import *
from bitstring import BitArray

""" keyPair = RSA.generate(bits=1024)
print "Public key: n = " + he
(keyPair.n) 
print "Public key: e = " + he
(keyPair.e) 
print "Private key: e = " + he
(keyPair.d)

f = open('mykey.pem','wb')
f.write(keyPair.e
port_key('PEM'))
f.close() """

""" f1 = open('mykey.pem','r')
keyPair1 = RSA.import_key(f1.read()) """

""" f1 = open('key.bin', 'r')
data = f1.read()
f1.close()

modsize = 512 // 8

modBytes = data[slice(0, modsize)]
mod = int(modBytes.encode('hex'), 16)

expBytes = data[slice(modsize, None)]
exp = int(expBytes.encode('hex'), 16) """

with open("key.bin", "rb") as key_file:
    n_bytes = key_file.read(64)
    e_bytes = key_file.read(3)


mod = int(n_bytes.encode('hex'), 16)
exp = int(e_bytes.encode('hex'), 16)


signature = 920542404865063586561214586346617980231637256995239447891847599721679709982649387610943178273234484750494599464580062759415140320974892020244472124921583

hashfromSig = pow(signature, exp, mod)

shash = format('%x' % hashfromSig)

print shash[-64:]


""" print "Public key: n = " + he
(keyPair1.n) 
print "Public key: e = " + he
(keyPair1.e) 
print "Private key: d = " + he
(keyPair1.d)

print len(bytes(keyPair1.n))
print len(bytes(keyPair1.e)) """


