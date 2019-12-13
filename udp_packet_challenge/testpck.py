from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

# Generate 1024-bit RSA key pair (private + public key)
keyPair = RSA.generate(bits=1024)

# Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
msg = b'A message for signing'
hash = SHA256.new(msg)
print hash.hexdigest()
#signer = PKCS115_SigScheme(keyPair)
#signature = signer.sign(hash)
signature = pow(int(hash.hexdigest(), 16), keyPair.d, keyPair.n)
#print("Signature:", binascii.hexlify(signature))
print '%x' % signature

# Verify valid PKCS#1 v1.5 signature (RSAVP1)
msg = b'A message for signing'
hash = SHA256.new(msg)
print hash.hexdigest()

hashFromSignature = pow(signature, keyPair.e, keyPair.n)

print '%x' % hashFromSignature

""" signer = PKCS115_SigScheme(keyPair)
try:
    signer.verify(hash, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.") """

# Verify invalid PKCS#1 v1.5 signature (RSAVP1)
msg = b'A tampered message'
hash = SHA256.new(msg)
print hash.hexdigest()
signer = PKCS115_SigScheme(keyPair)
try:
    signer.verify(hash, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.")
