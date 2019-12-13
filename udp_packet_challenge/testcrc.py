

""" with open("cat.jpg", "rb") as catfile:
    bt = bytes(catfile.read()).encode('hex')

print bt[1:2] """

import zlib

with open("cat.jpg", "rb") as catfile:
    data = catfile.read()

checksum = zlib.crc32(data, int('d26838ca',16)) & 0xFFFFFFFF

print hex(checksum)

dt = dict()

lst1 = (1,2,3)
lst2 = (3,4,5)
lst3 = (6,7,8)

dt[1] = lst1
dt[2] = lst2
dt[3] = lst3

print dt

del dt[1]

print dt
