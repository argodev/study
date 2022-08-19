#! /usr/bin/python3

import nclib

# connect to the server
nc = nclib.Netcat(('jupiter.challenges.picoctf.org', 29956))

# first response is something like this:
# b'Let us see how data is stored\ncomputer\nPlease give the 01100011 01101111 01101101 01110000 01110101 01110100 01100101 01110010 as a word.\n...\nyou have 45 seconds.....\n\nInput:\n'
resp = nc.recv()

# let's get just the binary string portion
s1 = resp[resp.find(b'Please give the')+16:resp.find(b'as a word')-1]
w1 = "".join([chr(int(x,2)) for x in s1.split()])
print(w1)
nc.send_line(w1)

# second response is something like this:
# b'Please give me the  143 150 141 151 162 as a word.\nInput:\n'
resp = nc.recv()
s2 = resp[resp.find(b'Please me give the')+20:resp.find(b'as a word')-1]
w2 = "".join([chr(int(x,8)) for x in s2.split()])
print(w2)
nc.send_line(w2)

# third response is something like this:
# b'Please give me the 6c696d65 as a word.\nInput:\n'
resp = nc.recv()
s3 = resp[resp.find(b'Please me give the')+20:resp.find(b'as a word')-1]
s3 = [s3[i:i+2] for i in range(0, len(s3), 2)]
w3 = "".join([chr(int(x,16)) for x in s3])
print(w3)
nc.send_line(w3)

print(nc.recv())
