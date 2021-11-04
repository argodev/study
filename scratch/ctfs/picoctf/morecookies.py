#!/usr/bin/python3

from base64 import b64decode, b64encode
import requests

def bitflip(pos, bit, data):
    raw = bytearray(b64decode(b64decode(data)))
    #print(len(raw))
    #print(bin(raw[pos]))
    raw[pos] = raw[pos]^(1<<bit)
    #print(bin(raw[pos]))
    return b64encode(b64encode(bytes(raw)))

auth_name='a041d2l1VlNlMWFUd3VQbWZjOHg3MGxZK2VtREp4T3NSdUlvNnRTNWtGUFlTRVQ2WXplYytpRjBTdUxJZS9zTkpHdWdSejFObXVibzNtSVlQazkvTVk4b0ZwUnBsRGowU2s1RGw0RTBzNFdQZDFjMnY0ajlOZDJIMGlWQlE4Uks='

found = False

for i in range(96):
    print(i)
    if found:
        break

    for j in range(8):
        c = bitflip(i, j, auth_name)
        #print()
#         print(str(c))
        cookies= {'auth_name': c.decode()}
#         print(cookies)

        r = requests.get('http://mercury.picoctf.net:15614/', cookies=cookies)
#        print(r.text)

        if 'picoCTF' in r.text:
            print(r.text)
            print(i)
            print(j)
            found = True
            break

        # if 'Cannot decode cookie' not in r.text:
        #     print("Valid Cookie")
        #     print(r.text)
        #     print(i)
        #     print(j)
        #     print(cookies)
    #found = True
print('Done!')