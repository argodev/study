import hashlib

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

correct_pw_hash = open('level5.hash.bin', 'rb').read()

with open('dictionary.txt', 'r') as pwds:
    pw = pwds.readline()
    while pw:
        # be sure to strip off the trailing \n
        x = hash_pw(pw[:-1])
        if correct_pw_hash == x:
            print('Found!')
            print(pw)
            break
        else:
            pw = pwds.readline()
