import hashlib

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()


pos_pw_list = ["8799", "d3ab", "1ea2", "acaf", "2295", "a9de", "6f3d"]

correct_pw_hash = open('level3.hash.bin', 'rb').read()

for pw in pos_pw_list:
    x = hash_pw(pw)
    if correct_pw_hash == x:
        print('Found!')
        print(pw)