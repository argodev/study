#! /usr/bin/python3

with open('output.txt', 'r') as fp:
    data = fp.readlines()

flag = "".join([chr(int(x.replace('\n', ''))) for x in data])
flag = f"picoCTF{{{flag}}}"
print(flag)
