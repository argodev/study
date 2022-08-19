#!/usr/bin/python3

# get the current challenge

# parse the message text

# encode it

# submit it

# how/where do I use my API key???

import requests
import hashlib
from bs4 import BeautifulSoup
#from Crypto.Hash import SHA512

start_string="----- BEGIN MESSAGE -----"
end_string="----- END MESSAGE -----"


cookies = {'PHPSESSID': 'ge428qu2obvf0vsaqe765r8kb6'}

url="https://ringzer0ctf.com/challenges/13"
resp = requests.get(url, cookies=cookies)

soup=BeautifulSoup(resp.text,'html.parser')
m = soup.find("div", {"class": "message"})


print("--------------------------")
# raw message
print(m.text)

# clean up
msg = m.text    
msg = msg.replace(start_string, '')
msg = msg.replace(end_string, '')
msg = msg.strip().encode('utf-8')

# calculate the hash
message_hash = hashlib.sha512(msg).hexdigest()


print("--------------------------")
# cleaned message
print(msg)
print("--------------------------")
# message hash
print(message_hash)
print("--------------------------")
update_url = url + "/" + message_hash
resp = requests.get(update_url, cookies=cookies)
print("--------------------------")

# response
soup=BeautifulSoup(resp.text,'html.parser')
a=soup.find("div",{"class":"alert"})
if len(a.text) > 0:
    print(a.text)
else:
    print(resp.text)
print("--------------------------")
