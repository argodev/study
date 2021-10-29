#!/usr/bin/python3

import hashlib

def simple_number_hash(hash, start=0, end=1000000, salt='', extra_rounds=0):
    retval = -1
    for i in range (start, end):
        msg = str(i).encode()
        msg = msg + salt.encode()
        message_hash = hashlib.sha1(msg).hexdigest()
        if (message_hash == hash):
            print('[*] Match Found!!!')
            print('%s generates %s' % (msg, message_hash))
            retval = (i)
            break

        # if not, let's try the current value for the number of rounds
        for j in range(extra_rounds):
            message_hash = hashlib.sha1(message_hash.encode()).hexdigest()
            if (message_hash == hash):
                print('[*] Match Found!!!')
                print('%s with %d rounds generates %s' % (msg, j, message_hash))
                retval = (i, j)
                break


        # status message otherwise
        if ((i % 1000) == 0) and (i > 0):
            print(i)

    return retval

# given a hash, let's try to find a match

# test it
hash = '6eaeb03ebe3d3a6249901ed4fd3a5f983c72b6ef'
retval = simple_number_hash(hash)

hash = 'bc40fdf0cfd9fe793bacc67e6af68cb38d1309fd'
salt = '81e44c47650b08211cc65efd00b74d6b2fcd6b7a26940e0cadf02de1f8934a04'
retval = simple_number_hash(hash, extra_rounds=100, salt=salt)

#hash = '18b41a850c666300a8bec7d7bc204ae889b4a4ab'
#retval = simple_number_hash(hash, extra_rounds=50)
#retval = simple_number_hash(hash, extra_rounds=100)
print('Done')


#        TvTKANPZDmX2rELHGwuOFuZEvuRf39KEGg11Uxm8o





# for i in range (0,10000):
#     msg = str(i).encode()
#     message_hash = hashlib.sha1(msg).hexdigest()
#     if (message_hash == hash):
#         print('Found!!!')
#         print(i)
#         print(message_hash) 
    
#     # status message otherwise
#     if (i % 1000) == 0:
#         print(i)

# message_hash = hashlib.sha1(str(9922).encode()).hexdigest()
# print(message_hash)