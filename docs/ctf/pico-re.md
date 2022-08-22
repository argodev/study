# Reverse Engineering

### Transformation

This one takes a little more work than some of the other starter challenges. You are given a file `enc` and a little bit of code: `''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])` and asked to figure out what it is. To solve this you likely need to understand what the "code" is doing and what each command is. This appears to be a python one-liner that takes a variable `flag`, loops through it, manipulates it a bit, and spits it out. To get the flag back in 'plain text', we simply need to reverse the process.

What appears to be happening in the provided python script is this:

* loop through the characters in `flag`, starting with the "0th", and skipping every other
* take the ordinal value of the current character (int that maps to the ASCII code, e.g. 'a' becomes 97) and shift that value up by 8.
* then take the next character in the flag and add it to the shifted value
* output the resulting number as a string character.

To "undo" the above, we need to:

* loop through the characters in enc _one at a time_
* take the ordinal value of the current character
* take the right-most 8 bits and convert that to a character (becomes the second letter)
* shift the remaining number down 8, convert that to a character
* output the results

A "verbose" version of the reversing is shown in the following python function:

```python
def decode(enc):
    result=''
    for i in range(0, len(enc)):
        result += chr(ord(enc[i]) >> 8)
        result += chr(ord(enc[i]) & 0xff)
    return result
```

A "one liner" is as follows:

```python
''.join([chr(ord(enc[i]) >> 8) + chr(ord(enc[i]) & 0xff) for i in range(0, len(enc))])
```

So, you can tie it all together if you like as follows:

```bash
$ cat enc | python3 -c "import sys; enc=sys.stdin.read(); plain=''.join([chr(ord(enc[i]) >> 8) + chr(ord(enc[i]) & 0xff) for i in range(0, len(enc))]); print(plain)"
picoCTF{redacted_value}
```

### keygenme-py

For this challenge, you are given the file `keygenme-trial.py` and no further instructions.

If we run the script, we see that there is some functionality that is protected by a license key. It doesn't take much guessing to assume we need to figure out the key, the result of which will either be the flag itself, or will unlock functionality that will render it. Looking into the code we see the function `check_key(user_key, bUsername_trial)` that looks quite promising. Digging into it and the surrounding code, we learn the following things:

* Must be 32 chars long
* Starts with `picoCTF{1n_7h3_|<3y_of_`
* Ends with `}`
* Has 8 unknown chars in the middle `xxxxxxxx`
* username_trial is `GOUGH`

Additionally, the main logic of the `check_key()` function is as follows:

1. Confirm provided key is 32 chars long
1. Ensure the first part of the key matches `picoCTF{1n_7h3_|<3y_of_`
1. Loops through the next 8 characters to ensure they match particular indicies of a hash based on the trial username
1. If everything else has passed, we are good to go.

All of the hash-based checks look at the same hash, simply compare against different indicies. So, let's do a one-liner to generate our own copy of the hash so we can work against it.

```bash
$ python3 -c "import hashlib; x=hashlib.sha256(b'GOUGH').hexdigest(); print(x)"
e8a1f9146d32473b9605568ca66f7b5c2db9f271f57a8c8e9e121e48accddf2f
```

Simple enough, we then build our 8-digit key using the proper values from the string above (remember the indicies in the code are zero-based).

`f911a486`

We then assemble the entire key and submit it to the app to decrypt the "full" version of the program.


### crackme-py

This one is pretty easy. Downloading/running the file didn't seem to do much, so we view it in an editor and notice an uncalled-function `decode_secret()` as well as an interesting constant `bezos_cc_secret`. We add a line at the bottom of the script `decode_secret(bezos_cc_secret)` and then run the script, providing some dummy values, and then being presented with a key.


### ARMssembly 0

Here we are presented a file (`chall.S`) which is an ARM-based assembly program. We then are asked "What integer does this program print with arguments `182476535` and `3742084308`? Flag format: picoCTF{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be picoCTF{0055aabb})"
