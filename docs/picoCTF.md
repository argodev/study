# picoCTF

picoCTF is .....

!!! note
    Any time a sample command/output is listed on this page, the actual flag value will be replaced with `redacted_value`. This is done to ensure the "keys" aren't given away entirely should someone find these notes.

## Web Exploitation

## Cryptography

### Mod 26

This is a test to see if you know what `ROT13` is, and how to encode/deocde from it. You are provided a value (`cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}`) that looks a bit like a flag and that is all.

[ROT13](https://en.wikipedia.org/wiki/ROT13) is a substitution cipher where you take one letter in plain text, increase the index by 13, and use the corresponding letter in the "enciphered" text. This is a special case of a [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher) because there are 26 letters in the Roman alphabet, the encoder is its own decoder.

There are a couple of easy ways to go about solving this. I've listed a few here because I thought they were informative for future challenges:

* [Cyber Chef](https://gchq.github.io/CyberChef/) with a `ROT13` recipe gives you the results straight away. This is how I solved it myself (kinda lazy, but effective).

* I saw some examples using the Linux `tr` command that I thought were pretty neat. The following example shows how:

```bash
# simple and straight-forward
$ echo "cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
picoCTF{redacted_value}

# or, let's get a little fancy...
# we could/should put this first line in our .bashrc
$ alias rot13="tr 'A-Za-z' 'N-ZA-Mn-za-m'"

# then, you can call it directly
$ echo "cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}" | rot13
picoCTF{redacted_value}
```

* I also saw a python one-liner that I thought was nice:

```bash
$ echo "cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}" | python3 -c 'import sys; import codecs; print(codecs.encode(sys.stdin.read(), "rot13"))'
picoCTF{redacted_value}
```

## Reverse Engineering

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



## Forensics

### information

Here you are presented with an image and asked nothing else. We download the file `cat.jpg` and inspect it. I immediately assumed there was either a string embedded in the file that was or contained the key. Running `strings` on the file and then grepping for `picoCTF` didn't yield anything, but that probably would have been too easy. Opening it with `eog` and then viewing the metadata, however, showed a weird-looking license.

Experimenting with this a little rendered the key:

```bash
$ strings cat.jpg | grep license | cut -d"'" -f 2 | base64 -d
picoCTF{redacted_value}
```

### Matryoska doll

As we are told in the instructions, "Matryoshka dolls are a set of wooden dolls of decreasing size placed one inside another." We download `dolls.jpg` and immediately learn that the file does not render properly with `eog`. Running `file` shows it as a `PNG` file rather than jpg. 

What followed was a cycle of running `binwalk` on the file, followed by extracting the contents (e.g. `binwalk -e <file_name>`) and a repeat. I did this 3 or 4 times, and the final "inner" file was `flag.txt`. this file contains the flag to be submitted.

### tunn3l v1s10n

We are provided a file, `tunn3l_v1s10n` and asked to recover the flag.




## General Skills

### Obedient Cat

This is basically a "test challenge" to ensure you know how things work. You download the file, read it in a text editor (or just via `cat`), and you can recover the flag for submission.

```bash
$ cat flag
picoCTF{redacted_value}
```

### Python Wrangling

This is a "can you run python and follow instructions" challenge. You start with a script `ende.py` that can encrypt/decrypt a file (`flag.txt.en`) using the password in `pw.txt`. You can do this in two steps, or in a one-liner as follows:

```bash
python3 ende.py -d flag.txt.en < pw.txt
Please enter the password:picoCTF{redacted_value}
```

### Wave a flag

This is a simple test to see if you know how to interact with command-line tools by asking for arguments. Additionally, you need to know a little about execute permissions.

```bash
# make it executable
$ chmod +x warm

# run it to see what it does
$ ./warm 
Hello user! Pass me a -h to learn what I can do!

# follow the instructions
$ ./warm -h
Oh, help? I actually don't do much, but I do have this flag here: picoCTF{redacted_value}
```

## Binary Exploitation

### Stonks

Here you are given a file `vuln.c` and told that there is a bot to trade "stonks" using AI and ML. It looks to be  service listening on `mercury.picoctf.net 16439` that you can interact with via netcat (`nc`). Probably need to spend some time looking at `vuln.c` to see what is going on...




## Uncategorized



xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx