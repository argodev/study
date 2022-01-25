# Password Cracking

There's a ton of work occuring in the password cracking space. In general, however, the problem is pretty simple. Given a hash of the password (and hopefully the salt), try a number of different values (with mutations) to see if you can create the same hash. If you do, then you know the original password. In this way, it isn't so much about _cracking_ the password as it is about _guessing_ it. 

I've tried a few tools and will document here some notes on using them. This is _not_ a definitive list, and there are many other approaches. These are just the ones I've used.

## Examples

First, we need some safe examples to play with. The first example uses the older-style MD5 based BSD password algorithm that is used by some older/more limited variants of linux. You can see them stored in `/etc/passwd` or `/etc/shadow` in the form of `$1$user_specifc_salt$user_password_hash` where the `$` is the delimiter and the value `1` indicates the MD5-based hash in the form of `salt$password`. In more modern systems you might see values of `6` which indicates a __sha-512__ based hash.

Thankfully, we can easily recreate an example hash as follows:

```bash
# given: user-specific salt of "mysalthere"
# given: user password of "pass1word"
# 
# create the hash version
$ openssl passwd -1 -salt mysalthere pass1word
$1$mysalthe$CzBJwN4eH504pWE9/g8ug.

# additionally, we can create the more-modern variant that utilizes the
# sha-512 algorithm
$ openssl passwd -6 -salt mysalthere pass1word
$6$mysalthere$V7n5N7SpCKyPt15fW3uKvRS51cLHH8TV8/RKA0DhHuzxZKbpkLDS7eciImIkzgG3cbrkSHonb3b2PQiANaF6X/
```

Given this, we'll put the first hash in a file called `hash.md5` and the second `hash.sha512`. These will be our test examples for the two tools we are looking at.


## Word Lists

Unless you have a magic list of starting words that you've curated over the years, you'll likely need a word list. There are tons available online - some free, others require payment. Some even come shipped by default in security-focused distros like Kali (`/usr/share/wordlists/`). Here I'll use the famous _"rockyou"_ list... its available online wherever [good word lists are found](https://google.com/?q=rockyou%20wordlist)...


## Iterations
asdfasdf

## Salts

asdfasdfasdf


## System Overview

Device #1: NVIDIA GeForce RTX 2080 Ti, 10859/11019 MB, 68MCU
Device #2: NVIDIA GeForce RTX 2080 Ti, 10741/10997 MB, 68MCU
```
$ ./hashcat.bin -O -m 1800 -w 4 -b
hashcat (v6.2.4) starting in benchmark mode


Benchmark relevant options:
===========================
* --optimized-kernel-enable
* --workload-profile=4

--------------------------------------------------------------------
* Hash-Mode 1800 (sha512crypt $6$, SHA512 (Unix)) [Iterations: 5000]
--------------------------------------------------------------------

Speed.#1.........:   303.6 kH/s (169.65ms) @ Accel:8192 Loops:1024 Thr:32 Vec:1
Speed.#2.........:   357.1 kH/s (144.11ms) @ Accel:8192 Loops:1024 Thr:32 Vec:1
Speed.#*.........:   660.7 kH/s
```

https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/