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

## HashCat

HashCat has *alot* of options. It is really worth taking time to read through the docs if you want to actually use the tool productively. 


!!! tip
    If you want to keep an eye on your NVIDIA GPUs while they are busy cracking passwords, you can get the equivalent of `htop` running a command similar to the following: `$ watch -d -n 0.5 nvidia-smi`. In this case it runs the `nvidia-smi` utility every half second (`-n 0.5`), leaves it "in place" (`watch`) (so your screen isn't constantly scrolling) and higlights the values that change between refreshes (`-d`)




## John the Ripper (aka John)

[John](https://www.openwall.com/john/) is another password discovery tool that has been around for quite some time. You can start off by giving it very little, and it will try to do it's thing:

```bash
$ ./john ~/Downloads/hash.md5 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-opencl"
Use the "--format=md5crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 16 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:./password.lst
Proceeding with incremental:ASCII
0g 0:00:01:47  3/3 0g/s 1092Kp/s 1092Kc/s 1092KC/s pm1LEN..pmbk2c
```

You can see that I let it run for just a short while (< 2 minutes) and it had already exhausted the default word list and had moved on to a more brute-force approach. 

If we next try the `all` wordlist [availble from Openwall](https://www.openwall.com/wordlists/), we get disappointing results:

```bash
$ ./john --wordlist=$HOME/Downloads/all ~/Downloads/hash.md5 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-opencl"
Use the "--format=md5crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:03 DONE (2021-09-21 15:01) 0g/s 1169Kp/s 1169Kc/s 1169KC/s zhnets..{ysrfk
Session completed. 
```

In less than one second, it ran through all 5,014,958 entries in our word list and, having not found a match, gave up. But wait, isn't it supposed to be a little smarter than that? Can't it try some permutations? Yes... the key is that if you provide your own list, and you also want it to _mangle_ the inputs, you need to enable the rules engine via `--rules`. If we do that, we still get sub-optimal results:

```bash
$ ./john --wordlist=$HOME/Downloads/all --rules ~/Downloads/hash.md5 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-opencl"
Use the "--format=md5crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:02:25 DONE (2021-09-21 15:04) 0g/s 1074Kp/s 1074Kc/s 1074KC/s Zwychiting..Zyyeking
Session completed. 
```

Here, it took about 2.5 minutes to test all of the default rules for each entry in the word list, but it still didn't find a match. You could go about crafting your own mangling rules, but we might also consider just having a better word list. Interestingly, if we provide it the `rockyou.txt` word list, the results come back nearly instantaneously:

``` bash
$ ./john --wordlist=$HOME/Downloads/rockyou.txt ~/Downloads/hash.md5 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-opencl"
Use the "--format=md5crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass1word        (?)     
1g 0:00:00:00 DONE (2021-09-21 14:47) 25.00g/s 307200p/s 307200c/s 307200C/s pitufo..gamboa
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

# now we run the "show" command, and we see the following:
$ ./john --show ~/Downloads/hash.md5 
?:pass1word

1 password hash cracked, 0 left
```
Not too bad... with a good wordlist, the password was found in nearly unmeasureable time. I should also note, that the `rockyou.txt` word list has 14,344,391 entries... almost three times larger than the `all` list by Openwall.

You might notice the `(?)` listed during the main run, as well as `?:` proceeding the password in the output from the `--show` command. In both cases, that is because I didn't provide a "normal" `passwd` file that would have started with `username:password:etc`. If I had, it would have shown the username where the `?` is shown above.

Running the same command against the sha-512 version of our password hash produced the same results - it successfully recovered the password in less-than-measureable time.

On a whim, I tried John against another password hash that I had. This time, I knew that it was 8 characters long, and consisted of only lower-case letters and numbers. In order to limit the search space, I customized `john.conf` such that the `MinLen` and `MaxLen` for the `[Incremental:LowerNum]` character set were both set to 8. Then, I ran the following command. Notice that I left the default word list but specified the `LowerNum` character set.

```bash
$ ./john --incremental=lowernum.chr ~/Downloads/hash.8lowernum
```


## Random Notes to be incorporated

* the pattern-based approach is called a "mask attack" - more info is available here: https://hashcat.net/wiki/doku.php?id=mask_attack
* we might want to create custom word-lists: https://infinitelogins.com/2020/11/16/using-hashcat-rules-to-create-custom-wordlists/
* I did some testing to compare, and (where appropriate), it seems that the mask-attack is more performant (hashes/sec) than a wordlist (though it might not be successful).
   * using a non-optimized command (`$ ./hascat.bin -m 1800 hash2 rockyou.txt) exhausted the list in 12:08 at a rate of roughly 19,706 H/s
   * using an optimized command (`$ ./hashcat.bin -O -w 3 hash2 rockyou.txt) exhausted the list in 2:38 with a rate of 90,525 H/s
   * using a mask attack (no wordlist) is seeing a hash rate of around 110 kH/s `$ ./hashcat.bin -O -w 3 -m 1800 -a 3 -1 ?l -2 ?l?d hash2 ?1?2?2?2?2?2?2?1`
   * tried a *very* targeted (cheating) mask based on what I know of how the password is formed `?l?d?l?d?l?d?l?l`
   * you can benchmark your system for a particular hash: `$ ./hashcat.bin -b -m 1800`. Mine claims 114.5 kH/s.
   * `-m 1800` is sha512crypt with 5000 iterations (e.g. `$6$`)
   * setting the mask to *exactly* what the password has (cheating), allowed the crack to finish in 8:20:00, after having made it through 27.86% of the search space. The speedd averaged 111.6 kH/s. The command run was: `./hashcat.bin -O -w 3 -m 1800 -a 3 hash2 ?l?d?l?d?l?d?l?l`
   * Next, we tried "loosening" it a bit, to see what we learn perf-wise: `./hashcat.bin -O -w 3 -m 1800 -a 3 -1 ?l -2 ?l?d hash2 ?1?2?1?2?1?2?1?1`. The estimate is that it will take 54 days to exhaust the search space.
   

