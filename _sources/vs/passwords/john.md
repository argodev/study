# John the Ripper (aka John)

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
