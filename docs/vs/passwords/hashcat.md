# HashCat

HashCat has *alot* of options. It is really worth taking time to read through the docs if you want to actually use the tool productively. 


```{tip}
If you want to keep an eye on your NVIDIA GPUs while they are busy cracking passwords, you can get the equivalent of `htop` running a command similar to the following: `$ watch -d -n 0.5 nvidia-smi`. In this case it runs the `nvidia-smi` utility every half second (`-n 0.5`), leaves it "in place" (`watch`) (so your screen isn't constantly scrolling) and higlights the values that change between refreshes (`-d`)
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
   

