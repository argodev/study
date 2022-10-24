# Challenge 00: ret2win

I'm new new ROP and trying to learn. Ben pointed me to the [ROP 
Emporium](https://ropemporium.com/) as well as [a 
writeup](https://medium.com/@int0x33/day-1-rop-emporium-ret2win-64bit-bb0d1893a3b0).  
As always, the writeup was a bit out of date, and could not be followed exactly, 
but that helped cement some of the learning and, while a little painful, maybe 
made some things stick.

## Starting

My initial plan was to read through the writeup twice. The first time was just 
to skim/do and the second was to understand. I followed my plan and wrote 
installed most of the tools. I did note that the writeup installed `peda` while 
the current version of the Rop Emporium site recommends `pwndbg`. Since I read 
through the writeup first, I setup `peda` - I'll need to come back and look at 
`pwndbg` later... it is supposedly a superset of both `peda` and `gef`.

I followed the walkthrough and used `radre2` to do the initial poking around.  
While I didn't confirm, my supposition is that `ghidra` would have been just as 
easy (if not more so) to accomplish this step.

This _"challenge"_ really isn't much of one... it is a simple stack overflow 
that requires you to learn the address in memory you want to jump to (return to) 
and obtain the flag. So, your "chain" has only a single link.

I liked the use of `pattern_create` and `pattern offset` as these are quite 
helpful in many situations.

I got to the point where I was to run the sample exploit, but it failed for me 
due to a segfault. Digging a bit further, this led me to the [Common 
Pitfalls](https://ropemporium.com/guide.html#Common%20pitfalls) section of the 
beginners guide and, specifically, the section on the `MOVAPS` issue. I read the 
text in this paragraph a time or two and it didn't really sink in... I was being 
told to ensure my stack was 16-byte aligned, but I didn't know how to do that 
_(I was, evidently, incapable of reading the last sentence of the paragraph)_.

My trouble, however, got me to trying to figure out how to use `gdb` while 
passing in a generated payload (program arguments) - and specifically those that 
contain illegal characters (e.g. \x00). If you were *not* using GDB, you could 
do something like this:

```bash
$ python -c 'print "\x90" * 40 + "\x11\x08\x40\x00\x00\x00\x00\x00" | ./ret2win
```

However, running this with `gdb` is not as straight-forward. After some poking 
around and flailing, I stumbled onto [this answer from 
StackOverflow](https://stackoverflow.com/questions/8422259/gdb-debugging-with-piped-input-not-arguments).  
The key is to write the input data to a file first, and then pass it to the 
program arguments once `gdb` is running. following this, I did something like 
the following:

```bash
$ python -c 'print "\x90" * 40 + "\x11\x08\x40\x00\x00\x00\x00\x00" > t1.dat
$ gdb ./ret2win
(gdb) r < t1.dat
```

This allowed me to pass the data exactly as I wished into the program being 
debugged by `gdb`. This confirmed my problem was the same `movaps` issue 
discussed above. This time, however, I read the entire paragraph and caught the 
last line... either pad the data, add an extra `ret`, or change the offset to 
skip a `push`. In the debugger, it was clear that the function I was interested 
in started at `0x400811`, but the first operation is a `push`. I adjusted my 
payload to cause `rip` to be set to one step further (`0x400812`) and the 
exploit completed successfully.

```bash
$ python -c 'print "\x90"*40 + "\x12\x08\x40\x00\x00\x00\x00\x00\x00"' | ./ret2win
ret2win by ROP Emporium
64bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!}

```



Following up, I wanted to do a little more to practice some of the other tools

Create a template where I can explore:

```bash
$ pwn template ret2win > ret2win.py
```

## break

I found that I really didn't understand what I thought I did. So, I started over 
again and did it from scratch.

After going back and re-working things, I bundled the solution in 
[exploit_00.py](exploit_00.py).


## 32-Bit Solution

The solution to the 32 bit version was not much different. The only change is 
that the offset is different (`44` rather than `40`), but that is determined 
automatically via the exploit script. Additionally, the exploit script needs to 
read the value of `eip` rather than `rsp` and its related to locate the pattern.  
Spent a bit too much time tracking down weird nuiances on that.  The solution 
for the 32 bit verison is [exploit_0032.py](exploit_0032.py).

## What Did I Learn?

Both versions of this challenge were relatively easy and straight forward. The 
take-aways for me from this challenge are:

* Exposure to some tools/extensions I have not used before
* Exposure to the MOVAPS issue with Ubuntu 18.04 and later
* Learning how to send various blocks of data to an application both from the 
  commandline directly as well as via GDB.

