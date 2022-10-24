# Challenge 05: fluff

Based on the instructions, I started with the `write4` solution and thought I'd 
go from there. I followed the normal early steps, confirmed the offset and 
updated the addresses for system and data write locations.

I actually spent quite a bit of time on this challenge and, after working 
through the *hard part*, got stuck on what should have been easy. 

## Getting the String where it Should Be

There were almost no overly helpful gadgets in this executeable. Following both 
the instructions as well as intuition from prior challenges, it is plain that we 
need a gadget of the form `mov [rega] regb; ret;`. We found exactly that in the 
`write4` challenge and I set out t o find something like that again. Instead of 
finding something that *clean*, I found the following:

```
0x40084e: mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; 
ret;
```

This gives me *notionally* what I want, but it also means I have an unneeded 
`pop r13`, a `pop r12`, and then this `xor byte ptr [r10], r12b` mess to deal 
with. The `pop13` can be handled by placing a dummy value in my payload that 
gets poped to that register and unused. The r12 value needs to be considered 
more closely as it will have an affect on the subsequent call. Providing `0x0` 
for that should be sufficient to nullify any changes that the last call would
make to the string just moved to the location referred to by `r10`.

Working backwards, I now know that I need to get my target address into `r10` 
and the data in `r11`. The hint from the instructions (and supported by 
investigation) is that a `pop r11; pop r10; ret;` will not exist. In fact, 
nothing even close does. I spent quite a bit of time with `ropper`, searching 
various options, learning op codes, and thinking through how one might get the 
data into those two registers. Here is what I ended up with:

```
# STEP 1: get target memory address into r10

# ensure that r11 is zeroed out. Provide dummy value for r14, ignore edi mov
0x400822: xor r11, r11; pop r14; mov edi, 0x601050; ret;

# pop the memory address into r12; ignore the r13d mov
0x400832: pop r12; mov r13d, 0x604060; ret; 

# XOR r11 and r12 to effectively move the address from r12 to r11
# provide dummy value for r12 pop, ignore r13d mov
0x40082f: xor r11, r12; pop r12; mov r13d, 0x604060; ret; 

# move contents of r11 into r10, ignore what was in r10
# provide dummy value for r15 pop, ignore r11d mov
0x400840: xchg r11, r10; pop r15; mov r11d, 0x602050; ret;

# r10 now has the target address

# STEP 2: get the text data into r11
# ensure that r11 is zeroed out. Provide dummy value for r14, ignore edi mov
0x400822: xor r11, r11; pop r14; mov edi, 0x601050; ret;

# pop 8 bytes of the text data into r12; ignore the r13d mov
0x400832: pop r12; mov r13d, 0x604060; ret; 

# XOR r11 and r12 to effectively move the text data from r12 to r11
# provide dummy value for r12 pop, ignore r13d mov
0x40082f: xor r11, r12; pop r12; mov r13d, 0x604060; ret; 

# r11 now has the text data

# STEP 3: move the data from the r11 register into memory
# mov r11 text data to the address provided by r10
# provide dummy value for r13 pop, provide 0x0 for r12 pop
0x40084e: mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; 
ret;

# 8 bytes of text data are now  in memory

## repeat steps 1-3 for each set of 8 bytes in command string

```

At this point, it should be a matter of putting the address of the command 
string into a register via a `pop rdi` followed by a call to `system()`.

## MOVAPS is Back (alignment issues)

Well, things don't always work out as you would like. My call to `system()` kept 
failing. I setup GDB to step through things and confirmed that it was getting 
passed exactly as I would expect it to be. I even did a side-by-side comparison 
to confirm... it was all good. However, it still failed. Stepping into that 
call, I found that it was failing within `do_system` on a `MOVAPS` call and that 
brought to mind some notes on the topic from the ROP Emporium beginners guide.  
Essentially, some newer systems require 16-byte alignment of the stack before a 
function call. I had fixed this in a prior challenge by simply changing where I 
jumped into a function by `0x8`. Unfortunately, I didn't see how to do that 
here. Worse, I found that I didn't understand what it meant by *16 byte 
aligned*, so... off to do some reading. Come to find out, it appears to be no 
big deal... you simply need the stack pointer to be pointing at an 
evenly-divisible mulitple of 16 (`0x7fffffffdd00` is good, `0x7fffffffdd08` is 
bad.). The question is, how do you fix it? Like most things, the solution is 
relatively easy... simply add an entry into the call chain that pushes the stack 
pointer down 8 bytes further before the call to system. The ROP equivalent of a 
`NOP`. With a little reading I found that this is sometimes called a `ret2ret` 
and you will sometimes see a chain of them built up just like you might fight a 
nop sled in shellcode. Searching for a `ret` gadget was obviously trivial and I 
simply added one in my payload right before my call to `system()`. Now, I should 
be all set.

## The Big Issue

But I wasn't. To be clear, the `ret2ret` trick *did* fix the `movaps` issue 
(confirmed by stepping through the code in gdb). Now, however, my exploit fails 
in the call to `execve()`. I set up a side-by-side window to see what was 
different between the call in this challenge and the call in one of the 
challenges that work, and I'm stuck. Somewhat frustrating as it seems that I've 
solved the *hard part* of the problem (gadget dance above to get the command 
string into memory as it needed to be).

> Interestingly, I did some poking around on other people's solutions, and 
> nearly everyone I found did it identically to mine. I tried to run some of 
> theirs, and *each one failed* exactly as mine did. I'm guessing that something 
> in the O/S has "helped" us. I may dig further.


There is an issue with the call to execve - the third parameter (RDX) is being 
set to 0x10000 and that is causing it to fail. You can test this by stepping 
through in GDB to the spot right before and updating the address value using 
something similar to the following:

```
$ set {int}0x7fff04ad75d8 = 0x0
```

If you then continue it will work properly. I'm still trying to figure out where 
this is coming from and if there is a way to avoid it, but I've not been 
terribly successful.



## 32 Bit Solution

The 32 bit solution was quite easy and straight-forward (well, given the 
solution to the 64 bit version). The registers and such were slightly different 
(obviously), but the pattern to solution was identical. Further, there were no 
issues with MOVAPS or the excve call - it *just worked*. The exploit is availble 
in [exploit_0532.py](exploit_0532.py).






