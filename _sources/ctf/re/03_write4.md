# Challenge 03: write4

I am not sure if I should be concerned that the instructions list this as the 
_"first foray into propery gadget use"_. I would have told you we've been there 
with the last two challenges.

After going through the normal steps, I confirmed that the initial attack 
surface is the same... the `pwnme()` function allocates a buffer of length `32`, 
does a memset on it (all zeros), and then accepts in a string of up to `512` 
characters. This length gives us a little hint as to the complexity of the chain 
we are going to have to stitch together.

## Solution

OK... I've solved it (4 hours later). Lots of interesting learning here for me 
today. The first thing is minor yet helpful... that is the pwn tools `fit()` 
command. This is a helper function for building a payload. Rather than having to  
build a string by hand, it accepts a dictionary with the information you *must* 
have in the payload and some description of what you need, and it handles 
formatting and building it out. The solution file for the 64 bit version shows 
the use, but essentially it is a dictionary where the key is the index where a 
value should start and then the value to be placed there. You also indicate the 
length and it will fill in the rest with random junk.

The instructions suggest that there are multiple ways to solve this challenge. I 
ended up using the `/bin/cat flag.txt` option. To accomplish this, I needed to 
do the following:

1. store the command string - `/bin/cat flag.txt` in some location within memory
1. place the location (memory address) of that string in the `RDI` register
1. call `system()`

Conceptually, there isn't much to this. I used the helpful 
[CyberChef](http://icyberchef.com/) website to easily convert my command string 
to the hex representation. The resulting string was 17 bytes long, meaning it 
would take 3 qwords (3 stack entries) to get it into memory.  Using `ropper`, I 
found a couple of helpful gadgets. The first is `pop r14; pop r15; ret` which, 
when paired with the second: `mov qword ptr [r14], r15; ret;` makes a pretty 
handy tool. You can call the first to place an address in r14 and a value in 
r15. Calling the second then moves the value in r15 to the location specified by 
r14. Calling this pair repeatedly allows you to build up a long string, 8 
bytes/characters at a time.

The next question, as suggested by the challenge instructions, is to figure out 
*where* to put it. Running `readelf -S <exe>` provides insight into the file 
sections and their permissions. Evaluating those with a `W` indicating write 
access gives you only a few that are long enough. I tried writing to the data 
section with success, but it is only 16 bytes long and cannot hold the command 
string. I also experimented with the dynamic section but this failed (I may have 
done something wrong). I ended up overwriting part of the GOT - ensuring to 
*not* touch the part of the GOT that contained the resoution for the `system()` 
call I was planning on using.

Having written the command string, I simply put the address into RDI via a `pop 
rdi; ret;` gadget followed by the address to a `call system` location within the 
program.

> NOTE: I lost alot of time attempting to bind directly to system within the 
> GOT. My understanding is that this *should* work, but it clearly doesn't (at 
> least, not as I'm calling it). I need to dig into this more and understand.

The solution is available in [exploit_03.py](https://github.com/argodev/study/blob/main/src/ropemporium/exploit_03.py).

## 32-bit solution

The 32 bit solution is similar to the 64 bit version, but some of the utilized 
gadgets are different. We started with a `mov dword ptr [edi], ebp; ret;` and a 
handy `pop edi; pop ebp; ret;`

With these primitives, the process is fairly straight-forward. I ended up using 
the `.bss` section to store the data as the other sections weren't quite big 
enough due to the nature of 32 bit structures vs. 64 bit structures. Similarly, 
it took 5 "loops" through the "load into registers, move from register to point" 
process to get the entire command string in place. Once this was done, calling 
it was easy.

The solution is available in [exploit_0332.py](https://github.com/argodev/study/blob/main/src/ropemporium/exploit_0332.py)


## What Did I Learn?

* Increased comfort with `pwntools` - specifically the `fit()` function for 
  crafting payloads
* The idea that you can stuff things (a small, limited amount) in memory already 
  owned by the file and, so long as you are careful, it may not blow up
* Increased understanding of the different file sections - `readelf()` and how 
  they work. Had some of this knowlege from Ben's 'server' challenge, but this 
  reinforced it

