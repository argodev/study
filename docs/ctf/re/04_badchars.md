# Challenge 04: badchars

I started this challenge just like all of the others. I used `pwntools` to 
generate an exploit template and then altered it to generate a cyclic of 512 
bytes and send it expecting the client to crash and to confirm the offset 
location. After disassembling, it became clear that the new-to-this-challenge 
`checkBadchars()` function is called *prior* to the `memcpy` into the undersized 
buffer. It appears to be altering characters in the input string if they match 
an existing buffer's character set. The only problem is that I don't see where 
that "filtering" buffer is being populated. Time to step into gdb to see what I 
can learn.

It is interesting to me, but the initilization of that array does *not* appear 
in the decompiled code within Ghidra, but it *does* show up in the disassembly 
as well as the gdb walk through. It is initilized to the following:

```
bic/ fns
```

Any of those characters (the fourth is a space) in the input string get 
converted to 0xeb.

```{Note}
_I'm a moron_... if I had a.) read all of the instructions (would have 
encouraged me to actually run the program) or b.) extracted strings from the 
program (`$ rabin2 -z ./badchars`) I would have see the very helpful 
explanation as to what characters are considered offlimits.
```

OK, having sorted that, I'm back to looking around at the binary and trying to 
figure out what I need to do, and how to solve it. There is our 
`usefulFunction()` with its call to `system()`, so I record that address.

Under the `usefulGadgets()` function, I see a `XOR byte ptr [r15], r14B; ret` 
which hints that I probably need to xor my known bads (or all) before sending 
and then xor them again to get them back.

Playing around a little with cyberchef clarifies my assumption that if I take my 
original command string `/bin/cat flag.txt` and `XOR` the bytes with a key like 
`0xff`, I can send them across the wire, get them into the buffer and then `XOR` 
them again (same key) and get my values back. This makes me wonder if I can do a 
for loop in assembly...

We also have the question of how to get the command into memory... I'm assuming 
some trick similar to what we did for the prior challenge (stuff in `bss` or 
`got`).

With just a little poking around I found a rop gadget to load two registers 
(`pop r12; pop r13; ret;`) as well as one to load data from one register to a 
pointer referred to by another (`mov qword ptr [r13], r12; ret;`) and assumed I 
was off to the races with *most* of the process... now I need to determine a 
location to store the data and a way to `xor` the data once in place.

Ok, I was able to get it working, but I think it is ugly.

Essentially, for each of the characters in the input string that were "bad 
chars", I `xor` them prior to sending and then again after they get there 
(bypassing the `checkBadchars()` check). the *ugly* part, is that I would have 
rather sent it all using xor encoding, transferred it into place, and then done 
a for-loop to work over each character. Instead, I explicitly xor only the chars 
that need it. As it stands, it too 417 out of 512 byte budget to get this to 
work and it feels... icky.

Anyway, the solution is avaiable in [exploit_04.py](https://github.com/argodev/study/blob/main/src/ropemporium/exploit_04.py)

## 32 Bit Solution

The 32 bit solution was rather straight forward after having solved the 64 bit 
version above and the prior 32 bit version. All I did was essentially combine 
the two scripts (with some mods) and it worked on the first go. The solution is 
available in [exploit_0432.py](https://github.com/argodev/study/blob/main/src/ropemporium/exploit_0432.py)

## What Did I Learn?

* A better understanding of XOR
* A view of how I might use a long string of commands (gadgets) to accomplish a 
  rather "simple" objective
* Comfort with CyberChef - simple but helpful utility to keep around

