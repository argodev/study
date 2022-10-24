# Challenge 07: ret2csu

Landscape:

* gadget-lean environment
* call `ret2win()` to, well... win
* third argument to `ret2win()` must be `0xdeadcafebabebeef`
* they have mucked around with the `.got.plt` entries for the libc calls
* Maximum chain length: 17 links (136 bytes)

I started like I always do and confirmed the offset of the payload. As with the 
other 64-bit challenges, the payload starts at `40` bytes into the input.

I briefly thought about cheating... could I jump into some odd spot within 
`ret2win()`, bypassing all of the 3rd parameter checks and get it to read out 
the flag? Possibly, but I decided that this wasn't really the objective.  
Additionally, the disassembly makes it look like they did a little work to make 
this not quite as easy as it might otherwise be.

Interestingly, the `ret2win()` function doesn't *really* take three parameters 
like the instructions suggest... the values of the two registers normally used 
for parameters 1 (`rdi`) & 2 (`rsi`) are not needed/checked. The goal is, can 
    you put what you need to into `rdx` prior to the `ret2win()` call.

## Solution

The instructions hint that there *may be* more than one way to skin this cat. I 
read the paper they reference (on ret2csu) and then tried *really hard* to do it 
a different way. I was reasonably certain I could get there... but I didn't.  
They hint that they mess with the `.got.plt` table - which they do... but they 
missed one already-populated call... the one to `setvbuf()`. I spent a fair 
amount of time going to the rabbit hole of calculating the offset to this, 
finding that I could easily find the gadgets I needed in `libc.so.6`, but I 
couldn't find a way to get the address out of the `.got.plt` and do the math 
needed (subtraction) to then call something in that library... there simply 
weren't enough gadgets available. 

Having failed that, I went back to the paper, and figured out the basics of what 
I needed to do. I coded up the payload to use both gadgets (as recommended by 
the paper), confirmed that they were all getting set correctly (gdb debug), and 
then failed miserably with the completion/call to `ret2win()`. The problem is 
that the second gadget ends with a call to a function pointer, rather than a 
direct address. This means, rather than putting the address of your 
to-be-called-function in, say, `r12` and then letting it call it, you need to 
put your function address in memory some place, and then put the address of that 
into `r12`. Unfortunately, there are 0 gadgets available to help you do that. I 
once again pounded my head against the wall... convinced once again that I had 
solved the hard part, and was missing the easy part.

The solution came when I read something that suggested that one might try 
calling a function that effectively *does nothing*, and *doesn't mess with the 
registers* (particularly `rdx`). You can find such a function in the form of 
`_init()` which is, convienently referenced in the `.dynamic` section. So, if 
you provide the address of the reference in the dyhnamic section, the call in 
gadget2 will resolve to the actual `init()` which will then complete 
successfully and execution will continue. What this then means, is you need to 
prepare your chain so that the rest of the function we are abusing will complete 
successfully. This includes setting the value that gets put into rbx to 0x0 and 
the value going into rbp to 0x1. This way, when rbx gets incremented by 1 and 
then the two are compared, they will be equal and the jump will not be taken.  
You then have to provide a number of dummy entries to support the series of pop 
operations as we go through the end of the function. You then place the address 
of `ret2win()` at the end and everything works.

The solution is available in [exploit_07.py](https://github.com/argodev/study/blob/main/src/ropemporium/exploit_07.py)

## What Did I Learn?

I learned a *ton* more about the `.got.plt`, how it works, and how I can utilize 
gadgets found in the shared libraries referenced therein.

As is the intetion of the challenge, I learned quite a bit about the `ret2csu` 
solution and find it rather intersting as a "known present" primitive.

## 32-Bit Solution

This challenge did not have a 32-bit variant.
