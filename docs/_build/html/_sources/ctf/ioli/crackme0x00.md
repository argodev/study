# Crackme 0x00

Before anything else, I opened the crackme in Ghidra to get an idea of what it 
is.

Running `file` tells me its a 32-bit elf. Should have symbols, is *not* 
relocateable

running `checksec` confirms the architecture, only partial `relro`, no stack 
canary, `NX` *is* enabled, PIE is *not* enabled (`0x8048000`).

running `rabin2 -I` confirms the above... indicates that it likely has symbols 
and line numbers included.

open the program in ghidra

The decompilation is easy... main comes out clear. Looks like if you provide the 
value `250382` when asked for a password, you win. Testing now...

ran and confirmed.

Also spent some time getting comfortable with the pwntools exploit framework.  
This is helpful for a number of things, but in this case, for documenting the 
actual exploit. I have included this in [crackme0x00.py](https://github.com/argodev/study/blob/main/src/ioli/crackme0x00.py)

