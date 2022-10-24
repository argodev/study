# Crackme 0x04

After the last few challenges, this one stepped it up quite a bit (though still 
not bad). Rather than simply finding the code in the decompilation, you have to 
look through the disassembly/decompliation, understand the algorithm, and then 
devise a solution.

Unlike the challenges so far, this has multiple solutions. The algorithim takes 
in a string representation of a password. For each character, it converts it to 
a decimal (assuming the chars are 0-9) and then adds it to a running total. The 
numbers need to sum to `15` (`0xf`). Valid solutions include:

- 78
- 96
- 915
- 4443

Solution is available in [crackme0x04.py](https://github.com/argodev/study/blob/main/src/ioli/crackme0x04.py)

