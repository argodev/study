# Crackme 0x03

This is identical in form to the prior two challenges - only the passcode is 
different. If you follow the same steps, open in Ghidra, the solution is clear.

Also, the passcode is identical to that of `0x02`. The difference here is that 
the check occurs in a function (`test()`) and the return values within `test()` 
are obfuscated. I presume that the author was trying to prevent you from running 
`strings` against the app and working from there. 

Passcode is `338724` or (`0x52b24`)

Solution is available in [crackme0x03.py](https://github.com/argodev/study/blob/main/src/ioli/crackme0x03.py)

