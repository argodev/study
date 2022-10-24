# Crackme 0x01

For this one, I followed the exact same process as for 0x00. The result was 
exactly the same, but the password was different. The key here appears to be the 
desire of the author to ensure that you understand that the comparison check of 
the password (`0x149a`) is hex, and how to properly send that in.

The solution is provided in [crackme0x01.py](https://github.com/argodev/study/blob/main/src/ioli/crackme0x01.py). This is 
functionaly identical to the 0x00 variant except that I send the integer 
representation of the password as a string.
