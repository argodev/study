# Crackme 0x05

At first blush, this solution looks nearly identical to that of `0x04`. And, if 
you do quickly evaluate it and do not try multiple variants, you may not notice 
the nuance.

Unlike the challenges so far, this has multiple solutions. The algorithim takes 
in a string representation of a password. For each character, it converts it to 
a decimal (assuming the chars are 0-9) and then adds it to a running total. The 
numbers need to sum to `16` (`0x10`). *However*, there is an additional 
requirement. Once the program confirms that the digits add up to 16, it then 
converts the digits as a unit (all together), and confirms that the LSB is not 
1. This means solutions such as `943` would fail, but `934` or `394` would pass.  
Valid solutions include:

- 88
- 934
- 394

Solution is available in [crackme0x05.py](https://github.com/argodev/study/blob/main/src/ioli/crackme0x05.py)

