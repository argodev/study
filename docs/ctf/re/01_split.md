# Challenge 01: split

I cannot take a ton of (read: none at all) credit for solving this one. It was 
here that I realized that while I conceptually (read: vague) understood ROP, I 
didn't understand it in any practical way - meaning... I couldn't do it.

It was through struggling with this challenge that I came across the writeup 
that is listed in the notes for this challenge. I point credit there. I will say 
that, having finished this walk-through, I was able to go on and solve challenge 
02 (callme) without any help... I understood what I needed to do.

The solution for the 64 bit version is in [exploit_01.py](exploit_01.py) and the 
32 bit solution is in [exploit_0132.py](exploit_0132.py)

## What Did I Learn?

It might be easier to list what I *didn't* learn on this challenge... this one 
was a big one for me as it was the first time the cooncept of ROP started to 
concretize in my head. Specific learnings included:

* How ROP actually works (not just the theory)
* The differences in 32 and 64 bit calling conventions (I didn't understand that 
  64 bit was register-based)
* Increased comfort with the tools

