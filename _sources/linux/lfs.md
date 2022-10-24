# Linux From Scratch

> "Persistence makes all the difference (and a high frustration threshold certainly helps). As in all endeavors, learning from mistakes is critically important. Each misstep, every failure contributes to the body of knowledge that will lead to mastery of __the art of building software__."
(from https://tldp.org/)

Started 13 December 2021

Working on version 11.0, published 01 September 2021

Plan is to work through the book taking the "default" paths at each choice (64-bit, x64). Will consider the  systemd variant as well as the multilib (32/64) option later (https://www.linuxfromscratch.org/~thomas/multilib/index.html).

Based on the Forward, I read this: https://tldp.org/HOWTO/Software-Building-HOWTO.html. I'm not sure I learned anything really new, but it exposed me to some history re: building software for Linux (1999). I did skim through the examples (section 9-13) as they were so dated as to likely not provide significant value.

Another forward-inspired read: http://moi.vonos.net/linux/beginners-installing-from-source/. This was approximately 15 years newer, but still 6+ years old. I apreciated the discussion of `configure` and `make` as well as `Makefile.in` and `autotools`. I also like the explanation/justification for the `./build` directory (keeping src dir clean).

## To Investigate Further:

- `setuid root`; `chmod u+s filename`
