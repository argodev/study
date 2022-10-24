# Challenge 06: pivot

This one challenge was the reason I started this series. I knew I needed to 
understand ROP at a tactical level and I needed to have a working knowledge of a 
a stack pivot. I could have told you what it was, but had not done it and 
therefore had no confidence in my ability to do so. That has all changed.

I blew an entire day on this challenge, and most of it was (as is normal) for 
dumb reasons. The actual problem solving portion wasn't too bad - especially if 
you read the instructions. Those instructions give you what is essentially a 
road map that you just need to follow.

## Approach

As hinted at above, there was quite a bit of stumbling around on this challenge 
and I've documented that below in the What Did I Learn section. Therefore, this 
section will simply present the solution and not all of the flailing.

If you run the program (or look at it in a debugger), you will see that there 
are many similarities to prior challenges. Within the `pwnme()` function 
however, there are two buffers (one allocated on the heap during `main()` and 
passed in as a parameter, and the second is the one we are used to. The first is 
quite large and the second is quite small. Worse, the `fgets()` call for the 
second is limited to 64 bytes. At 8-bytes per chain link, given an offset to 
`RSP` of 40 bytes already, you only have room in the main ROP exploit for three 
links.

When you run the program, it helpfully writes to the screen a pointer to a heap 
allocation that can serve as your pivot target. You are prompted first for what 
will end up being the second half of your payload...  your *"fake stack"* if you 
will.  You have a generous amount of space for this and can put in as many as 31 
links in the chain. Having provided this, you are the prompted for your stack 
smash, which can be no more than 64 bytes (only 24 are part of your chain).  
While you are prompted for the second part first, I'm going to walk through the 
first payload first followed by the second.

### Stack Smash

The objective of this stage is to take the address of our fake stack and put 
that in `rsp` and trigger a `ret`. Poking around with ropper looking for gadgets 
that will update `rsp`, I found the following: `xchg rax, rsp; ret;`. Excellent.  
Now, all I need is a `pop rax; ret;` and I'll be set. Thankfully, that was easy 
to find. The chain for the stack smash now resembled the following:

1. `pop rax; ret;`
1. Address of fake stack
1. `xchg rax, rsp; ret;`

### Fake Stack

Now that we have arrived at our fake stack, we need to call `ret2win()`. The 
problem is that this exists in a shared library. Further complicating things is 
that there are no calls in the main program to that shared library. Lastly, 
while there is a function call in the main program to one of the library
functions, it has not yet been called. This means, we have no idea what the real 
address of the `ret2win()` function is. Thankfully, we have some helpful hints 
in the instructions that will get us rolling.

We understand how the `.got` and `.got.plt` work (if not, the instructions hint 
at this). Our first call to `foothold_function()` will cause it to be resolved, 
thereby updating its entry in the `.got`. Therefore, we start by calling it. We 
then inspect its `.got` entry to get the actual memory address for that 
function. With this, we can calculate the location of the `ret2win()` function 
and then call it. Not surprisingly, the necessary gadgets are all present given 
just a little bit of looking around.

The final fake stack looks like the following:

1. func ptr to `foothold_function()` (plt)
1. `pop rax; ret;`
1. addr to `foothold_function()` (got)
1. `mov rax, qword ptr [rax]; ret;`
1. `pop rbp; ret;`
1. offset of `ret2win()` relative to `foothold_function()` in `libpivot.so`
1. `add rax rbp; ret;`
1. `call rax; ret;`

The solution is available in [exploit_06.py](https://github.com/argodev/study/blob/main/src/ropemporium/exploit_06.py)


## What Did I Learn?

As with each of these, many things. Some of them include:

* The built-in-to-the-exoloit-template debugging support is pretty good. If you 
  simply run `$ ./exploit.py GDB` it will automatically launch your program with 
  the debugger attached via a remote connection. What is *particularly helpful*, 
  is the `gdbscript` section of the template. Here you can place commands just 
  like you would in your `.gdbinit` file such as the breakpoints you want 
  created every time you launch. Finding this was *very* helpful as I ran the 
  debugger over, and over, and over again.
* The feature above is great... but not perfect. I had some *weird* things going 
  on during my debugging that I couldn't quite explain. Attaching to a *local 
  process* solved some of those. I found someone's solution online where they 
  used had a line that wrote out the PID of the running program followed by a 
  line that was commented out but included `util.proc.wait_for_debugger(pid)`.  
  This is a very handy feature of the pwntools framework that will pause the 
  script at that point until you attach with gdb. All you do is open a new 
  terminal window, type `gdb -p <pid>` and you are set. This differs from the 
  prior step in that it is all local and not running over a remote port... some 
  things will behave differently in this situation.
* What both of the prior items have in common is that they solve a problem that 
  I spent a couple of hours trying to solve... how do I run gdb with two 
  different external input files... especially when the second needs to be 
  generated with data that is only available after the program has started 
  running? I would love to say that I came up with a great solution for this, 
  but I didn't. It is easy to start the program (`gdb ./program`) and then run 
  it with an input data set (`(gdb) r < input.dat`) but there doesn't appear to 
  be a way of doing that with a second set of data. If you use either of the 
  approaches listed above, they both work. You will be set. Use them.
* There is a difference within pwntools using `io.write()` and `io.writeline()`.  
  This is an obvious statement as the name implies that the latter appends a 
  `\n` to the end (it does). I lost a fair bit of the day due to my using the 
  former (no good reason) and it not ending the input. This was complicated by 
  my inexplicable desire to send a *full* chunk of data (all that the buffer 
  could possibly hold) and, when adding the `writeline()` variant, it pushed it 
  over the max char length and messed up some of the subsequent registers.
* Adding `DEBUG` to the end of your exploit call (e.g. `> ./exploit.py DEBUG`) 
  will cause it to log in debug mode. This is helpful as you can see additional 
  information. As I got near the end of the problem, I was convinced it was 
  working, but I couldn't see the output key. Enabling debug made it very clear 
  that I was parsing the "here's your key" line incorrectly... I was succeeding, 
  but not knowing I was.
* I now understand how the `.got` and `.got.plt` tables work. This was hinted at 
  during a prior challenge, but you could skirt around it. In this challenge, 
  you had to understand that you had to trigger a call to get the resolution to 
  work so that you would then have the `.got.plt` updated with a pointer to the 
  actual function loaded into memory in the shared library. Understanding this 
  was crucial to completing this exploit.
  
## 32-Bit Solution

After solving the 64 bit version, this one was easy. The same gadgets were 
available and the process was exactly the same. The only work to be done was to 
tailor for the 32-bit architecture and look up the proper gadgets and addresses.

The solution is available in [exploit_0632.py](https://github.com/argodev/study/blob/main/src/ropemporium/exploit_0632.py)

