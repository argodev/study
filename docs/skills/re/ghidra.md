# Ghidra

Ghidra is "a software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate in support of the Cybersecurity mission". It was released as free and open source a few years ago (https://ghidra-sre.org/) and has exposed binary reverse engineering to many world-wide who would otherwise be unable to afford commercial tools such as IDA Pro.

I followed the [installation instructions](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/InstallationGuide.html) and left the version in `~/Downloads/ghidra_10.1.1_PUBLIC`.

Included with the distribution of Ghidra are some tutorials `<installdir>/docs/GhidraClass`. There are four classes available, ranging from beginner to advanced.

## Tutorials

### Beginner

- Install and Introduction
- Creating Projects
    - wrote my own little C program to use as the example program:
    
    ```c
    // Simple C program to display "Hello World"

    // Header file for input output functions
    #include <stdio.h>

    // Add a global to see how it shows up
    int MYGLOBAL;

    // main function
    int main() {
        printf("Hello World\n");

        // local variables
        int a, b;

        // interact with the global variable
        a = 10;
        b = 20;
        MYGLOBAL = a + b;
        printf("Value of a = %d, b = %d, and MYGLOBAL = %d\n", a, b, MYGLOBAL);

        return 0;
    }
    ```

    - I then build the program using the following, rather standard commands:

    ```bash
    gcc helloworld.c -o helloworld
    ```

- Importing/Exporting Programs
    - One thing I have failed to do in the past is the `Options -> Load External Libraries` option... this was helpful as it picked up `libc.so.6`. My guess is that this would be particularly helpful when evaluating an entire firmware(?)

- Customizing Tools
- Basic Code Analysis
    - Recommendation: take a layered approach. Do simple "auto analysis" first and then run "one-shots" later
    - Learn how to recognize and fix problems (use scripts) - This is a skill I need!
    - It was interesting to see how Ghidra decompiled my program...

    ```c
    undefined8 main(void) {
        puts("Hello World");
        MYGLOBAL = 0x1e;
        printf("Value of a = %d, b = %d, and MYGLOBAL = %d\n",10,0x14,0x1e);
        return 0;
    }
    ```

    - The compiler auto-optimized out the local variables. 
    - Ghidra used the hex-representation of some of the integers.
    - One key I picked up from the notes is that if, rather than individually closing all of the windows/tools to close ghidra, you instead choose `File --> Exit Ghidra`, it will save the state of all of your windows/tools and when you next launch the program, you will return to the same position.
    - After a bit of cleanup, the decompilation looks more like this:

    ```c
    int main(void) {
        puts("Hello World");
        MYGLOBAL = 30;
        printf("Value of a = %d, b = %d, and MYGLOBAL = %d\n",10,20,30);
        return 0;
    }
    ```

    - *interestingly*, as I looked at the disassembly, I noticed that the compiler had *not* optimized out the locals, but rather __Ghidra simply did__ in the decompilation step. Notice the "undefined" stack items in the code block below... additionally, at `0x00101181` and again at `0x00101188`, you see values being assigned to those locals, followed by the addition operation at `0x00101195` and the assignment to the global at `0x00101197`. This is *all lost* in decompilation.
    
    <figure markdown> 
        [![locals not interpreted correctly][1]][1]
    </figure>

    !!! warning
        I spent *way* too much time here, trying to figure out why ghidra's decompilation wouldn't match the disassembly. Further, I tried to see if there was a way in which I could, having analyzed the disassembly, force the decompilation to be better, yet to no avail. I need to look at this more later.

- Selections
- Basic code Markup
- Basic Decompiler
- Applying Data Types
- Navigation
- Searching
- Byte Viewer
- Basic Program Tree
- Symbol Table/Tree
- Function Graph
- Function Call Tree


  [1]: ../../assets/images/ghidra01.png