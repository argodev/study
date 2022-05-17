#!/bin/sh

# build the x64 version
gcc -o hello_gcc_x64_stripped -s hello.c
gcc -o hello_gcc_x64_debug -g hello.c
clang -o hello_clang_x64_stripped -s hello.c
clang -o hello_clang_x64_debug -g hello.c


# build the x32 version
gcc -o hello_gcc_x32_stripped -s -m32 hello.c
gcc -o hello_gcc_x32_debug -g -m32 hello.c
clang -o hello_clang_x32_stripped -s -m32 hello.c
clang -o hello_clang_x32_debug -g -m32 hello.c




# get the disassembly from that file
objdump -d -Mintel hello_gcc_x32_stripped  >> hello_gcc_x32_stripped.asm
objdump -d -Mintel hello_gcc_x32_debug  >> hello_gcc_x32_debug.asm
objdump -d -Mintel hello_clang_x32_stripped  >> hello_clang_x32_stripped.asm
objdump -d -Mintel hello_clang_x32_debug  >> hello_clang_x32_debug.asm

objdump -d -Mintel hello_gcc_x32_stripped  >> hello_gcc_x32_stripped.asm
objdump -d -Mintel hello_gcc_x32_debug  >> hello_gcc_x32_debug.asm
objdump -d -Mintel hello_clang_x32_stripped  >> hello_clang_x32_stripped.asm
objdump -d -Mintel hello_clang_x32_debug  >> hello_clang_x32_debug.asm