#!/bin/sh

g++ -m32 -fno-rtti -fno-exceptions -O1 reversing1.cpp -o reversing1
strip reversing1

g++ -m32 -fno-rtti -fno-exceptions reversing2.cpp -o reversing2
strip reversing2
