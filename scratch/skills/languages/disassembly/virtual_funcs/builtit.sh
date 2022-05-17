#!/bin/sh

g++ -m32 -fno-rtti -fno-exceptions -O1 reversing1.cpp -o reversing1
strip reversing1
