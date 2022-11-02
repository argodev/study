# Fuzzing a Library

I had a project that presented me with a pre-compiled shared library (e.g. `*.so`) that I wanted to both audit and fuzz. The auditing was all done within Ghidra, but the fuzzing issue was a bit more complex. In support of this work, I decided to write a high-level walkthrough of fuzzing a shared library.

## Identifying a Target

My ultimate goal here is to develop some skills on fuzzing a non-instrumented (e.g. black-box) shared object. However, I thought I'd walk through the process gradually, starting with something that I could build and instrument (and verify), followed by an increasingly complex scenario.  I recently was doing an evaluation of a device that implemented the [IEC 61850](https://en.wikipedia.org/wiki/IEC_61850) [GOOSE](https://en.wikipedia.org/wiki/Generic_Substation_Events#Generic_Object_Oriented_Substation_Events) (Generic Object Oriented System Event) protocol which eventually led me to looking at [libiec61850](https://github.com/rwl/libiec61850).  This library is written in C and is reasonably straight-forward, so I determined it might be a good target for my little effort.  