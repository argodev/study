# Reversing Virtual Functions

The following is a Ghidra-specific walk through of https://alschwalm.com/blog/static/2016/12/17/reversing-c-virtual-functions/


```c++
#include <cstdlib>
#include <iostream>

struct Mammal {
    Mammal() { std::cout << "Mammal::Mammal\n"; }
    virtual ~Mammal() { std::cout << "Mammal::~Mammal\n"; }
    virtual void run() = 0;
    virtual void walk() = 0;
    virtual void move() { walk();}
};

struct Cat : Mammal {
    Cat() { std::cout << "Cat::Cat\n"; }
    virtual ~Cat() { std::cout << "Cat::~Cat\n"; }
    virtual void run() { std::cout << "Cat::run\n"; }
    virtual void walk() { std::cout << "Cat::walk\n"; }
};

struct Dog : Mammal {
    Dog() { std::cout << "Dog::Dog\n"; }
    virtual ~Dog() { std::cout << "Dog::~Dog\n"; }
    virtual void run() { std::cout << "Dog::run\n"; }
    virtual void walk() { std::cout << "Dog::walk\n"; }
};

int main(int argc, char** argv) {
    Mammal *m;
    if (rand() % 2) {
        m = new Cat();
    } else {
        m = new Dog();
    }
    m->walk();

    delete m;

    return 0;
}
```

```bash
g++ -m32 -fno-rtti -fno-exceptions -O1 reversing1.cpp -o reversing1
strip reversing1

file reversing1
reversing1: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), \
    dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1] \ 
    =a0458157cf642fb4a793d7c402728b8771fe309d, for GNU/Linux 3.2.0, stripped
```

