#include <iostream>
#include <cstdlib>

struct Mammal {
    Mammal() { std::cout << "Mammal::Mammal\n"; }
    virtual ~Mammal() {}
    virtual void walk() { std::cout << "Mammal::walk\n"; }
};

struct Cat : Mammal {
    Cat() { std::cout << "Cat::Cat\n"; }
    virtual ~Cat() {}
    virtual void walk() { std::cout << "Cat::walk\n"; }
};

struct Dog : Mammal {
    Dog() { std::cout << "Dog::Dog\n"; }
    virtual ~Dog() {}
    virtual void walk() { std::cout << "Dog::walk\n"; }
};

struct Bird {
    Bird() { std::cout << "Bird::Bird\n"; }
    virtual ~Bird() {}
    virtual void fly() { std::cout << "Bird::fly\n"; }
};

// note: this may not be taxonomically correct
struct Bat : Bird, Mammal {
    Bat() { std::cout << "Bat::Bat\n"; }
    virtual ~Bat() {}
    virtual void fly() { std::cout << "Bat::fly\n"; }
};

int main(int argc, char** argv) {
    Bird* b;
    Mammal* m;

    if (rand() % 2) {
        b = new Bat();
        m = new Cat();
    } else {
        b = new Bird();
        m = new Dog();
    }

    b->fly();
    m->walk();

    return 0;
}