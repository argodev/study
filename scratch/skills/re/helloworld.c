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