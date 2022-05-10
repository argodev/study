#include <cstdio>

// create a function called absolute_value that returns the
// absolute value of its single argument

int absolute_value(int x) {
    int result = 0;
    if (x >= 0) {
        result = x;
    } else {
        result = x * -1;
    }
    return result;
}

int main(int argc, char** argv) {

    int my_num = -10;
    printf("The absolute value of %d is %d.\n", my_num, absolute_value(my_num));
}