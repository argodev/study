#include <iostream>
#include <string>
#include "getopt.h"

using namespace std;

int main(int argc, char* argv[]) {
    option longopts[] = {
        {"number", optional_argument, NULL, 'n'},
        {"show-ends", optional_argument, NULL, 'E'},
        {0}
    };



    return 0;
}