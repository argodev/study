#include <iostream>

using namespace std;

int main() {
    int thisisanumber;

    cout << "Please enter a number: ";
    cin >> thisisanumber;

    // dangerous... no validation of the input!123
    cout << "You entered: " << thisisanumber << "\n";
}