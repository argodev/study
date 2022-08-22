#include <stdio.h>
#include <stdlib.h>

int main() {
    // these are both signed!
    int account_balance = 0;
    int number_flags = 0;
    int total_cost = 0;

    do {
        account_balance = 1100;
        number_flags++;
        total_cost = 900*number_flags;
        if (total_cost <= account_balance) {
            account_balance = account_balance - total_cost;
        }
    } while (account_balance < 100000);

    printf("\nWhen the number of fake flags ordered is: %d\n", number_flags);
    printf("The resulting cost is %d\n", total_cost);
    printf("And our account balance will be %d\n", account_balance);
}