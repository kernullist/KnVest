// Expected output:
// 1x1=1
// 1x2=2
// 1x3=3
// 2x1=2
// 2x2=4
// 2x3=6
// 3x1=3
// 3x2=6
// 3x3=9

#include <stdio.h>

void print_char(char c) {
    putchar(c);
}

void print_digit(int n) {
    putchar('0' + n);
}

int main() {
    int i, j, product;
    for (i = 1; i <= 3; i++) {
        for (j = 1; j <= 3; j++) {
            product = i * j;
            print_digit(i);
            print_char('x');
            print_digit(j);
            print_char('=');
            if (product >= 10) {
                print_digit(product / 10);
                print_digit(product % 10);
            } else {
                print_digit(product);
            }
            print_char('\n');
        }
    }
    return 0;
}
