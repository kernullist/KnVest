#include <stdio.h>

int main() {
    volatile int a = 3;
    volatile int b = 4;
    volatile int c = 5;
    volatile int result = (a + b) * c;
    printf("%d\n", result);
    return 0;
}
