// Expected output:
// 6

#include <stdio.h>

int main() {
    const char *s = "knvest";
    int len = 0;
    while (s[len] != 0) {
        len++;
    }
    printf("%d\n", len);
    return 0;
}
