#include <stdio.h>

int get_value() {
    return 7;
}

int main() {
    int value = get_value();
    printf("%d\n", value);
    return 0;
}
