/*
 * partial_loop — educational sample for KnVest L4d partial virtualization.
 *
 * Build (MinGW): gcc -O0 -o partial_loop.exe partial_loop.c
 *
 * When packed, the seed selects loop basic blocks for VM lifting while
 * straight-line prologue/epilogue stay on native sleds (run_native).
 */
#include <stdio.h>

int main(void) {
    int i;
    for (i = 3; i >= 1; i--) {
        printf("%d\n", i);
    }
    return 0;
}
