/*
 * partial_loop — educational sample for KnVest L4d partial virtualization.
 *
 * Build (MinGW): gcc -O0 -o partial_loop.exe partial_loop.c
 *
 * Verify L4d (Windows): knvest pack partial_loop.exe -o out.exe --partial --seed 0x14D02026
 *   Expected: IR shows mixed VM/native BBs with run_native; runtime prints 3/2/1, exit 0.
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
