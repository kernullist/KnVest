/*
 * KnVest L3 IAT sample — prints via puts() through the import table.
 *
 * When packed, the lifter should emit native_call with func_id >= 0x100000000
 * (IAT win64 ABI path) resolving msvcrt/ucrtbase puts, not native_call 1/2/3.
 *
 * Verify on Windows:
 *   x86_64-w64-mingw32-gcc sample/puts_hello.c -o sample/puts_hello.exe
 *   knvest pack sample/puts_hello.exe -o sample/puts_hello_packed.exe
 *   knvest ir sample/puts_hello_packed.exe
 *   sample/puts_hello_packed.exe
 *
 * Expected stdout: IAT puts hello\n
 * Expected IR: native_call 0x100000000... (IAT slot RVA for puts)
 */
#include <stdio.h>

int main(void) {
    puts("IAT puts hello");
    return 0;
}
