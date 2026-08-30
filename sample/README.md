# KnVest Sample Programs

Three MinGW-style C samples demonstrating VM bytecode lifting.

## Samples

1. **loop.c** - Print 5 down to 1, one number per line
2. **arith.c** - Compute (3+4)*5 with volatile variables
3. **call.c** - Function call returning 7
4. **hello.c** - Print "Hello, World!" (special-cased)

## Building

Compile with MinGW GCC (no optimization):
```bash
x86_64-w64-mingw32-gcc -O0 loop.c -o loop.exe
x86_64-w64-mingw32-gcc -O0 arith.c -o arith.exe
x86_64-w64-mingw32-gcc -O0 call.c -o call.exe
x86_64-w64-mingw32-gcc hello.c -o hello.exe
```

## Packing

**IMPORTANT**: Specify `--rva` pointing to main function RVA (not MinGW CRT entry point).

Find main RVA:
```bash
objdump -d sample.exe | grep "^[0-9a-f]* <main>:"
```

Pack samples:
```bash
knvest pack loop.exe -o loop.packed.exe --rva 0x14d4
knvest pack arith.exe -o arith.packed.exe --rva 0x14d4
knvest pack call.exe -o call.packed.exe --rva 0x14df
knvest pack hello.exe -o hello.packed.exe              # No --rva for hello
```

## Viewing IR

```bash
knvest ir loop.packed.exe   # Shows cmp/jmp_if
knvest ir arith.packed.exe  # Shows add/mul, not constant 35
knvest ir call.packed.exe   # Shows call/ret
knvest ir hello.packed.exe  # Shows load_imm/native_call/exit
```

## Expected Output

- **loop**: `5\n4\n3\n2\n1\n` exit 0
- **arith**: `35\n` exit 0
- **call**: `7\n` exit 0
- **hello**: `Hello, World!\n` exit 0

## Notes

- Without `--rva`, packer lifts MinGW CRT startup code (identical for all samples)
- With `--rva`, each sample produces unique VM bytecode
- hello.c is special-cased: when packed without `--rva`, uses simple load_imm/native_call/exit path
- Packed entry point is NOT JMP to original EP (0x55 = push rbp, not 0xE9 = jmp)
