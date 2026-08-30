# KnVest Sample Programs

Seven MinGW-style C samples demonstrating VM bytecode lifting.

## Samples

1. **hello.c** - Print "Hello, World!" (special-cased)
2. **loop.c** - Print 5 down to 1, one number per line
3. **arith.c** - Compute (3+4)*5 with volatile variables
4. **call.c** - Function call returning 7
5. **nested.c** - Nested loops with character-by-character output (multiplication table 1-3)
6. **fact.c** - Recursive factorial(5) = 120
7. **str.c** - String byte walking to count length of "knvest"

## Building

Compile with MinGW GCC:
```bash
x86_64-w64-mingw32-gcc hello.c -o hello.exe
x86_64-w64-mingw32-gcc -O0 loop.c -o loop.exe
x86_64-w64-mingw32-gcc -O0 arith.c -o arith.exe
x86_64-w64-mingw32-gcc -O0 call.c -o call.exe
x86_64-w64-mingw32-gcc -O0 nested.c -o nested.exe
x86_64-w64-mingw32-gcc -O0 fact.c -o fact.exe
x86_64-w64-mingw32-gcc -O0 str.c -o str.exe
```

## Expected Output

- **hello**: `Hello, World!\n` exit 0
- **loop**: `5\n4\n3\n2\n1\n` exit 0
- **arith**: `35\n` exit 0
- **call**: `7\n` exit 0
- **nested**: `1x1=1\n1x2=2\n1x3=3\n2x1=2\n2x2=4\n2x3=6\n3x1=3\n3x2=6\n3x3=9\n` exit 0
- **fact**: `120\n` exit 0
- **str**: `6\n` exit 0

## VM Features Demonstrated

- **hello.c**: Special-cased string output via native_call 1 (WriteFile)
- **loop.c**: Countdown loop with conditional jumps and integer output
- **arith.c**: Arithmetic operations (add, mul) without constant folding
- **call.c**: Simple function call/return
- **nested.c**: Nested control flow, character output (native_call 3), manual digit formatting
- **fact.c**: Recursive function calls with VM call stack
- **str.c**: String literals, byte loads (LoadByte), pointer arithmetic

## Notes

- Use `--rva` to specify main function RVA when packing
- Packed entry point is `0x55` (push rbp), not `0xE9` (jmp)
- Each sample produces unique VM bytecode that reflects its control flow
- Recursion (fact.c) uses VM Call/Ret with proper stack management
- String operations (str.c) use LoadStr and LoadByte opcodes
