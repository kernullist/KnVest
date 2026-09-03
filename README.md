# KnVest

Toy VM protector + IR viewer for your own PE64 binaries (educational/dev tool)

## What It Is

KnVest is an educational tool that demonstrates basic VM-based code protection for Windows PE64 executables. It provides:

1. A simple register-based virtual machine (VM)
2. A packer that lifts x64 code into VM bytecode and injects an in-process interpreter stub
3. An IR viewer that pretty-prints the embedded VM bytecode as human-readable assembly

**Language:** Rust  
**Target:** Windows x86-64 PE (PE32+)

## What It Is NOT

This is a toy/educational project, not a production-grade protector. It does NOT include:

- Commercial packer features (anti-debug, anti-VM, anti-dump)
- Sophisticated obfuscation (mutation, MBA, control-flow flattening)
- Full x64 instruction virtualization
- GUI, kernel drivers, or overlay packing
- Decompilation or LLVM/MLIR integration

## Features

- **Minimal VM**: 16 registers, call stack, data stack, opcodes (load, arithmetic, control flow, native helpers)
- **Pack**: Lifts `main` plus pre-main callees (functions starting with `push rbp`) into VM bytecode; new PE entry is the interpreter stub (`0x55` = `push rbp`, not a JMP-to-OEP trampoline)
- **IR Display**: Pretty-prints VM bytecode with addresses and operands
- **x64 lifter**: Uses [iced-x86](https://github.com/icedland/iced) to decode the lifted code window
- **Portable**: Written in Rust, runs on Linux/Windows for pack/IR; packed binaries run on Windows

## Build

```bash
cargo build --release
```

The binary will be at `target/release/knvest` (or `knvest.exe` on Windows).

## Usage

### Pack an Executable

Virtualize the detected `main` function (default: auto-detect) and write a new PE whose entry point runs the VM interpreter:

```bash
knvest pack input.exe -o output.exe
```

To specify a custom function RVA:

```bash
knvest pack input.exe -o output.exe --rva 0x1234
```

### View IR

Pretty-print the VM bytecode from a packed executable:

```bash
knvest ir output.exe
```

Example output (bytecode differs per sample):

```
Address  | Opcode       | Operands
---------+--------------+---------
00000000 | push         | r5
00000002 | move         | r5, r4
...
00000024 | native_call  | 0x2
0000002d | load_imm     | r0, 0x0
00000036 | exit         | r0
```

## Runtime Model

1. **Parse PE** and locate `main` (or use `--rva`)
2. **Lift** `main` and real pre-main callees (must start with `0x55`; CRT/`__main` are skipped) via iced-x86 → VM opcodes
3. **Inject** a `.knvest` section containing:
   - An x64 VM interpreter stub (opcode → handler VA table dispatch)
   - A `VMBC` marker followed by VM bytecode
4. **Redirect** the PE entry point to the stub (first byte `0x55`)
5. **Execute**: The stub interprets bytecode. Native helpers handle I/O:
   - `native_call 1` — WriteFile a string from VM registers (used when the lifter emits it from real x64, e.g. hello via `printf`)
   - `native_call 2` — print integer in `r2` with newline (1/2/3-digit branches)
   - `native_call 3` — putchar one byte from `r0`, no newline

Overwriting the original EP bytes with `0xCC` still works: the packed program does not depend on executing the original EP.

**Cmp / branches**: The interpreter stores x64-like flags (ZF/SF/CF/OF). `jmp_if` condition codes match x64 Jcc semantics (JE, JNE, JL, JLE, JG, JGE).

## Sample Programs

The `sample/` directory contains seven C programs exercised by the packer:

| Sample   | Behavior |
|----------|----------|
| `hello`  | `printf("Hello, World!\n")` — lifted like all other samples (no special path) |
| `loop`   | Countdown loop |
| `arith`  | Arithmetic |
| `call`   | Internal calls |
| `nested` | Nested loops, `putchar` via native_call 3 |
| `fact`   | Recursive factorial |
| `str`    | Walks embedded `knvest\0` string via LoadByte |

### Building Samples (Windows)

**MinGW:**

```bash
x86_64-w64-mingw32-gcc sample/hello.c -o sample/hello.exe
x86_64-w64-mingw32-gcc sample/loop.c -o sample/loop.exe
# ... same for arith.c, call.c, nested.c, fact.c, str.c
```

**MSVC (Developer Command Prompt):**

```bat
cl /Fe:hello.exe sample\hello.c
cl /Fe:loop.exe sample\loop.c
```

### Pack and Run (Windows)

```bash
knvest pack sample/hello.exe -o sample/hello_packed.exe
knvest ir sample/hello_packed.exe
sample\hello_packed.exe
```

Verify: EP starts with `0x55`, stdout matches original (CRLF/LF ok), exit code 0; patching original EP to `CC` still prints the same output.

## Testing

```bash
cargo test
```

Tests cover VM semantics, IR disassembly, PE parsing/packing, stub invariants (handler table, LoadByte rip-rel, WriteFile slot), and integration pack→IR workflow. Unit tests run on Linux without a Windows runtime.

## Project Structure

```
src/
├── vm/          - Virtual machine (reference interpreter for tests)
├── ir/          - IR disassembly and display
├── pe/
│   ├── parser.rs
│   ├── lifter.rs   - iced-x86 lifter → VM bytecode
│   ├── vm_stub.rs  - x64 interpreter stub generator
│   └── packer.rs
├── pack/
├── cli/
└── main.rs

sample/          - hello, loop, arith, call, nested, fact, str
tests/
```

## License

MIT License (see LICENSE file)

## Disclaimer

Educational tool for learning about code virtualization and PE file formats. Use only on your own binaries. Not intended for malicious use.
