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
- **Pack**: Lifts `main` and CFG-reachable callees into VM bytecode; new PE entry is the interpreter stub (`0x55` = `push rbp`, not a JMP-to-OEP trampoline)
- **IAT native calls (L3)**: Parses the PE import directory; `call [rip+IAT]` to `puts`/`printf`/etc. emits `native_call` with win64 ABI (rcx/rdx/r8/r9 + shadow space) via the real IAT slot
- **CFG function collection (L3)**: BFS over direct near calls from the entry function instead of the old “main-front + push rbp only” heuristic; prologue-less entries accepted when reachable
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

To specify a custom function RVA (lifts that function and all CFG-reachable callees within `.text`):

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
00000024 | native_call  | 0x100000030
0000002d | load_imm     | r0, 0x0
00000036 | exit         | r0
```

`native_call` values `0x100000000 | iat_rva` invoke the imported function through the IAT with win64 calling convention. Legacy helpers remain: `1` = WriteFile string, `2` = integer print, `3` = putchar.

## Runtime Model

1. **Parse PE** — locate `main` (or use `--rva`), parse import directory / IAT
2. **CFG collect** — BFS from entry over direct `call rel32` targets in `.text`
3. **Lift** via iced-x86 → VM opcodes; IAT thunks (`call [rip+disp]`) → IAT `native_call`; CRT startup imports (`__main`, `_initterm`, …) skipped by name
4. **Inject** `.knvest` section: x64 interpreter stub + `VMBC` + bytecode
5. **Redirect** EP to stub (first byte `0x55`)
6. **Execute**: stub interprets bytecode; I/O via IAT win64 `native_call` or legacy helpers

Overwriting the original EP bytes with `0xCC` still works.

**Cmp / branches**: ZF/SF/CF/OF stored x64-style; `jmp_if` uses native Jcc semantics on restored flags.

## Sample Programs

Eight MinGW-style C samples in `sample/`:

| Sample        | Behavior |
|---------------|----------|
| `hello`       | `printf("Hello, World!\n")` — legacy native_call 1 or IAT printf when resolved |
| `puts_hello`  | **`puts("IAT puts hello")` — documents IAT win64 native_call path** |
| `loop`        | Countdown loop |
| `arith`       | Arithmetic |
| `call`        | Internal calls |
| `nested`      | Nested loops, putchar |
| `fact`        | Recursive factorial |
| `str`         | LoadByte string walk |

### Building Samples (Windows / MinGW)

```bash
x86_64-w64-mingw32-gcc sample/hello.c -o sample/hello.exe
x86_64-w64-mingw32-gcc sample/puts_hello.c -o sample/puts_hello.exe
x86_64-w64-mingw32-gcc -O0 sample/loop.c -o sample/loop.exe
# ... arith, call, nested, fact, str
```

### Pack and Run (Windows)

```bash
knvest pack sample/puts_hello.exe -o sample/puts_hello_packed.exe
knvest ir sample/puts_hello_packed.exe    # expect native_call 0x10000xxxx (puts IAT RVA)
sample\puts_hello_packed.exe              # IAT puts hello
```

Regression samples (hello, loop, arith, call, nested, fact, str) must still pack/ir/run with the same stdout as before.

## Testing

```bash
cargo test
```

Tests cover IAT parse/resolve, CFG collection, `--rva` packing, VM semantics, stub invariants, and integration pack→IR. Unit tests run on Linux without a Windows runtime.

## Project Structure

```
src/
├── vm/          - Virtual machine (reference interpreter for tests)
├── ir/          - IR disassembly and display
├── pe/
│   ├── parser.rs
│   ├── imports.rs  - PE import directory / IAT resolution
│   ├── cfg.rs      - CFG-based function collection
│   ├── lifter.rs   - iced-x86 lifter → VM bytecode
│   ├── vm_stub.rs  - x64 interpreter stub generator
│   └── packer.rs
├── pack/
├── cli/
└── main.rs

sample/          - hello, puts_hello, loop, arith, call, nested, fact, str
tests/
```

## License

MIT License (see LICENSE file)

## Disclaimer

Educational tool for learning about code virtualization and PE file formats. Use only on your own binaries. Not intended for malicious use.
