# KnVest

Toy VM protector + IR viewer for your own PE64 binaries (educational/dev tool)

## What It Is

KnVest is an educational tool that demonstrates basic VM-based code protection for Windows PE64 executables. It provides:

1. A simple register-based virtual machine (VM)
2. A packer that wraps function code in VM bytecode
3. An IR viewer that pretty-prints VM bytecode as human-readable assembly

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

- **Minimal VM**: 16 registers, stack, simple opcodes (load, store, arithmetic, control flow)
- **Pack**: Virtualizes a function (default: entry point) and emits a modified PE
- **IR Display**: Pretty-prints VM bytecode with addresses and operands
- **Portable**: Written in Rust, runs on Linux/Windows, targets PE64

## Build

```bash
cargo build --release
```

The binary will be at `target/release/knvest` (or `knvest.exe` on Windows).

## Usage

### Pack an Executable

Wrap the entry-point function in VM protection:

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

Example output:

```
Address  | Opcode       | Operands
---------+--------------+---------
00000000 | load_imm     | r0, 0x48656c6c6f
00000009 | load_imm     | r1, 0x576f726c64
00000012 | native_call  | 0x1
0000001b | load_imm     | r0, 0x0
00000024 | exit         | r0
```

## VM Instruction Set

The VM supports the following operations:

| Opcode       | Description                                    |
|--------------|------------------------------------------------|
| `nop`        | No operation                                   |
| `load_imm`   | Load immediate value into register             |
| `load_mem`   | Load from memory into register                 |
| `store_mem`  | Store register to memory                       |
| `move`       | Copy value between registers                   |
| `add`        | Add two registers, store result                |
| `sub`        | Subtract two registers, store result           |
| `xor`        | XOR two registers, store result                |
| `cmp`        | Compare two registers, set flags               |
| `jmp`        | Unconditional jump                             |
| `jmp_if`     | Conditional jump based on flags                |
| `call`       | Call VM function (push return address)         |
| `ret`        | Return from VM function                        |
| `native_call`| Call native function by ID                     |
| `push`       | Push register onto VM stack                    |
| `pop`        | Pop from VM stack into register                |
| `exit`       | Exit VM with return code                       |

## Sample

The `sample/` directory contains a hello-world C program:

```c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```

### Building the Sample

**On Windows:**

```bash
# MinGW
gcc hello.c -o hello.exe

# Visual Studio
cl hello.c /Fe:hello.exe
```

**On Linux (cross-compile):**

```bash
# Install MinGW-w64
sudo apt-get install mingw-w64

# Compile for Windows x64
x86_64-w64-mingw32-gcc sample/hello.c -o sample/hello.exe
```

### Pack and Run

```bash
# Pack the executable
cargo run --release -- pack sample/hello.exe -o sample/hello_packed.exe

# View the IR
cargo run --release -- ir sample/hello_packed.exe

# Run on Windows
sample/hello_packed.exe
```

## Testing

Run all unit and integration tests:

```bash
cargo test
```

Tests cover:

- VM instruction execution semantics
- IR disassembly and pretty-printing
- PE file parsing and structure validation
- End-to-end pack and IR extraction

All tests run on Linux (no Windows runtime required for CI).

## Project Structure

```
src/
├── vm/          - Virtual machine implementation
│   ├── mod.rs
│   ├── opcode.rs   - Opcode definitions
│   └── machine.rs  - VM interpreter
├── ir/          - IR disassembly and display
│   └── mod.rs
├── pe/          - PE file parsing and packing
│   ├── mod.rs
│   ├── parser.rs   - PE64 parser
│   ├── packer.rs   - Function virtualization
│   └── test_pe.rs  - Minimal PE generator for tests
├── pack/        - High-level packing logic
│   └── mod.rs
├── cli/         - Command-line interface
│   └── mod.rs
├── main.rs      - CLI entry point
└── lib.rs       - Library exports

tests/
└── integration_test.rs

sample/
├── hello.c
└── README.md
```

## How It Works

1. **Parse PE**: Read the input PE64 file and locate the target function
2. **Translate**: Convert native x64 code to VM bytecode (simplified translation)
3. **Inject**: Embed VM bytecode and interpreter stub into the PE
4. **Redirect**: Patch the entry point to jump to the VM interpreter
5. **Execute**: At runtime, the VM interprets bytecode and produces the original behavior

The current implementation uses a toy translation for demonstration purposes. A real protector would perform full x64 instruction lifting.

## License

MIT License (see LICENSE file)

## Disclaimer

This is an educational tool for learning about code virtualization and PE file formats. Use only on your own binaries. Not intended for malicious use or to circumvent software protections.
