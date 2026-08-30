# Testing Instructions

## Automated Tests

Run all tests (works on Linux, no Windows required):

```bash
cargo test
```

This runs:
- 13 unit tests covering VM, IR, PE parsing, and packing logic
- 2 integration tests for end-to-end workflows
- All tests verify bytecode contains real VM opcodes

## Manual Testing on Windows

### Prerequisites

On Windows, install MinGW-w64:

```powershell
# Using chocolatey
choco install mingw

# Or download from: https://www.mingw-w64.org/
```

### Build the Sample

```bash
# In the sample/ directory
x86_64-w64-mingw32-gcc hello.c -o hello.exe

# Or on Windows with MinGW
gcc hello.c -o hello.exe
```

### Test Original Executable

```bash
# Run original
./sample/hello.exe
# Expected output: Hello, World!
# Expected exit code: 0
```

### Pack the Executable

```bash
# Build knvest
cargo build --release

# Pack the executable
./target/release/knvest pack sample/hello.exe -o sample/hello_packed.exe

# Expected output: "Successfully packed..."
# Expected: Generates N bytes of VM bytecode message
```

### View IR

```bash
./target/release/knvest ir sample/hello_packed.exe
```

Expected output should show:
- Address column (e.g., `00000000`)
- Opcode column with actual VM opcodes: `load_imm`, `call`, `exit`
- Operands column with register numbers and hex values

Example:
```
Address  | Opcode       | Operands
---------+--------------+---------
00000000 | load_imm     | r0, 0x1000
00000009 | call         | 0x5
00000012 | exit         | r0
```

**NOT expected**: A listing full of `nop` or native x64 bytes like `0x48`, `0x83`, `0xc3`.

### Run Packed Executable

```bash
./sample/hello_packed.exe
```

Expected:
- Exit code: 0
- Stdout: `Hello, World!\n`
- No errors like `STATUS_INVALID_IMAGE_FORMAT` (0xC000007B)

### Verify PE Structure

On Windows with PE tools:

```bash
# Check PE validity (if you have dumpbin)
dumpbin /headers sample/hello_packed.exe

# Should show:
# - Valid PE32+ format
# - Additional .knvest section
# - Executable characteristics
```

## Expected vs Actual

### ✅ Success Criteria

1. `cargo test` passes (all tests)
2. Packed PE loads and runs on Windows
3. Packed PE prints "Hello, World!" with exit code 0
4. `knvest ir` shows actual VM opcodes (`load_imm`, `call`, `exit`)

### ❌ Failure Indicators

1. Packed PE fails to load (STATUS_INVALID_IMAGE_FORMAT)
2. IR viewer shows mostly `nop` or native bytes
3. Packed PE crashes or produces no output
4. Tests fail

## Troubleshooting

### Packed PE Won't Run

Check:
- File size increased (should be slightly larger than original)
- PE headers are valid (use PE viewer tool)
- Section alignment is correct (0x1000 for virtual, 0x200 for file)

### IR Shows Wrong Data

Check:
- `.knvest` section exists in packed PE
- `VMBC` marker is present in the section
- Bytecode extraction logic finds the marker

### Build Errors

- Ensure Rust 1.83+ is installed
- Clean build: `cargo clean && cargo build`
- Check dependencies in `Cargo.toml`
