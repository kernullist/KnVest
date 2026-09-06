# Windows Verification Checklist

This document outlines what to verify on Windows to confirm the packing fixes work correctly.

## Expected Behavior (Success Criteria)

### 1. Packed PE Loads ✅
```bash
sample/hello_packed.exe
```
**Expected**: 
- Exit code: 0
- Stdout: `Hello, World!`
- No error: STATUS_INVALID_IMAGE_FORMAT (0xC000007B)

### 2. IR Shows Real VM Opcodes ✅
```bash
knvest ir sample/hello_packed.exe
```
**Expected output format**:
```
Address  | Opcode       | Operands
---------+--------------+---------
00000000 | load_imm     | r0, 0x????
00000009 | call         | 0x5
00000012 | exit         | r0
```

**NOT expected**: 
- Listing full of `nop` opcodes
- Native x64 bytes like `[48 83 c3 55]`
- Empty output or error

### 3. PE Structure is Valid ✅

Using Windows PE tools (dumpbin, PE-bear, etc.):

```bash
dumpbin /headers sample/hello_packed.exe
```

**Verify**:
- Machine type: 8664 (x64)
- Magic: 20B (PE32+)
- Section count increased by 1
- New `.knvest` section exists
- Section characteristics: 0xE0000020 (code, execute, read, write)
- Entry point RVA points to `.knvest` section
- File size ~48 bytes larger than original (stub + bytecode + alignment padding)

### 4. Automated Tests Pass ✅

```bash
cargo test --release
```

**Expected**: 
- 15 unit tests pass (13 lib + 2 integration)
- 0 failures
- Tests verify:
  - Bytecode contains LoadImm, Call, Exit opcodes
  - .knvest section exists
  - Bytecode extraction works
  - Packed PE has valid structure

## What Was Fixed

### Before (First Attempt - Broken)
- Packed PE: STATUS_INVALID_IMAGE_FORMAT on Windows
- IR output: Mostly `nop` + native bytes
- Bytecode size: 41 bytes (hardcoded, unused)
- PE structure: Corrupted (section count wrong, headers not updated)

### After First Fix (Still Broken)
- Packed PE: Still STATUS_INVALID_IMAGE_FORMAT
- IR output: Error "No VM bytecode found in packed PE"
- Entry point: All zeros at file offset
- Problem: Section data appended to EOF, not written at PointerToRawData
- For PE with overlays: PointerToRawData points inside file, but data was at EOF

### After Final Fix (Should Work)
- Packed PE: Loads and runs correctly, prints "Hello, World!"
- IR output: Real VM opcodes (load_imm, call, exit)  
- Bytecode size: Varies based on entry point RVA (~21 bytes typical)
- PE structure: Valid PE32+ with proper headers and alignment
- Section data: Written at PointerToRawData, not appended to EOF
- Entry point: Contains JMP stub (E9 XX XX XX XX)
- Handles overlays: New section placed after actual file size if needed

### 5. L4b Add handler polymorphism (optional spot-check)

When comparing two packed builds that differ only by `--seed`, logical IR and stdout should match while native Add handler bytes in `.knvest` may differ.

```bash
knvest pack sample/hello.exe -o /tmp/a.exe --seed 0x8
knvest pack sample/hello.exe -o /tmp/b.exe --seed 0x9
knvest ir /tmp/a.exe > /tmp/ir_a.txt
knvest ir /tmp/b.exe > /tmp/ir_b.txt
fc /tmp/ir_a.txt /tmp/ir_b.txt
```

Expected: IR text identical (same mnemonics/operands); `.knvest` section bytes differ (wire shuffle + handler body selection).

**Variant selection (Add only, L4b):** read the pack seed from the embedded `KNV4` header (offset +5, 8-byte LE `u64`). Compute:

```
variant = splitmix64(seed ^ 0x504F4C59 ^ 3) % 3
```

where `3` is the canonical index of `Add` and `splitmix64` matches `opcode_map.rs`. The stub emits exactly one Add handler body for that variant; dispatch still uses the L4a wire-byte handler table (no runtime variant compare in the stub).

| Variant | Native sequence (equivalent) |
|---------|------------------------------|
| 0 | `mov rax,[src1]; add rax,[src2]` |
| 1 | `mov rax,[src1]; mov rbx,[src2]; lea rax,[rax+rbx]` |
| 2 | store `[src1]`→`dst`, reload `dst`, `add [src2]` |

To inspect handler bytes on Windows, disassemble the `.knvest` section (e.g. dumpbin /disasm or your favorite PE tool) and locate the handler table entry for the wire byte that encodes `add` for that seed.

## Technical Details

### Section Addition
- Name: `.knvest`
- Virtual alignment: 0x1000 (4096 bytes)
- File alignment: 0x200 (512 bytes)  
- Characteristics: 0xE0000020 (executable, readable, writable)

### Section Contents
1. **x64 Stub** (5 bytes):
   ```
   E9 XX XX XX XX    ; JMP rel32 to original entry point
   ```
2. **Padding**: 0xCC bytes to 16-byte boundary
3. **Marker**: `VMBC` (4 bytes)
4. **Bytecode**: VM opcodes (typically ~21 bytes)
5. **Padding**: 0x00 bytes to file alignment

### Bytecode Format
```
01 00 [8 bytes: original_entry_rva as u64]   ; LoadImm r0, <entry>
0B [8 bytes: 0x05]                            ; Call 0x5
FF 00                                         ; Exit r0
```

### Header Updates
1. **COFF Header** (PE offset + 4 + 2): Section count += 1
2. **Optional Header** (PE offset + 24 + 16): Entry point RVA = new section RVA
3. **Optional Header** (PE offset + 24 + 56): Image size = aligned(new section end)
4. **Section Table**: New 40-byte section header appended

## Debugging Failed Tests

### If PE Won't Load
```bash
# Check PE validity
dumpbin /headers sample/hello_packed.exe | findstr "magic machine entry"

# Expected:
#   20B magic # (PE32+)
#   8664 machine (x64)
#   entry point RVA should be in .knvest section range
```

### If IR Shows Wrong Opcodes
```bash
# Extract .knvest section manually
# Look for "VMBC" marker (hex: 56 4D 42 43)
# Bytecode follows immediately after marker

# First byte should be 01 (LoadImm opcode)
# Not 90 (nop) or 48/83/... (native x64)
```

### If Tests Fail
```bash
cargo test -- --nocapture
# Shows detailed test output
# Check which specific assertion failed
```

## L4c dispatch modes (table vs threaded)

Default packing uses **table** dispatch (unchanged from L4b/L4d). **Threaded** dispatch is opt-in.

### Table (default) — 8 samples + smoke

Pack and run the usual educational samples with default flags (no `--dispatch`):

```bash
knvest pack sample/hello.exe -o sample/hello_packed.exe
sample/hello_packed.exe
knvest ir sample/hello_packed.exe
```

**IR header** should include `L4c dispatch=table` and the usual opcode listing.

Repeat for the other default-table samples in `sample/` (fact, loop, IAT, nested, partial_loop, etc.).

### Threaded smoke

```bash
knvest pack sample/hello.exe -o sample/hello_threaded.exe --dispatch threaded
knvest ir sample/hello_threaded.exe
sample/hello_threaded.exe
```

**Expected**: `L4c dispatch=threaded` in IR header; same logical opcodes as table mode; executable runs with exit code 0.

### Threaded + partial (if feasible)

```bash
knvest pack sample/partial_loop.exe -o sample/partial_loop_threaded.exe \
  --partial --dispatch threaded --seed 0x14D02026
knvest ir sample/partial_loop_threaded.exe
sample/partial_loop_threaded.exe
```

**Expected**: partial IR header shows `dispatch=threaded`; `run_native` / `bail_native` sled paths still present; program behavior matches table partial pack.

## Contact

If verification fails on Windows with this fixed version, provide:
1. `knvest ir sample/hello_packed.exe` full output
2. Error message when running hello_packed.exe
3. `dumpbin /headers sample/hello_packed.exe` output (sections + entry point)
4. File sizes: hello.exe vs hello_packed.exe
