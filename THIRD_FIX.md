# Third Fix - Preserve COFF Symbol Table and String Table

## Problem Identified (Windows Test of 77edbbd)

Good news:
- ✅ Entry point at 0xEC00 has JMP stub (E9 5A B0 FE FF)
- ✅ VMBC marker present
- ✅ `knvest ir` works - shows real VM opcodes

Bad news:
- ❌ Packed PE still STATUS_INVALID_IMAGE_FORMAT (0xC000007B)
- ❌ COFF symbol table corrupted at 0x6E00 (all zeros)
- ❌ String table size corrupted at 0xD100 (0x20020 instead of 0x1A0A)
- ❌ dumpbin fails: cannot find section names like `/14`, `/29` (string table broken)

## Root Cause

The section header **splice** was **inserting 40 bytes** and **shifting all subsequent data**:

```rust
// BROKEN CODE:
let section_table_offset = pe.sections_offset + (pe.num_sections as usize * 40);
pe.data.splice(section_table_offset..section_table_offset, section_header.iter().cloned());
// This INSERTS 40 bytes at offset ~0x458
// Everything after 0x458 shifts down by 40 bytes!
```

### What Gets Corrupted

MinGW PE layout:
```
0x000   DOS header
0x080   PE signature + COFF header
0x0B0   Optional header
0x200   Section table (18 sections = 720 bytes, ends at 0x4D0)
0x600   Section data starts (SizeOfHeaders)
...
0x6E00  COFF symbol table (PointerToSymbolTable in COFF header)
        1408 symbols, each 18 bytes
0xD100  COFF string table
        First u32 = 0x1A0A (size of string table)
        Contains section names: /14, /29, /91 etc.
```

When we splice at offset 0x458 (in section table):
- Symbol table moves from 0x6E00 → 0x6E28 (+40 bytes)
- But COFF header PointerToSymbolTable still says 0x6E00
- Loader looks at 0x6E00, finds wrong data
- String table references are off by 40 bytes
- Section names `/14` etc. can't be resolved
- Windows rejects the image

## Solution

Write section header **in-place** (overwrite slack space) instead of inserting:

```rust
// FIXED CODE:
let section_table_offset = pe.sections_offset + (pe.num_sections as usize * 40);

// Check slack space exists
if section_table_offset + 40 > pe.data.len() {
    return Err(PEError::InvalidPE("No space for new section header".to_string()));
}

// Overwrite slack space (do NOT shift data)
pe.data[section_table_offset..section_table_offset + 40]
    .copy_from_slice(&section_header);
```

### Why This Works

SizeOfHeaders is 0x600. Section table starts at 0x200, occupies 18*40 = 720 bytes (0x2D0), ending at 0x4D0. Adding one more section header (40 bytes) makes it 0x4F8, which is still < 0x600. There's slack space!

By overwriting the slack space instead of inserting:
- No data shifts
- PointerToSymbolTable at 0x6E00 stays valid
- String table at 0xD100 stays intact
- Section names resolve correctly
- PE structure remains valid

### Additional Safeguard

Removed truncate that could corrupt overlay:
```rust
// REMOVED:
if pe.data.len() > new_pointer_to_raw as usize {
    pe.data.truncate(new_pointer_to_raw as usize);
}
```

Now we only:
1. Write header in-place (no shift)
2. Pad from original EOF to new_pointer_to_raw
3. Append section data

**Never modify bytes in [0, original_file_size).**

## Expected Windows Results

With this fix:
- ✅ COFF symbol table at 0x6E00 intact (0x6C69662E = ".fil")
- ✅ String table size at 0xD100 = 0x1A0A (correct)
- ✅ dumpbin works - can resolve `/14`, `/29` section names
- ✅ PE loads: CreateProcess succeeds
- ✅ Prints "Hello, World!" with exit code 0
- ✅ `knvest ir` shows VM opcodes (already working)

## Test Coverage

Existing tests verify:
- Section header placement
- Bytecode extraction
- Entry point stub

This fix ensures we don't corrupt existing PE structures when adding sections.

## Key Principle

**Never insert data into a PE file** - only:
1. Overwrite slack/padding
2. Append to end
3. Update header pointers

Inserting shifts offsets and breaks internal references.
