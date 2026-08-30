# Second Fix Explanation - Why Section Data Was at Wrong Offset

## The Problem Observed

After first fix (commit 43f2529), Windows verification still failed:

```
Original hello.exe:
- 18 sections
- Last section: PointerToRawData=0x6C00, SizeOfRawData=0x200
- Entry point: 0x105F
- File size: 60170 bytes

Packed hello_packed.exe:
- 19 sections (added .knvest)
- .knvest section: PointerToRawData=0x6E00, SizeOfRawData=0x200
- Entry point: 0x16000 (redirected to .knvest)
- File size: 60722 bytes

BUT:
- Bytes at file offset 0x6E00: ALL ZEROS (no JMP stub!)
- VMBC marker: Found at file offset 60226 (near EOF)
- Result: STATUS_INVALID_IMAGE_FORMAT
```

## Why This Happened

The code calculated PointerToRawData correctly but then **appended data to EOF**:

```rust
// BROKEN CODE:
let new_pointer_to_raw = align_up(
    last_section.pointer_to_raw_data + last_section.size_of_raw_data,
    FILE_ALIGNMENT
);
// new_pointer_to_raw = 0x6E00

// ... create section header with PointerToRawData = 0x6E00 ...

// WRONG: Just append to end
pe.data.extend_from_slice(&section_data);  
// Appends at file offset 60170, not 0x6E00!
```

### File Layout (Broken)

```
Offset   Content
------   -------
0x0000   DOS header
0x0080   PE headers
0x0400   Section 0 data
...
0x6C00   Section 17 data (last section)
0x6E00   OVERLAY/DEBUG DATA (not our section!)
         (MinGW puts debug info here)
...
60170    [OUR SECTION DATA APPENDED HERE]
         E9 XX XX XX XX  (JMP stub)
         VMBC
         [bytecode]
60722    EOF
```

But section header says: PointerToRawData = 0x6E00
→ Windows loader looks at 0x6E00, finds zeros or overlay data
→ Entry point invalid → STATUS_INVALID_IMAGE_FORMAT

## The Fix

Check actual file size and adjust if overlays present:

```rust
// FIXED CODE:
let theoretical_raw_ptr = align_up(
    last_section.pointer_to_raw_data + last_section.size_of_raw_data,
    FILE_ALIGNMENT
);
// theoretical = 0x6E00

let actual_file_size = pe.data.len();
// actual = 60170

// IMPORTANT: If theoretical < actual, there's overlay data
let new_pointer_to_raw = if theoretical_raw_ptr < actual_file_size as u32 {
    // Use actual file size, aligned
    align_up(actual_file_size as u32, FILE_ALIGNMENT)
} else {
    theoretical_raw_ptr
};
// new_pointer_to_raw = align_up(60170, 512) = 60416

// Pad file to pointer location
while pe.data.len() < new_pointer_to_raw as usize {
    pe.data.push(0x00);
}
// File is now 60416 bytes

// NOW append section data
pe.data.extend_from_slice(&section_data);
// Appends at 60416, which matches PointerToRawData!
```

### File Layout (Fixed)

```
Offset   Content
------   -------
0x0000   DOS header
0x0080   PE headers
0x0400   Section 0 data
...
0x6C00   Section 17 data
0x6E00   OVERLAY/DEBUG DATA (preserved)
...
60170    [Original overlay continues]
60416    [OUR SECTION DATA - CORRECT LOCATION]
         E9 XX XX XX XX  (JMP stub at entry point)
         CC CC ... CC    (padding)
         VMBC            (marker)
         01 00 ... FF 00 (VM bytecode)
60928    EOF (60416 + 512)
```

Now:
- Section header PointerToRawData = 60416
- Section data IS at file offset 60416
- Entry point RVA 0x16000 → file offset 60416 → JMP stub ✅
- Windows loader finds valid code → PE loads ✅

## Test Coverage

Added `test_pack_pe_with_overlay`:

```rust
let pe_data = test_pe::create_pe64_with_overlay();
// Creates PE with 2 sections + 530 bytes of overlay

let original_size = pe_data.len();
let mut pe = PEFile::from_bytes(pe_data).unwrap();

pack_function(&mut pe, None).unwrap();

let section = pe.get_section(".knvest").unwrap();
let ptr = section.pointer_to_raw_data as usize;

// Verify section placed AFTER original file
assert!(ptr >= original_size);

// Verify entry point has JMP instruction
let stub_byte = pe.data[ptr];
assert_eq!(stub_byte, 0xE9);  // JMP opcode
```

This test verifies the fix works for PEs with overlays, like MinGW produces.

## Why Overlays Matter

Many real PE files have data after the last section:
- MinGW: Debug symbols (`/14`, `/91` sections)
- MSVC: `.debug$T`, `.debug$S` sections
- Linkers: Custom data, certificates, overlays

Our packer must:
1. Detect when theoretical pointer < actual file size
2. Place new section AFTER actual file end
3. Update PointerToRawData to match where we actually put the data

## Summary

**Before 84ea6bc**:
- PointerToRawData = 0x6E00 (inside overlay)
- Section data at file offset 60170 (EOF)
- Entry point → zeros → STATUS_INVALID_IMAGE_FORMAT ❌

**After 84ea6bc**:
- PointerToRawData = 60416 (after overlay)
- Section data at file offset 60416 (matches pointer)
- Entry point → JMP stub → Original entry → Works ✅

This fix is essential for packing real-world PE files with overlays or debug data.
