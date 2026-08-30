# Critical Fix - Section Data Placement

## Problem Identified

Windows verification failed with:
1. **Packed PE won't load**: STATUS_INVALID_IMAGE_FORMAT (0xC000007B)
2. **Entry point has zeros**: File offset 0x6E00 (entry RVA 0x16000) contains all zeros
3. **VMBC at wrong location**: Found at EOF, not at PointerToRawData (0x6E00)
4. **IR extraction fails**: "No VM bytecode found in packed PE"

## Root Cause

The packer was **appending section data to EOF** instead of **writing it at PointerToRawData**.

```rust
// WRONG (previous code):
pe.data.extend_from_slice(&section_data);  // Just appends to end

// File layout became:
// [PE headers] [sections] [overlay/debug] [VMBC at EOF]
//                                ^
//                                0x6E00 has zeros (should have stub)
```

For MinGW PE with 18 sections and overlays:
- Last section: PointerToRawData=0x6C00, SizeOfRawData=0x200
- New section PointerToRawData: 0x6E00 (0x6C00 + 0x200)
- But file has overlay after 0x6E00
- Section data was appended at EOF instead

## Solution

Calculate correct file offset and pad/truncate as needed:

```rust
// Calculate theoretical pointer
let theoretical_raw_ptr = align_up(
    last_section.pointer_to_raw_data + last_section.size_of_raw_data,
    FILE_ALIGNMENT
);

// If file has overlays, use actual file size
let actual_file_size = pe.data.len();
let new_pointer_to_raw = if theoretical_raw_ptr < actual_file_size as u32 {
    align_up(actual_file_size as u32, FILE_ALIGNMENT)
} else {
    theoretical_raw_ptr
};

// Pad to pointer location
while pe.data.len() < new_pointer_to_raw as usize {
    pe.data.push(0x00);
}

// Truncate if needed (shouldn't happen but defensive)
if pe.data.len() > new_pointer_to_raw as usize {
    pe.data.truncate(new_pointer_to_raw as usize);
}

// NOW append section data at correct location
pe.data.extend_from_slice(&section_data);
```

## Verification

Added test `test_pack_pe_with_overlay`:
- Creates PE with 2 sections + overlay data
- Packs it
- Verifies:
  - New section PointerToRawData >= original file size
  - Entry point has JMP (0xE9) instruction
  - Bytecode extraction works

All 15 tests pass (was 13, added 2 for overlay handling).

## Expected Windows Results

With MinGW hello.exe (18 sections, overlays):

**Before fix**:
- Entry at 0x6E00: all zeros ❌
- VMBC: at EOF, not at 0x6E00 ❌
- IR: "No VM bytecode found" ❌
- Run: STATUS_INVALID_IMAGE_FORMAT ❌

**After fix**:
- Entry at aligned EOF: JMP stub (E9 XX XX XX XX) ✅
- VMBC: at PointerToRawData (after padding) ✅
- IR: Shows LoadImm, Call, Exit ✅
- Run: Loads and prints "Hello, World!" ✅

## Files Changed

- `src/pe/packer.rs`: Fixed `add_vm_section` to write at correct offset
- `src/pe/test_pe.rs`: Added `create_pe64_with_overlay` and test
- Tests: 13 → 15 unit tests (both new tests verify overlay handling)
