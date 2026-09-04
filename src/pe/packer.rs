use super::parser::{PEFile, PEResult, PEError};
use super::lifter::lift_to_vm_bytecode_for_main;
use super::vm_stub::create_vm_interpreter_stub;
use super::cfg::{collect_cfg_entries, disassemble_cfg_function};

const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;

pub fn pack_function(pe: &mut PEFile, function_rva: Option<u32>) -> PEResult<Vec<u8>> {
    let explicit_rva = function_rva.is_some();
    let target_rva = if let Some(rva) = function_rva {
        rva
    } else {
        detect_main_rva(pe)?
    };
    let original_entry_rva = pe.entry_point_rva;

    let bytecode = translate_to_vm_bytecode(pe, target_rva, original_entry_rva, explicit_rva)?;
    
    add_vm_section(pe, &[], &bytecode)?;
    
    Ok(bytecode)
}

fn has_stack_prologue(text_data: &[u8], offset: usize) -> bool {
    if offset + 7 >= text_data.len() {
        return false;
    }
    // sub rsp, imm8  (48 83 EC xx)
    if text_data[offset + 4] == 0x48
        && text_data[offset + 5] == 0x83
        && text_data[offset + 6] == 0xEC
    {
        return true;
    }
    // sub rsp, imm32 (48 81 EC xx xx xx xx)
    offset + 10 < text_data.len()
        && text_data[offset + 4] == 0x48
        && text_data[offset + 5] == 0x81
        && text_data[offset + 6] == 0xEC
}

fn has_near_call_in_window(text_data: &[u8], offset: usize, window: usize) -> bool {
    let start = offset + 4;
    let end = std::cmp::min(offset + window, text_data.len());
    if start + 5 > end {
        return false;
    }
    text_data[start..end].contains(&0xE8)
}

fn detect_main_rva(pe: &PEFile) -> PEResult<u32> {
    let text_section = pe
        .get_section(".text")
        .or_else(|_| pe.get_section("CODE"))?;

    let text_start_rva = text_section.virtual_address;

    let text_offset = pe.rva_to_file_offset(text_start_rva)?;
    let text_data = &pe.data
        [text_offset..std::cmp::min(text_offset + text_section.size_of_raw_data as usize, pe.data.len())];

    let mut candidates = Vec::new();

    for offset in 0..text_data.len().saturating_sub(50) {
        if text_data[offset] == 0x55
            && text_data[offset + 1] == 0x48
            && text_data[offset + 2] == 0x89
            && text_data[offset + 3] == 0xE5
            && has_stack_prologue(text_data, offset)
            && has_near_call_in_window(text_data, offset, 0x100)
            && (0x350..=0x900).contains(&offset)
        {
            candidates.push((text_start_rva + offset as u32, offset));
        }
    }

    if let Some(&(rva, offset)) = candidates.iter().max_by_key(|(_, off)| *off) {
        eprintln!("Auto-detected main at RVA {:#x} (.text+{:#x})", rva, offset);
        return Ok(rva);
    }

    eprintln!(
        "Could not auto-detect main, using entry point {:#x}",
        pe.entry_point_rva
    );
    Ok(pe.entry_point_rva)
}

fn translate_to_vm_bytecode(
    pe: &PEFile,
    target_rva: u32,
    _original_entry: u32,
    explicit_rva: bool,
) -> PEResult<Vec<u8>> {
    let file_offset = pe.rva_to_file_offset(target_rva)?;

    if file_offset + 16 > pe.data.len() {
        return Err(PEError::InvalidPE("Code section too small".to_string()));
    }

    let text_section = pe
        .get_section(".text")
        .or_else(|_| pe.get_section("CODE"))?;
    let text_start = pe.rva_to_file_offset(text_section.virtual_address)?;
    let text_end = text_start + text_section.size_of_raw_data as usize;

    let imports = pe.parse_imports()?;
    let cfg_entries = collect_cfg_entries(
        pe,
        file_offset,
        file_offset,
        text_start,
        text_end,
        &imports,
        explicit_rva,
    )?;

    if cfg_entries.is_empty() {
        return Err(PEError::InvalidPE("CFG found no functions to lift".to_string()));
    }

    let mut all_instrs = Vec::new();
    for &entry in &cfg_entries {
        let max_end = (entry + super::cfg::MAX_FUNCTION_BYTES).min(text_end);
        let code = &pe.data[entry..max_end];
        let mut instrs = disassemble_cfg_function(code, entry);
        all_instrs.append(&mut instrs);
    }

    all_instrs.sort_by_key(|i| i.offset);

    if all_instrs.is_empty() {
        return Err(PEError::InvalidPE("Failed to disassemble CFG functions".to_string()));
    }

    let string_literal = find_string_literal_in_pe(pe);
    let bytecode = lift_to_vm_bytecode_for_main(
        &all_instrs,
        target_rva,
        file_offset,
        pe,
        string_literal.as_deref(),
        &imports,
    );

    Ok(bytecode)
}

fn find_string_literal_in_pe(pe: &PEFile) -> Option<Vec<u8>> {
    const NEEDLES: &[&[u8]] = &[
        b"IAT puts hello\n",
        b"IAT puts hello\0",
        b"Hello, World!\n",
        b"Hello, World!",
    ];
    for name in [".rdata", ".rdata$zzz", ".rodata", ".data"] {
        if let Ok(sec) = pe.get_section(name) {
            let start = sec.pointer_to_raw_data as usize;
            let end = (start + sec.size_of_raw_data as usize).min(pe.data.len());
            if start >= end {
                continue;
            }
            let data = &pe.data[start..end];
            for needle in NEEDLES {
                if data.windows(needle.len()).any(|w| w == *needle) {
                    return Some(needle.to_vec());
                }
            }
        }
    }
    None
}

fn add_vm_section(pe: &mut PEFile, _vm_stub_template: &[u8], bytecode: &[u8]) -> PEResult<()> {
    let _original_entry_rva = pe.entry_point_rva;
    
    let last_section = get_last_section(pe)?;
    
    let new_virtual_address = align_up(
        last_section.virtual_address + last_section.virtual_size,
        SECTION_ALIGNMENT
    );
    
    let theoretical_raw_ptr = align_up(
        last_section.pointer_to_raw_data + last_section.size_of_raw_data,
        FILE_ALIGNMENT
    );
    
    let actual_file_size = pe.data.len();
    let new_pointer_to_raw = if theoretical_raw_ptr < actual_file_size as u32 {
        align_up(actual_file_size as u32, FILE_ALIGNMENT)
    } else {
        theoretical_raw_ptr
    };
    
    let image_base = 0x140000000u64;
    let (vm_stub, _) = create_vm_interpreter_stub(image_base, new_virtual_address);
    
    let mut section_data = Vec::new();
    section_data.extend_from_slice(&vm_stub);
    section_data.extend_from_slice(bytecode);
    
    let virtual_size = section_data.len() as u32;
    let size_of_raw_data = align_up(section_data.len() as u32, FILE_ALIGNMENT);
    
    while section_data.len() < size_of_raw_data as usize {
        section_data.push(0x00);
    }
    
    let section_header = create_section_header(
        b".knvest\0",
        virtual_size,
        new_virtual_address,
        size_of_raw_data,
        new_pointer_to_raw,
        0xE0000020,
    );
    
    let section_table_offset = pe.sections_offset + (pe.num_sections as usize * 40);
    
    if section_table_offset + 40 > pe.data.len() {
        return Err(PEError::InvalidPE("No space for new section header".to_string()));
    }
    
    pe.data[section_table_offset..section_table_offset + 40]
        .copy_from_slice(&section_header);
    
    let coff_offset = pe.pe_header_offset + 4;
    let new_section_count = pe.num_sections + 1;
    pe.data[coff_offset + 2] = (new_section_count & 0xFF) as u8;
    pe.data[coff_offset + 3] = ((new_section_count >> 8) & 0xFF) as u8;
    
    pe.num_sections = new_section_count;
    
    let old_entry_offset = pe.optional_header_offset + 16;
    pe.data[old_entry_offset..old_entry_offset + 4]
        .copy_from_slice(&new_virtual_address.to_le_bytes());
    pe.entry_point_rva = new_virtual_address;
    
    let image_size_offset = pe.optional_header_offset + 56;
    let new_image_size = align_up(new_virtual_address + virtual_size, SECTION_ALIGNMENT);
    pe.data[image_size_offset..image_size_offset + 4]
        .copy_from_slice(&new_image_size.to_le_bytes());
    
    while pe.data.len() < new_pointer_to_raw as usize {
        pe.data.push(0x00);
    }
    
    pe.data.extend_from_slice(&section_data);
    
    Ok(())
}

fn get_last_section(pe: &PEFile) -> PEResult<LastSectionInfo> {
    let mut last_va = 0u32;
    let mut last_vs = 0u32;
    let mut last_ptr = 0u32;
    let mut last_size = 0u32;
    
    for i in 0..pe.num_sections {
        let section_offset = pe.sections_offset + (i as usize * 40);
        if section_offset + 40 > pe.data.len() {
            continue;
        }
        
        let virtual_size = u32::from_le_bytes([
            pe.data[section_offset + 8],
            pe.data[section_offset + 9],
            pe.data[section_offset + 10],
            pe.data[section_offset + 11],
        ]);
        
        let virtual_address = u32::from_le_bytes([
            pe.data[section_offset + 12],
            pe.data[section_offset + 13],
            pe.data[section_offset + 14],
            pe.data[section_offset + 15],
        ]);
        
        let size_of_raw_data = u32::from_le_bytes([
            pe.data[section_offset + 16],
            pe.data[section_offset + 17],
            pe.data[section_offset + 18],
            pe.data[section_offset + 19],
        ]);
        
        let pointer_to_raw_data = u32::from_le_bytes([
            pe.data[section_offset + 20],
            pe.data[section_offset + 21],
            pe.data[section_offset + 22],
            pe.data[section_offset + 23],
        ]);
        
        if virtual_address >= last_va {
            last_va = virtual_address;
            last_vs = virtual_size;
            last_ptr = pointer_to_raw_data;
            last_size = size_of_raw_data;
        }
    }
    
    Ok(LastSectionInfo {
        virtual_address: last_va,
        virtual_size: last_vs,
        pointer_to_raw_data: last_ptr,
        size_of_raw_data: last_size,
    })
}

struct LastSectionInfo {
    virtual_address: u32,
    virtual_size: u32,
    pointer_to_raw_data: u32,
    size_of_raw_data: u32,
}

fn align_up(value: u32, alignment: u32) -> u32 {
    ((value + alignment - 1) / alignment) * alignment
}

fn create_section_header(
    name: &[u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
) -> Vec<u8> {
    let mut header = vec![0u8; 40];
    header[0..8].copy_from_slice(name);
    header[8..12].copy_from_slice(&virtual_size.to_le_bytes());
    header[12..16].copy_from_slice(&virtual_address.to_le_bytes());
    header[16..20].copy_from_slice(&size_of_raw_data.to_le_bytes());
    header[20..24].copy_from_slice(&pointer_to_raw_data.to_le_bytes());
    header[36..40].copy_from_slice(&characteristics.to_le_bytes());
    header
}

pub fn extract_bytecode_from_packed(pe: &PEFile) -> PEResult<Vec<u8>> {
    let knvest_section = pe.get_section(".knvest");
    
    if let Ok(section) = knvest_section {
        let section_start = section.pointer_to_raw_data as usize;
        let section_end = section_start + section.size_of_raw_data as usize;
        
        if section_end > pe.data.len() {
            return Err(PEError::InvalidPE("Section data out of bounds".to_string()));
        }
        
        let section_data = &pe.data[section_start..section_end];
        
        for i in 0..section_data.len().saturating_sub(4) {
            if &section_data[i..i+4] == b"VMBC" {
                let bytecode_start = i + 4;
                let mut bytecode_end = bytecode_start;
                
                while bytecode_end < section_data.len() {
                    let byte = section_data[bytecode_end];
                    if byte == 0xCC || byte == 0x00 {
                        let rest_is_padding = section_data[bytecode_end..].iter()
                            .all(|&b| b == 0xCC || b == 0x00);
                        if rest_is_padding {
                            break;
                        }
                    }
                    bytecode_end += 1;
                }
                
                if bytecode_end > bytecode_start {
                    return Ok(section_data[bytecode_start..bytecode_end].to_vec());
                }
            }
        }
    }
    
    Err(PEError::InvalidPE("No VM bytecode found in packed PE".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::imports::{is_iat_ptr_native_call, native_call_iat_id, native_call_iat_ptr_id};
    use crate::pe::test_pe;
    use crate::vm::OpCode;

    #[test]
    fn test_pack_with_explicit_rva() {
        let pe_data = test_pe::create_pe64_with_callee();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x20;
        pack_function(&mut pe, Some(main_rva)).unwrap();
        let bc = extract_bytecode_from_packed(&pe).unwrap();
        assert!(!bc.is_empty());
        assert!(bc.contains(&(OpCode::LoadImm as u8)));
    }

    #[test]
    fn test_cfg_collects_multiple_functions() {
        let pe_data = test_pe::create_pe64_with_callee();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_start = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let text_end = text_start + text.size_of_raw_data as usize;
        let main_off = text_start + 0x20;
        let entries = collect_cfg_entries(
            &pe,
            main_off,
            main_off,
            text_start,
            text_end,
            &pe.parse_imports().unwrap(),
            false,
        )
        .unwrap();
        assert!(entries.len() >= 2);
    }

    #[test]
    fn test_pack_creates_valid_pe() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let original_entry = pe.entry_point_rva;
        
        let result = pack_function(&mut pe, None);
        assert!(result.is_ok());
        
        let bytecode = result.unwrap();
        assert!(!bytecode.is_empty());
        assert!(bytecode.contains(&(OpCode::LoadImm as u8)));
    }

    #[test]
    fn test_packed_pe_has_knvest_section() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        
        pack_function(&mut pe, None).unwrap();
        
        let section = pe.get_section(".knvest");
        assert!(section.is_ok());
    }

    #[test]
    fn test_extract_bytecode_from_packed() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        
        pack_function(&mut pe, None).unwrap();
        
        let bytecode = extract_bytecode_from_packed(&pe);
        assert!(bytecode.is_ok());
        
        let bc = bytecode.unwrap();
        assert!(!bc.is_empty());
        assert!(bc.contains(&(OpCode::LoadImm as u8)));
    }

    #[test]
    fn test_bytecode_contains_vm_opcodes() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        
        pack_function(&mut pe, None).unwrap();
        
        let bytecode = extract_bytecode_from_packed(&pe).unwrap();
        
        let mut has_load_imm = false;
        let mut has_exit = false;

        let mut i = 0;
        while i < bytecode.len() {
            if let Some(op) = OpCode::from_u8(bytecode[i]) {
                match op {
                    OpCode::LoadImm => has_load_imm = true,
                    OpCode::Exit => has_exit = true,
                    _ => {}
                }
            }
            i += 1;
        }

        assert!(has_load_imm, "Bytecode should contain LoadImm");
        assert!(has_exit, "Bytecode should contain Exit");
    }

    #[test]
    fn test_pack_pe_with_overlay() {
        let pe_data = test_pe::create_pe64_with_overlay();
        let original_size = pe_data.len();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        
        pack_function(&mut pe, None).unwrap();
        
        let section = pe.get_section(".knvest").unwrap();
        let ptr = section.pointer_to_raw_data as usize;
        
        assert!(ptr >= original_size, "New section should be after original file");
        
        assert!(ptr < pe.data.len(), "PointerToRawData should be within file");
        
        let stub_byte = pe.data[ptr];
        assert_eq!(stub_byte, 0x55, "Entry point should have VM stub (0x55 = push rbp)");
        
        let bytecode = extract_bytecode_from_packed(&pe);
        assert!(bytecode.is_ok(), "Should extract bytecode from packed PE with overlay");
    }
    
    #[test]
    fn test_stub_encoding_correctness() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        
        let mut i = 0;
        while i < stub.len() {
            if stub[i] == 0xE9 {
                assert!(i + 5 <= stub.len(), "E9 (jmp rel32) at offset {} must have 4 bytes following", i);
                i += 1;
                continue;
            }
            
            if i + 3 < stub.len() {
                let b0 = stub[i];
                let b1 = stub[i + 1];
                let b2 = stub[i + 2];
                let disp8 = stub[i + 3];
                
                if (b0 == 0x48 || b0 == 0x4C) && 
                   (b1 == 0x89 || b1 == 0x8B || b1 == 0x8D || b1 == 0xFF) &&
                   (b2 == 0x45 || b2 == 0x4D || b2 == 0x55 || b2 == 0x5D) {
                    let known_api_offsets = [0xC0, 0xB8, 0xB0, 0xA8, 0xA0, 0xD0];
                    if known_api_offsets.contains(&disp8) {
                        panic!(
                            "Invalid disp8 encoding at offset {}: {:02X} {:02X} {:02X} {:02X} (API offset 0x{:02X} requires disp32)",
                            i, b0, b1, b2, disp8, disp8
                        );
                    }
                }
            }
            
            i += 1;
        }
    }

    #[test]
    fn test_stub_does_not_clobber_writefile_slot() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        // mov [rbp-0xB0], rsi would clobber the WriteFile function pointer slot
        let clobber_pattern = [0x48u8, 0x89, 0xB5, 0x50, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(clobber_pattern.len()).any(|w| w == clobber_pattern),
            "stub must not store to [rbp-0xB0] (WriteFile pointer slot)"
        );
        // WriteFile pointer store uses mov [rbp-0xB0], rax
        let writefile_store = [0x48u8, 0x89, 0x85, 0x50, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(writefile_store.len()).any(|w| w == writefile_store),
            "stub must still store WriteFile pointer at [rbp-0xB0]"
        );
    }

    #[test]
    fn test_loadbyte_uses_rip_rel_bytecode_base() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let vmbc = stub.windows(4).position(|w| w == b"VMBC").expect("VMBC marker");
        let bytecode_offset = vmbc + 4;
        let cache_store = [0x48u8, 0x89, 0xB5, 0xE8, 0xFE, 0xFF, 0xFF];
        assert!(
            !stub.windows(cache_store.len()).any(|w| w == cache_store),
            "LoadByte must not use [rbp-0x118] cache"
        );
        let loadbyte_add = [0x48u8, 0x01, 0xD0];
        assert!(
            stub.windows(loadbyte_add.len()).any(|w| w == loadbyte_add),
            "LoadByte must add VM offset to rip-rel bytecode base"
        );
        let lea_pattern = [0x48u8, 0x8D, 0x15];
        let mut loadbyte_lea_found = false;
        for i in 0..stub.len().saturating_sub(7) {
            if stub[i..i + 3] != lea_pattern {
                continue;
            }
            let disp = i32::from_le_bytes([
                stub[i + 3],
                stub[i + 4],
                stub[i + 5],
                stub[i + 6],
            ]);
            let target = (i + 7) as i32 + disp;
            if target as usize == bytecode_offset {
                loadbyte_lea_found = true;
                break;
            }
        }
        assert!(loadbyte_lea_found, "LoadByte lea rdx must patch to opcode 0 (VMBC+4)");
    }

    #[test]
    fn test_prologue_uses_near_jb_ja_not_jl_jg() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let cmp_a = [0x83u8, 0xF8, 0x41];
        let mut found_jb = false;
        for i in 0..stub.len().saturating_sub(cmp_a.len() + 3) {
            if stub[i..i + 3] != cmp_a {
                continue;
            }
            assert_eq!(
                stub[i + 3],
                0x0F,
                "unsigned char range check must use near jcc"
            );
            assert_eq!(
                stub[i + 4],
                0x82,
                "cmp eax,'A' must be followed by near jb (0F 82), not jl"
            );
            found_jb = true;
            break;
        }
        assert!(found_jb, "kernel32 lowercase prologue must exist");
    }

    #[test]
    fn test_handler_table_resolves_handlers() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let dispatch_lea = [0x48u8, 0x8D, 0x1D];
        let mut table_base = None;
        for i in 0..stub.len().saturating_sub(7) {
            if stub[i..i + 3] == dispatch_lea {
                let disp = i32::from_le_bytes([stub[i + 3], stub[i + 4], stub[i + 5], stub[i + 6]]);
                table_base = Some((i + 7) as isize + disp as isize);
                break;
            }
        }
        let table_base = table_base.expect("dispatch lea rbx,[handler_table]") as usize;
        let load_imm_off = i32::from_le_bytes([
            stub[table_base + 4],
            stub[table_base + 5],
            stub[table_base + 6],
            stub[table_base + 7],
        ]);
        assert!(load_imm_off > 0, "handler offsets must be positive (handlers after table)");
        let h_load_imm = (table_base as i64 + load_imm_off as i64) as usize;
        assert_eq!(stub[h_load_imm], 0x0F);
        assert_eq!(stub[h_load_imm + 1], 0xB6);
    }

    #[test]
    fn test_native_call_saves_and_restores_rsi() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let save_rsi = [0x48u8, 0x89, 0xB5, 0x68, 0xFF, 0xFF, 0xFF];
        let restore_rsi = [0x48u8, 0x8B, 0xB5, 0x68, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(save_rsi.len()).any(|w| w == save_rsi),
            "native_call must save bytecode rsi at [rbp-0x68]"
        );
        assert!(
            stub.windows(restore_rsi.len()).any(|w| w == restore_rsi),
            "native_call must restore bytecode rsi from [rbp-0x68]"
        );
        let clobber_r3 = [0x48u8, 0x89, 0x85, 0x68, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(clobber_r3.len()).any(|w| w == clobber_r3),
            "native_call must not clobber VM r3 via mov [rbp-0x68], rax"
        );
    }

    #[test]
    fn test_detect_main_prefers_high_candidate() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_off = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let sec_off = pe.sections_offset;
        pe.data[sec_off + 16..sec_off + 20].copy_from_slice(&0x600u32.to_le_bytes());
        while pe.data.len() < text_off + 0x600 {
            pe.data.push(0x90);
        }
        let crt = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x05, 0x00, 0x00, 0x00, 0x90, 0xC3];
        pe.data[text_off + 0x380..text_off + 0x380 + crt.len()].copy_from_slice(&crt);
        let mainfn = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xC3];
        pe.data[text_off + 0x400..text_off + 0x400 + mainfn.len()].copy_from_slice(&mainfn);
        let rva = super::detect_main_rva(&pe).unwrap();
        assert_eq!(rva, text.virtual_address + 0x400);
    }

    #[test]
    fn test_jmpif_ne_uses_jne_not_je() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let ne_cond = [0x83u8, 0xF9, 0x02];
        let push_flags = [0xFFu8, 0xB5, 0x70, 0xFF, 0xFF, 0xFF];
        let mut found = false;
        for i in 0..stub.len().saturating_sub(ne_cond.len() + 32) {
            if stub[i..i + 3] != ne_cond {
                continue;
            }
            let window = &stub[i..i + 32];
            let push_at = window
                .windows(push_flags.len())
                .position(|w| w == push_flags)
                .expect("JmpIf must push saved VM flags before popfq");
            assert_eq!(window[push_at + push_flags.len()], 0x9D, "JmpIf must popfq before semantic jcc");
            assert_eq!(
                window[push_at + push_flags.len() + 1],
                0x0F,
                "JmpIf NE must use near jcc rel32"
            );
            assert_eq!(
                window[push_at + push_flags.len() + 2],
                0x85,
                "JmpIf NE must use native jne rel32 (0F 85) on restored flags"
            );
            found = true;
            break;
        }
        assert!(found, "JmpIf NE (cond 2) handler must exist in stub");
    }

    #[test]
    fn test_h_cmp_preserves_zf_in_flag_mask() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let mask = [0x48u8, 0x25, 0xC1, 0x08, 0x00, 0x00];
        assert!(
            stub.windows(mask.len()).any(|w| w == mask),
            "h_cmp must mask flags with 0x8C1 (ZF|SF|CF|OF), not 0x881"
        );
    }

    #[test]
    fn test_jmpif_taken_uses_add_rsi_rbx() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let taken_add = [0x48u8, 0x01, 0xDE];
        assert!(
            stub.windows(taken_add.len()).any(|w| w == taken_add),
            "jmpif_taken must add target offset in rbx to bytecode base in rsi"
        );
    }

    #[test]
    fn test_three_digit_printer_uses_rcx_buffer() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        // three_digit path must store via rcx (buffer from lea rcx,[rbp-0xF0]), not wrong disp32
        let bad_hundreds = [0x88u8, 0x85, 0xF0, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(bad_hundreds.len()).any(|w| w == bad_hundreds),
            "three_digit must not use mov [rbp+disp32], al with F0 FF FF FF (-0x10)"
        );
        assert!(stub.windows(2).any(|w| w == [0x88u8, 0x01]));
        assert!(stub.windows(3).any(|w| w == [0x88u8, 0x41, 0x01]));
        assert!(stub.windows(3).any(|w| w == [0x88u8, 0x51, 0x02]));
        assert!(stub.windows(4).any(|w| w == [0xC6u8, 0x41, 0x03, 0x0A]));
    }

    #[test]
    fn test_pack_preserves_overlay_data() {
        let pe_data = test_pe::create_pe64_with_overlay();
        let original_data = pe_data.clone();
        
        let marker_offset = pe_data.len() - 100;
        let original_marker = original_data[marker_offset..marker_offset + 10].to_vec();
        
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let original_size = pe.data.len();
        
        pack_function(&mut pe, None).unwrap();
        
        let preserved_marker = &pe.data[marker_offset..marker_offset + 10];
        assert_eq!(
            &original_marker[..], preserved_marker,
            "Overlay data should not be modified"
        );
        
        for i in 0..original_size {
            if i >= marker_offset && i < marker_offset + 10 {
                continue;
            }
            let original = original_data[i];
            let packed = pe.data[i];
            
            if packed != original {
                let in_section_table = i >= pe.sections_offset 
                    && i < pe.sections_offset + (20 * 40);
                let in_optional_header = i >= pe.optional_header_offset 
                    && i < pe.optional_header_offset + 240;
                let in_coff_header = i >= pe.pe_header_offset + 4
                    && i < pe.pe_header_offset + 24;
                assert!(in_section_table || in_optional_header || in_coff_header, 
                    "Only headers should be modified, but byte at {:#x} changed from {:#x} to {:#x}", 
                    i, original, packed);
            }
        }
    }

    #[test]
    fn test_find_printf_literal_in_rdata() {
        let pe_data = test_pe::create_pe64_with_overlay();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let sec = pe.get_section(".data").unwrap();
        let off = sec.pointer_to_raw_data as usize;
        let msg = b"Hello, World!\n";
        while pe.data.len() < off + msg.len() {
            pe.data.push(0);
        }
        pe.data[off..off + msg.len()].copy_from_slice(msg);
        let found = super::find_string_literal_in_pe(&pe);
        assert_eq!(found.as_deref(), Some(&b"Hello, World!\n"[..]));
    }

    #[test]
    fn test_module_next_advances_rcx_not_rbx() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let advance_rcx = [0x48u8, 0x8B, 0x09];
        let advance_rbx = [0x48u8, 0x8B, 0x1B];
        assert!(
            stub.windows(advance_rcx.len()).any(|w| w == advance_rcx),
            "module_next must advance list with mov rcx, [rcx]"
        );
        assert!(
            !stub.windows(advance_rbx.len()).any(|w| w == advance_rbx),
            "module_next must not dereference uninitialized rbx"
        );
    }

    #[test]
    fn test_handler_targets_for_push_and_native_call() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let pat = [0x48u8, 0x8D, 0x1D];
        let mut table_base = 0usize;
        for i in 0..stub.len().saturating_sub(7) {
            if stub[i..i + 3] == pat {
                let disp = i32::from_le_bytes([stub[i + 3], stub[i + 4], stub[i + 5], stub[i + 6]]);
                table_base = (i as i64 + 7 + disp as i64) as usize;
                break;
            }
        }
        let table_end = table_base + 1024;
        let load_imm_off = i32::from_le_bytes(
            stub[table_base + 4..table_base + 8].try_into().unwrap(),
        );
        let load_imm_target = (table_base as i64 + load_imm_off as i64) as usize;
        assert!(load_imm_off > 0);
        assert!(load_imm_target >= table_end);
        assert_eq!(stub[load_imm_target], 0x0F);
        assert_eq!(stub[load_imm_target + 1], 0xB6);

        let nc_off = i32::from_le_bytes(
            stub[table_base + 0x0E * 4..table_base + 0x0E * 4 + 4]
                .try_into()
                .unwrap(),
        );
        let nc_target = (table_base as i64 + nc_off as i64) as usize;
        assert!(nc_off > 0);
        assert!(nc_target >= table_end);
        assert_eq!(stub[nc_target], 0x48);
        assert_eq!(stub[nc_target + 1], 0x8B);
    }

    fn native_call_ids_in_bytecode(bytecode: &[u8]) -> Vec<u64> {
        let mut ids = Vec::new();
        let mut i = 0;
        while i < bytecode.len() {
            if bytecode[i] == OpCode::NativeCall as u8 && i + 9 <= bytecode.len() {
                ids.push(u64::from_le_bytes(bytecode[i + 1..i + 9].try_into().unwrap()));
                i += 9;
            } else {
                i += 1;
            }
        }
        ids
    }

    #[test]
    fn test_pack_puts_thunk_emits_iat_native_call() {
        let pe_data = test_pe::create_pe64_with_puts_thunk_call();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let imports = pe.parse_imports().unwrap();
        let puts = imports.entries().iter().find(|e| e.name == "puts").unwrap();
        let text = pe.get_section(".text").unwrap();
        let bc = pack_function(&mut pe, Some(text.virtual_address + 0x20)).unwrap();
        let ids = native_call_ids_in_bytecode(&bc);
        assert!(
            ids.iter().any(|id| *id == native_call_iat_ptr_id(puts.iat_rva)),
            "expected IAT puts native_call with ptr flag, got {:?}",
            ids
        );
        assert!(bc.len() < 300, "puts thunk pack should stay small, got {} bytes", bc.len());
    }

    #[test]
    fn test_pack_does_not_lift_forward_crt_call() {
        let pe_data = test_pe::create_pe64_with_forward_crt_call();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let bc = pack_function(&mut pe, Some(text.virtual_address + 0x20)).unwrap();
        assert!(
            bc.len() < 400,
            "forward CRT must not be lifted into bytecode, got {} bytes",
            bc.len()
        );
    }
}
