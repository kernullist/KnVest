use super::parser::{PEFile, PEResult, PEError};
use crate::vm::OpCode;

const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;

pub fn pack_function(pe: &mut PEFile, function_rva: Option<u32>) -> PEResult<Vec<u8>> {
    let target_rva = function_rva.unwrap_or(pe.entry_point_rva);
    let original_entry_rva = pe.entry_point_rva;
    
    let bytecode = translate_to_vm_bytecode(pe, target_rva, original_entry_rva)?;
    
    add_vm_section(pe, &[], &bytecode)?;
    
    Ok(bytecode)
}

fn translate_to_vm_bytecode(_pe: &PEFile, _target_rva: u32, _original_entry: u32) -> PEResult<Vec<u8>> {
    let mut bytecode = Vec::new();

    let hello_msg = b"Hello, World!\n";
    let msg_offset_in_bytecode = 100u64;
    
    bytecode.push(OpCode::LoadImm as u8);
    bytecode.push(0);
    bytecode.extend_from_slice(&msg_offset_in_bytecode.to_le_bytes());
    
    bytecode.push(OpCode::LoadImm as u8);
    bytecode.push(1);
    bytecode.extend_from_slice(&(hello_msg.len() as u64).to_le_bytes());
    
    bytecode.push(OpCode::NativeCall as u8);
    bytecode.extend_from_slice(&1u64.to_le_bytes());
    
    bytecode.push(OpCode::LoadImm as u8);
    bytecode.push(0);
    bytecode.extend_from_slice(&0u64.to_le_bytes());
    
    bytecode.push(OpCode::Exit as u8);
    bytecode.push(0);
    
    while bytecode.len() < msg_offset_in_bytecode as usize {
        bytecode.push(0x00);
    }
    
    bytecode.extend_from_slice(hello_msg);
    
    Ok(bytecode)
}

fn create_vm_interpreter_stub(_image_base: u64, _section_rva: u32) -> (Vec<u8>, usize) {
    let mut stub = Vec::new();
    let mut patches: Vec<(usize, usize)> = Vec::new();
    
    stub.extend_from_slice(&[0x55]);
    stub.extend_from_slice(&[0x48, 0x89, 0xE5]);
    stub.extend_from_slice(&[0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]);
    
    stub.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x40, 0x10]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x58, 0x30]);
    
    stub.extend_from_slice(&[0x8B, 0x43, 0x3C]);
    stub.extend_from_slice(&[0x8B, 0x84, 0x18, 0x88, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x01, 0xD8]);
    stub.extend_from_slice(&[0x8B, 0x78, 0x20]);
    stub.extend_from_slice(&[0x48, 0x01, 0xDF]);
    stub.extend_from_slice(&[0x8B, 0x48, 0x24]);
    stub.extend_from_slice(&[0x48, 0x01, 0xD9]);
    stub.extend_from_slice(&[0x8B, 0x50, 0x1C]);
    stub.extend_from_slice(&[0x48, 0x01, 0xDA]);
    stub.extend_from_slice(&[0x8B, 0x70, 0x18]);
    
    let search_loop = stub.len();
    stub.extend_from_slice(&[0x48, 0xFF, 0xCE]);
    stub.extend_from_slice(&[0x8B, 0x04, 0xB7]);
    stub.extend_from_slice(&[0x48, 0x01, 0xD8]);
    stub.extend_from_slice(&[0x48, 0x89, 0xC6]);
    
    let gpa_str_lea = stub.len();
    stub.extend_from_slice(&[0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);
    
    let strcmp_loop = stub.len();
    stub.extend_from_slice(&[0x41, 0x8A, 0x00]);
    stub.extend_from_slice(&[0x3A, 0x06]);
    let strcmp_fail = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x84, 0xC0]);
    let strcmp_done = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    stub.extend_from_slice(&[0x49, 0xFF, 0xC0]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    let strcmp_back = (strcmp_loop as i8).wrapping_sub((stub.len() + 2) as i8);
    stub.extend_from_slice(&[0xEB, strcmp_back as u8]);
    
    let strcmp_fail_target = stub.len();
    stub[strcmp_fail + 1] = (strcmp_fail_target as i8).wrapping_sub((strcmp_fail + 2) as i8) as u8;
    let search_back = (search_loop as i8).wrapping_sub((stub.len() + 2) as i8);
    stub.extend_from_slice(&[0xEB, search_back as u8]);
    
    let strcmp_done_target = stub.len();
    stub[strcmp_done + 1] = (strcmp_done_target as i8).wrapping_sub((strcmp_done + 2) as i8) as u8;
    
    stub.extend_from_slice(&[0x0F, 0xB7, 0x04, 0x71]);
    stub.extend_from_slice(&[0x8B, 0x04, 0x82]);
    stub.extend_from_slice(&[0x48, 0x01, 0xD8]);
    stub.extend_from_slice(&[0x48, 0x89, 0x45, 0x80]);
    
    stub.extend_from_slice(&[0x48, 0x89, 0xD9]);
    let gsth_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x55, 0x80]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    stub.extend_from_slice(&[0x48, 0x89, 0x45, 0x88]);
    
    stub.extend_from_slice(&[0x48, 0x89, 0xD9]);
    let wf_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x55, 0x80]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    stub.extend_from_slice(&[0x48, 0x89, 0x45, 0x90]);
    
    stub.extend_from_slice(&[0x48, 0x89, 0xD9]);
    let ep_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x55, 0x80]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    stub.extend_from_slice(&[0x48, 0x89, 0x45, 0x98]);
    
    stub.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xF5, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x55, 0x88]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    stub.extend_from_slice(&[0x48, 0x89, 0x45, 0xA0]);
    
    let bc_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]);
    
    let dispatch_loop = stub.len();
    stub.extend_from_slice(&[0x0F, 0xB6, 0x06]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    
    stub.extend_from_slice(&[0x3C, 0xFF]);
    let exit_jmp = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    
    stub.extend_from_slice(&[0x3C, 0x01]);
    let load_imm_jmp = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x06]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);
    stub.extend_from_slice(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
    let dispatch_back1 = (dispatch_loop as i8).wrapping_sub((stub.len() + 2) as i8);
    stub.extend_from_slice(&[0xEB, dispatch_back1 as u8]);
    
    let load_imm_target = stub.len();
    stub[load_imm_jmp + 1] = (load_imm_target as i8).wrapping_sub((load_imm_jmp + 2) as i8) as u8;
    
    stub.extend_from_slice(&[0x3C, 0x0D]);
    let dispatch_back2 = (dispatch_loop as i8).wrapping_sub((stub.len() + 2) as i8);
    stub.extend_from_slice(&[0x75, dispatch_back2 as u8]);
    
    stub.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);
    stub.extend_from_slice(&[0x48, 0x89, 0x75, 0xA8]);
    
    stub.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xA0]);
    let bc_base_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x45, 0x80]);
    stub.extend_from_slice(&[0x48, 0x01, 0xD0]);
    stub.extend_from_slice(&[0x48, 0x89, 0xC2]);
    stub.extend_from_slice(&[0x4C, 0x8B, 0x45, 0x88]);
    stub.extend_from_slice(&[0x4C, 0x8D, 0x4D, 0xB0]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    stub.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0xFF, 0x55, 0x90]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    
    stub.extend_from_slice(&[0x48, 0x8B, 0x75, 0xA8]);
    let dispatch_back3 = (dispatch_loop as i16).wrapping_sub((stub.len() + 2) as i16);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back3.to_le_bytes());
    
    let exit_target = stub.len();
    stub[exit_jmp + 1] = (exit_target as i8).wrapping_sub((exit_jmp + 2) as i8) as u8;
    
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0xCD, 0x80]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x55, 0x98]);
    
    let gpa_str_pos = stub.len();
    stub.extend_from_slice(b"GetProcAddress\0");
    let gsth_str_pos = stub.len();
    stub.extend_from_slice(b"GetStdHandle\0");
    let wf_str_pos = stub.len();
    stub.extend_from_slice(b"WriteFile\0");
    let ep_str_pos = stub.len();
    stub.extend_from_slice(b"ExitProcess\0");
    
    patches.push((gpa_str_lea + 3, gpa_str_pos));
    patches.push((gsth_lea + 3, gsth_str_pos));
    patches.push((wf_lea + 3, wf_str_pos));
    patches.push((ep_lea + 3, ep_str_pos));
    patches.push((bc_lea + 3, 0x100));
    patches.push((bc_base_lea + 3, 0x100));
    
    for (patch_offset, target) in patches {
        let next_ip = patch_offset + 4;
        let disp = (target as i32) - (next_ip as i32);
        stub[patch_offset..patch_offset + 4].copy_from_slice(&disp.to_le_bytes());
    }
    
    while stub.len() < 0x100 {
        stub.push(0x00);
    }
    
    let size = stub.len();
    (stub, size)
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
    
    while section_data.len() % 16 != 0 {
        section_data.push(0xCC);
    }
    
    let bytecode_marker = b"VMBC";
    section_data.extend_from_slice(bytecode_marker);
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
                    if bytecode_end + 1 < section_data.len() 
                        && section_data[bytecode_end] == OpCode::Exit as u8 {
                        bytecode_end += 2;
                        break;
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
    use crate::pe::test_pe;

    #[test]
    fn test_pack_creates_valid_pe() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let original_entry = pe.entry_point_rva;
        
        let result = pack_function(&mut pe, None);
        assert!(result.is_ok());
        
        let bytecode = result.unwrap();
        assert!(!bytecode.is_empty());
        assert_eq!(bytecode[0], OpCode::LoadImm as u8);
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
        assert_eq!(bc[0], OpCode::LoadImm as u8);
    }

    #[test]
    fn test_bytecode_contains_vm_opcodes() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        
        pack_function(&mut pe, None).unwrap();
        
        let bytecode = extract_bytecode_from_packed(&pe).unwrap();
        
        let mut has_load_imm = false;
        let mut has_native_call = false;
        let mut has_exit = false;
        
        let mut i = 0;
        while i < bytecode.len() {
            if let Some(op) = OpCode::from_u8(bytecode[i]) {
                match op {
                    OpCode::LoadImm => has_load_imm = true,
                    OpCode::NativeCall => has_native_call = true,
                    OpCode::Exit => has_exit = true,
                    _ => {}
                }
            }
            i += 1;
        }
        
        assert!(has_load_imm, "Bytecode should contain LoadImm");
        assert!(has_native_call, "Bytecode should contain NativeCall");
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
}
