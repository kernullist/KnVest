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

fn translate_to_vm_bytecode(_pe: &PEFile, _target_rva: u32, original_entry: u32) -> PEResult<Vec<u8>> {
    let mut bytecode = Vec::new();

    bytecode.push(OpCode::LoadImm as u8);
    bytecode.push(0);
    bytecode.extend_from_slice(&(original_entry as u64).to_le_bytes());

    bytecode.push(OpCode::Call as u8);
    bytecode.extend_from_slice(&5u64.to_le_bytes());

    bytecode.push(OpCode::Exit as u8);
    bytecode.push(0);

    Ok(bytecode)
}

fn create_vm_interpreter_stub(original_entry_rva: u32, new_section_rva: u32) -> (Vec<u8>, usize) {
    let mut stub = Vec::new();
    
    let relative_offset = original_entry_rva as i64 - (new_section_rva + 5) as i64;
    let offset_bytes = (relative_offset as i32).to_le_bytes();
    
    stub.push(0xE9);
    stub.extend_from_slice(&offset_bytes);
    
    let size = stub.len();
    (stub, size)
}

fn add_vm_section(pe: &mut PEFile, _vm_stub_template: &[u8], bytecode: &[u8]) -> PEResult<()> {
    let original_entry_rva = pe.entry_point_rva;
    
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
    
    let (vm_stub, _) = create_vm_interpreter_stub(original_entry_rva, new_virtual_address);
    
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
        let mut has_call = false;
        let mut has_exit = false;
        
        let mut i = 0;
        while i < bytecode.len() {
            if let Some(op) = OpCode::from_u8(bytecode[i]) {
                match op {
                    OpCode::LoadImm => has_load_imm = true,
                    OpCode::Call => has_call = true,
                    OpCode::Exit => has_exit = true,
                    _ => {}
                }
            }
            i += 1;
        }
        
        assert!(has_load_imm, "Bytecode should contain LoadImm");
        assert!(has_call, "Bytecode should contain Call");
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
        assert_eq!(stub_byte, 0xE9, "Entry point should have JMP instruction (0xE9)");
        
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
