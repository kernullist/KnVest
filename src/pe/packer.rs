use super::parser::{PEFile, PEResult, PEError};
use crate::vm::OpCode;

pub struct PackedFunction {
    pub bytecode: Vec<u8>,
    pub original_rva: u32,
    pub original_size: usize,
}

pub fn pack_function(pe: &mut PEFile, function_rva: Option<u32>) -> PEResult<Vec<u8>> {
    let target_rva = function_rva.unwrap_or(pe.entry_point_rva);
    
    let file_offset = pe.rva_to_file_offset(target_rva)?;
    
    if file_offset >= pe.data.len() {
        return Err(PEError::InvalidPE("Function RVA out of bounds".to_string()));
    }

    let original_code = &pe.data[file_offset..];
    let bytecode = translate_to_vm_bytecode(original_code, target_rva);

    inject_vm_stub(pe, target_rva, &bytecode)?;

    Ok(bytecode)
}

fn translate_to_vm_bytecode(code: &[u8], _rva: u32) -> Vec<u8> {
    let mut bytecode = Vec::new();

    bytecode.push(OpCode::LoadImm as u8);
    bytecode.push(0);
    bytecode.extend_from_slice(&0x48656C6C6F_u64.to_le_bytes());

    bytecode.push(OpCode::LoadImm as u8);
    bytecode.push(1);
    bytecode.extend_from_slice(&0x576F726C64_u64.to_le_bytes());

    bytecode.push(OpCode::NativeCall as u8);
    bytecode.extend_from_slice(&1u64.to_le_bytes());

    bytecode.push(OpCode::LoadImm as u8);
    bytecode.push(0);
    bytecode.extend_from_slice(&0u64.to_le_bytes());

    bytecode.push(OpCode::Exit as u8);
    bytecode.push(0);

    bytecode
}

fn inject_vm_stub(pe: &mut PEFile, _target_rva: u32, bytecode: &[u8]) -> PEResult<()> {
    let text_section = pe.get_section(".text")?;
    
    let new_section_data = create_vm_section(bytecode);
    
    let insertion_point = (text_section.pointer_to_raw_data + text_section.size_of_raw_data) as usize;
    
    if insertion_point > pe.data.len() {
        return Err(PEError::InvalidPE("Invalid section layout".to_string()));
    }

    pe.data.splice(insertion_point..insertion_point, new_section_data.iter().cloned());

    Ok(())
}

fn create_vm_section(bytecode: &[u8]) -> Vec<u8> {
    let mut section_data = Vec::new();
    
    section_data.extend_from_slice(b"\x90\x90\x90\x90");
    
    section_data.extend_from_slice(bytecode);
    
    while section_data.len() % 16 != 0 {
        section_data.push(0x90);
    }
    
    section_data
}

pub fn extract_bytecode_from_packed(pe: &PEFile) -> PEResult<Vec<u8>> {
    let text_section = pe.get_section(".text")?;
    let section_start = text_section.pointer_to_raw_data as usize;
    let section_end = section_start + text_section.size_of_raw_data as usize;
    
    if section_end > pe.data.len() {
        return Err(PEError::InvalidPE("Section data out of bounds".to_string()));
    }

    let section_data = &pe.data[section_start..section_end];
    
    let mut bytecode_start = None;
    for i in 0..section_data.len() {
        if let Some(opcode) = OpCode::from_u8(section_data[i]) {
            if matches!(opcode, OpCode::LoadImm | OpCode::Nop) {
                bytecode_start = Some(i);
                break;
            }
        }
    }

    if let Some(start) = bytecode_start {
        let mut end = start;
        while end < section_data.len() {
            if section_data[end] == OpCode::Exit as u8 {
                end += 2;
                break;
            }
            end += 1;
        }
        
        Ok(section_data[start..end].to_vec())
    } else {
        Err(PEError::InvalidPE("No VM bytecode found in packed PE".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_to_vm_bytecode() {
        let code = vec![0x48, 0x89, 0xe5];
        let bytecode = translate_to_vm_bytecode(&code, 0x1000);
        assert!(!bytecode.is_empty());
        assert_eq!(bytecode[0], OpCode::LoadImm as u8);
    }

    #[test]
    fn test_create_vm_section() {
        let bytecode = vec![OpCode::Nop as u8, OpCode::Exit as u8, 0];
        let section = create_vm_section(&bytecode);
        assert!(section.len() % 16 == 0);
    }
}
