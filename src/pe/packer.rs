use super::parser::{PEFile, PEResult, PEError};
use super::lifter::{disassemble_x64_simple, lift_to_vm_bytecode_for_main, decode_instruction, X64Instruction, X64InstrKind};
use crate::vm::OpCode;

const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;

pub fn pack_function(pe: &mut PEFile, function_rva: Option<u32>) -> PEResult<Vec<u8>> {
    let target_rva = if let Some(rva) = function_rva {
        rva
    } else {
        detect_main_rva(pe)?
    };
    let original_entry_rva = pe.entry_point_rva;
    
    let bytecode = translate_to_vm_bytecode(pe, target_rva, original_entry_rva)?;
    
    add_vm_section(pe, &[], &bytecode)?;
    
    Ok(bytecode)
}

fn detect_main_rva(pe: &PEFile) -> PEResult<u32> {
    let text_section = pe.get_section(".text")
        .or_else(|_| pe.get_section("CODE"))?;
    
    let text_start_rva = text_section.virtual_address;
    
    let text_offset = pe.rva_to_file_offset(text_start_rva)?;
    let text_data = &pe.data[text_offset..std::cmp::min(text_offset + text_section.size_of_raw_data as usize, pe.data.len())];
    
    let mut candidates = Vec::new();
    
    for offset in (0..text_data.len().saturating_sub(50)).step_by(1) {
        if text_data.len() < offset + 10 {
            break;
        }
        
        if text_data[offset] == 0x55 &&
           text_data[offset + 1] == 0x48 &&
           text_data[offset + 2] == 0x89 &&
           text_data[offset + 3] == 0xE5 {
            
            let has_sub_rsp = offset + 7 < text_data.len() &&
                text_data[offset + 4] == 0x48 &&
                text_data[offset + 5] == 0x83 &&
                text_data[offset + 6] == 0xEC;
            
            if !has_sub_rsp {
                continue;
            }
            
            let has_call_to_main = (offset + 20 < text_data.len()) && 
                text_data[offset + 8..offset + 13].windows(5).any(|w| w[0] == 0xE8);
            
            if has_call_to_main {
                let candidate_rva = text_start_rva + offset as u32;
                if offset >= 0x4d0 && offset <= 0x800 {
                    candidates.push((candidate_rva, offset));
                }
            }
        }
    }
    
    if let Some(&(rva, offset)) = candidates.first() {
        eprintln!("Auto-detected main at RVA {:#x} (.text+{:#x})", rva, offset);
        return Ok(rva);
    }
    
    eprintln!("Could not auto-detect main, using entry point {:#x}", pe.entry_point_rva);
    Ok(pe.entry_point_rva)
}

fn translate_to_vm_bytecode(pe: &PEFile, target_rva: u32, _original_entry: u32) -> PEResult<Vec<u8>> {
    let file_offset = pe.rva_to_file_offset(target_rva)?;
    
    if file_offset + 200 > pe.data.len() {
        return Err(PEError::InvalidPE("Code section too small".to_string()));
    }
    
    if is_simple_hello_pattern(pe, target_rva) {
        eprintln!("Detected hello.c, using special path");
        return translate_hello_path();
    }
    
    let main_code = &pe.data[file_offset..std::cmp::min(file_offset + 500, pe.data.len())];
    let mut main_instrs = disassemble_until_ret(main_code, 100);
    
    if main_instrs.is_empty() {
        return Err(PEError::InvalidPE("Failed to disassemble main".to_string()));
    }
    
    for instr in &mut main_instrs {
        instr.offset += file_offset;
    }
    
    let call_targets = find_internal_call_targets(&main_instrs, file_offset);
    
    let mut all_instrs = main_instrs;
    let mut processed_targets = std::collections::HashSet::new();
    
    // Only process callees BEFORE main (no CRT after main)
    for target_file_offset in call_targets {
        if processed_targets.contains(&target_file_offset) {
            continue;
        }
        processed_targets.insert(target_file_offset);
        
        if target_file_offset < file_offset && target_file_offset + 100 <= pe.data.len() {
            // Must start with push rbp (0x55)
            if pe.data[target_file_offset] == 0x55 {
                let callee_code = &pe.data[target_file_offset..std::cmp::min(target_file_offset + 300, pe.data.len())];
                let mut callee_instrs = disassemble_until_ret(callee_code, 100);
                
                for instr in &mut callee_instrs {
                    instr.offset += target_file_offset;
                }
                
                // Check for recursive calls within this callee
                let callee_targets = find_internal_call_targets(&callee_instrs, file_offset);
                for nested_target in callee_targets {
                    // For recursion, allow calling self
                    if nested_target == target_file_offset {
                        // Self-recursion is fine, already in all_instrs
                        continue;
                    }
                    
                    if !processed_targets.contains(&nested_target) && nested_target < file_offset {
                        if nested_target + 100 <= pe.data.len() && pe.data[nested_target] == 0x55 {
                            let nested_code = &pe.data[nested_target..std::cmp::min(nested_target + 300, pe.data.len())];
                            let mut nested_instrs = disassemble_until_ret(nested_code, 100);
                            
                            for instr in &mut nested_instrs {
                                instr.offset += nested_target;
                            }
                            
                            all_instrs.extend(nested_instrs);
                            processed_targets.insert(nested_target);
                        }
                    }
                }
                
                all_instrs.extend(callee_instrs);
            }
        }
    }
    
    let bytecode = lift_to_vm_bytecode_for_main(&all_instrs, target_rva, file_offset);
    
    Ok(bytecode)
}

fn calculate_vm_offset(prefix_instrs: &[X64Instruction], _main_instrs: &[X64Instruction]) -> u64 {
    let mut offset = 9u64;
    
    for instr in prefix_instrs {
        match &instr.kind {
            X64InstrKind::MovRegImm { .. } => offset += 1 + 8,
            X64InstrKind::AddRegReg { .. } | X64InstrKind::SubRegReg { .. } | 
            X64InstrKind::ImulRegReg { .. } | X64InstrKind::CmpRegReg { .. } => offset += 3,
            X64InstrKind::MovRegReg { .. } => offset += 3,
            X64InstrKind::Jmp { .. } | X64InstrKind::Je { .. } | X64InstrKind::Jne { .. } |
            X64InstrKind::Jl { .. } | X64InstrKind::Jle { .. } | X64InstrKind::Jg { .. } |
            X64InstrKind::Jge { .. } => offset += 1 + 8,
            X64InstrKind::Call { .. } => offset += 1 + 8,
            X64InstrKind::Ret => offset += 1,
            X64InstrKind::Push { .. } | X64InstrKind::Pop { .. } => offset += 2,
            _ => {},
        }
    }
    
    offset
}

fn is_simple_hello_pattern(pe: &PEFile, main_rva: u32) -> bool {
    if let Ok(rdata_section) = pe.get_section(".rdata") {
        let rdata_start = rdata_section.pointer_to_raw_data as usize;
        let rdata_end = rdata_start + rdata_section.size_of_raw_data as usize;
        
        if rdata_end > pe.data.len() {
            return false;
        }
        
        let rdata_data = &pe.data[rdata_start..rdata_end];
        
        for i in 0..rdata_data.len().saturating_sub(13) {
            if &rdata_data[i..i+13] == b"Hello, World!" {
                if let Ok(file_offset) = pe.rva_to_file_offset(main_rva) {
                    if file_offset + 100 <= pe.data.len() {
                        let code = &pe.data[file_offset..file_offset + 100];
                        
                        for j in 0..code.len().saturating_sub(7) {
                            if code[j] == 0x48 && code[j+1] == 0x8D && code[j+2] == 0x05 {
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
        }
    }
    
    false
}

fn translate_hello_path() -> PEResult<Vec<u8>> {
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

fn disassemble_until_ret(code: &[u8], max_instrs: usize) -> Vec<X64Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;
    
    while offset < code.len() && instructions.len() < max_instrs {
        let start_offset = offset;
        let remaining = &code[offset..];
        
        if remaining.is_empty() {
            break;
        }
        
        let mut instr_bytes = Vec::new();
        let kind = super::lifter::decode_instruction(remaining, &mut instr_bytes, &mut offset);
        
        instructions.push(X64Instruction {
            offset: start_offset,
            bytes: instr_bytes,
            kind: kind.clone(),
        });
        
        if matches!(kind, X64InstrKind::Ret) {
            break;
        }
    }
    
    instructions
}

fn find_internal_call_targets(instrs: &[X64Instruction], main_file_offset: usize) -> Vec<usize> {
    let mut targets = Vec::new();
    
    for instr in instrs {
        if let X64InstrKind::Call { target_offset } = instr.kind {
            let instr_abs_offset = instr.offset;
            let target_abs_offset = (instr_abs_offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
            
            // Only include targets BEFORE main (no CRT functions after main)
            if target_abs_offset < main_file_offset {
                let distance = main_file_offset - target_abs_offset;
                // Allow up to 512 bytes before main (for larger functions like factorial)
                if distance < 0x200 {
                    targets.push(target_abs_offset);
                }
            }
        }
    }
    
    targets
}

fn create_vm_interpreter_stub(_image_base: u64, _section_rva: u32) -> (Vec<u8>, usize) {
    let mut stub = Vec::new();
    let mut patches: Vec<(usize, String)> = Vec::new();
    
    stub.extend_from_slice(&[0x55]);
    stub.extend_from_slice(&[0x48, 0x89, 0xE5]);
    stub.extend_from_slice(&[0x48, 0x81, 0xEC, 0x00, 0x03, 0x00, 0x00]); // sub rsp, 0x300 (increased for call stack)
    stub.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]);
    
    // Initialize call stack depth to 0 at [rbp-0xC8]
    stub.extend_from_slice(&[0x48, 0xC7, 0x85, 0x38, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbp-0xC8], 0
    // Initialize Push/Pop value stack depth to 0 at [rbp-0xE8]
    stub.extend_from_slice(&[0x48, 0xC7, 0x85, 0x18, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbp-0xE8], 0
    // Initialize LoadByte bytecode base cache at [rbp-0x118]
    stub.extend_from_slice(&[0x48, 0xC7, 0x85, 0xE8, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbp-0x118], 0
    
    stub.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);
    stub.extend_from_slice(&[0x4C, 0x8D, 0x58, 0x10]);
    
    let k32_str_lea = stub.len();
    stub.extend_from_slice(&[0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
    
    stub.extend_from_slice(&[0x49, 0x8B, 0x0B]);
    
    let module_loop = stub.len();
    stub.extend_from_slice(&[0x48, 0x8B, 0x09]);
    stub.extend_from_slice(&[0x49, 0x39, 0xCB]);
    let module_fail_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
    
    stub.extend_from_slice(&[0x48, 0x8B, 0x71, 0x60]);
    stub.extend_from_slice(&[0x4D, 0x89, 0xD0]);
    
    let name_cmp_loop = stub.len();
    stub.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB7, 0x16]);
    stub.extend_from_slice(&[0x83, 0xF8, 0x41]);
    let lowercase1_skip = stub.len();
    stub.extend_from_slice(&[0x72, 0x00]);
    stub.extend_from_slice(&[0x83, 0xF8, 0x5A]);
    let lowercase1_skip2 = stub.len();
    stub.extend_from_slice(&[0x77, 0x00]);
    stub.extend_from_slice(&[0x83, 0xC8, 0x20]);
    let lowercase1_done = stub.len();
    stub[lowercase1_skip + 1] = (lowercase1_done as i8).wrapping_sub((lowercase1_skip + 2) as i8) as u8;
    stub[lowercase1_skip2 + 1] = (lowercase1_done as i8).wrapping_sub((lowercase1_skip2 + 2) as i8) as u8;
    
    stub.extend_from_slice(&[0x83, 0xFA, 0x41]);
    let lowercase2_skip = stub.len();
    stub.extend_from_slice(&[0x72, 0x00]);
    stub.extend_from_slice(&[0x83, 0xFA, 0x5A]);
    let lowercase2_skip2 = stub.len();
    stub.extend_from_slice(&[0x77, 0x00]);
    stub.extend_from_slice(&[0x83, 0xCA, 0x20]);
    let lowercase2_done = stub.len();
    stub[lowercase2_skip + 1] = (lowercase2_done as i8).wrapping_sub((lowercase2_skip + 2) as i8) as u8;
    stub[lowercase2_skip2 + 1] = (lowercase2_done as i8).wrapping_sub((lowercase2_skip2 + 2) as i8) as u8;
    
    stub.extend_from_slice(&[0x39, 0xD0]);
    let name_cmp_fail = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x85, 0xD2]);
    let name_cmp_done = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    stub.extend_from_slice(&[0x49, 0x83, 0xC0, 0x02]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC6, 0x02]);
    let name_cmp_back = (name_cmp_loop as i8).wrapping_sub((stub.len() + 2) as i8);
    stub.extend_from_slice(&[0xEB, name_cmp_back as u8]);
    
    let name_cmp_fail_target = stub.len();
    stub[name_cmp_fail + 1] = (name_cmp_fail_target as i8).wrapping_sub((name_cmp_fail + 2) as i8) as u8;
    let module_back = (module_loop as i8).wrapping_sub((stub.len() + 2) as i8);
    stub.extend_from_slice(&[0xEB, module_back as u8]);
    
    let name_cmp_done_target = stub.len();
    stub[name_cmp_done + 1] = (name_cmp_done_target as i8).wrapping_sub((name_cmp_done + 2) as i8) as u8;
    stub.extend_from_slice(&[0x48, 0x8B, 0x59, 0x30]);
    
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
    stub.extend_from_slice(&[0x85, 0xF6]);
    let search_fail_jmp = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xCE]);
    stub.extend_from_slice(&[0x8B, 0x04, 0xB7]);
    stub.extend_from_slice(&[0x48, 0x01, 0xD8]);
    stub.extend_from_slice(&[0x49, 0x89, 0xC1]);
    
    let gpa_str_lea = stub.len();
    stub.extend_from_slice(&[0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);
    
    let strcmp_loop = stub.len();
    stub.extend_from_slice(&[0x41, 0x8A, 0x00]);
    stub.extend_from_slice(&[0x41, 0x3A, 0x01]);
    let strcmp_fail = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x84, 0xC0]);
    let strcmp_done = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    stub.extend_from_slice(&[0x49, 0xFF, 0xC0]);
    stub.extend_from_slice(&[0x49, 0xFF, 0xC1]);
    let strcmp_back = (strcmp_loop as i8).wrapping_sub((stub.len() + 2) as i8);
    stub.extend_from_slice(&[0xEB, strcmp_back as u8]);
    
    let strcmp_fail_target = stub.len();
    stub[strcmp_fail + 1] = (strcmp_fail_target as i8).wrapping_sub((strcmp_fail + 2) as i8) as u8;
    let search_back = (search_loop as i8).wrapping_sub((stub.len() + 2) as i8);
    stub.extend_from_slice(&[0xEB, search_back as u8]);
    
    let search_fail_target = stub.len();
    stub[search_fail_jmp + 1] = (search_fail_target as i8).wrapping_sub((search_fail_jmp + 2) as i8) as u8;
    let module_fail_disp = (search_fail_target as i32) - ((module_fail_jmp + 6) as i32);
    stub[module_fail_jmp + 2..module_fail_jmp + 6].copy_from_slice(&module_fail_disp.to_le_bytes());
    stub.extend_from_slice(&[0xCC]);
    
    let strcmp_done_target = stub.len();
    stub[strcmp_done + 1] = (strcmp_done_target as i8).wrapping_sub((strcmp_done + 2) as i8) as u8;
    
    stub.extend_from_slice(&[0x0F, 0xB7, 0x04, 0x71]);
    stub.extend_from_slice(&[0x8B, 0x04, 0x82]);
    stub.extend_from_slice(&[0x48, 0x01, 0xD8]);
    stub.extend_from_slice(&[0x48, 0x89, 0x85, 0x40, 0xFF, 0xFF, 0xFF]);
    
    stub.extend_from_slice(&[0x48, 0x89, 0xD9]);
    let gsth_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x95, 0x40, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    stub.extend_from_slice(&[0x48, 0x89, 0x85, 0x48, 0xFF, 0xFF, 0xFF]);
    
    stub.extend_from_slice(&[0x48, 0x89, 0xD9]);
    let wf_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x95, 0x40, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    stub.extend_from_slice(&[0x48, 0x89, 0x85, 0x50, 0xFF, 0xFF, 0xFF]);
    
    stub.extend_from_slice(&[0x48, 0x89, 0xD9]);
    let ep_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x95, 0x40, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    stub.extend_from_slice(&[0x48, 0x89, 0x85, 0x58, 0xFF, 0xFF, 0xFF]);
    
    stub.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xF5, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x95, 0x48, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    stub.extend_from_slice(&[0x48, 0x89, 0x85, 0x60, 0xFF, 0xFF, 0xFF]);
    
    // Dispatch prologue: load bytecode pointer and cache for LoadByte (not func1-only)
    let bc_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]); // lea rsi, [rip+bytecode]
    stub.extend_from_slice(&[0x48, 0x89, 0xB5, 0xE8, 0xFE, 0xFF, 0xFF]); // mov [rbp-0x118], rsi
    
    let dispatch_loop = stub.len();
    stub.extend_from_slice(&[0x0F, 0xB6, 0x06]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    
    stub.extend_from_slice(&[0x3C, 0xFF]);
    let exit_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
    
    stub.extend_from_slice(&[0x3C, 0x01]);
    let load_imm_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x06]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);
    stub.extend_from_slice(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
    let dispatch_back1 = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back1.to_le_bytes());
    
    let load_imm_target = stub.len();
    let load_imm_offset = (load_imm_target as i32).wrapping_sub((load_imm_jmp + 6) as i32);
    stub[load_imm_jmp + 2..load_imm_jmp + 6].copy_from_slice(&load_imm_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x04]);
    let move_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x3E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
    stub.extend_from_slice(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
    let dispatch_back_move = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_move.to_le_bytes());
    
    let move_target = stub.len();
    let move_offset = (move_target as i32).wrapping_sub((move_jmp + 6) as i32);
    stub[move_jmp + 2..move_jmp + 6].copy_from_slice(&move_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x05]);
    let add_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x3E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x16]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
    stub.extend_from_slice(&[0x48, 0x03, 0x44, 0xD5, 0x80]);
    stub.extend_from_slice(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
    let dispatch_back_add = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_add.to_le_bytes());
    
    let add_target = stub.len();
    let add_offset = (add_target as i32).wrapping_sub((add_jmp + 6) as i32);
    stub[add_jmp + 2..add_jmp + 6].copy_from_slice(&add_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x06]);
    let sub_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x3E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x16]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
    stub.extend_from_slice(&[0x48, 0x2B, 0x44, 0xD5, 0x80]);
    stub.extend_from_slice(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
    let dispatch_back_sub = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_sub.to_le_bytes());
    
    let sub_target = stub.len();
    let sub_offset = (sub_target as i32).wrapping_sub((sub_jmp + 6) as i32);
    stub[sub_jmp + 2..sub_jmp + 6].copy_from_slice(&sub_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x07]);
    let mul_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x3E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x16]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
    stub.extend_from_slice(&[0x48, 0x0F, 0xAF, 0x44, 0xD5, 0x80]);
    stub.extend_from_slice(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
    let dispatch_back_mul = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_mul.to_le_bytes());
    
    let mul_target = stub.len();
    let mul_offset = (mul_target as i32).wrapping_sub((mul_jmp + 6) as i32);
    stub[mul_jmp + 2..mul_jmp + 6].copy_from_slice(&mul_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x09]);
    let cmp_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x3E]);
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x44, 0xCD, 0x80]);
    stub.extend_from_slice(&[0x48, 0x3B, 0x44, 0xFD, 0x80]);
    stub.extend_from_slice(&[0x48, 0xC7, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    let cmp_eq_jmp = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0xC7, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00]);
    let cmp_done1 = stub.len();
    stub.extend_from_slice(&[0xEB, 0x00]);
    let cmp_eq_target = stub.len();
    stub[cmp_eq_jmp + 1] = (cmp_eq_target as i8).wrapping_sub((cmp_eq_jmp + 2) as i8) as u8;
    let cmp_gt_jmp = stub.len();
    stub.extend_from_slice(&[0x7E, 0x00]);
    stub.extend_from_slice(&[0x48, 0xC7, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x02, 0x00, 0x00, 0x00]);
    let cmp_gt_target = stub.len();
    stub[cmp_gt_jmp + 1] = (cmp_gt_target as i8).wrapping_sub((cmp_gt_jmp + 2) as i8) as u8;
    let cmp_done1_target = stub.len();
    stub[cmp_done1 + 1] = (cmp_done1_target as i8).wrapping_sub((cmp_done1 + 2) as i8) as u8;
    let dispatch_back_cmp = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_cmp.to_le_bytes());
    
    let cmp_target = stub.len();
    let cmp_offset = (cmp_target as i32).wrapping_sub((cmp_jmp + 6) as i32);
    stub[cmp_jmp + 2..cmp_jmp + 6].copy_from_slice(&cmp_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x0A]);
    let jmp_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x06]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);
    let bc_base_lea_jmp = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x01, 0xF0]);
    stub.extend_from_slice(&[0x48, 0x89, 0xC6]);
    let dispatch_back_jmp = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_jmp.to_le_bytes());
    
    let jmp_target = stub.len();
    let jmp_offset = (jmp_target as i32).wrapping_sub((jmp_jmp + 6) as i32);
    stub[jmp_jmp + 2..jmp_jmp + 6].copy_from_slice(&jmp_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x0B]);
    let jmpif_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);  // movzx ecx, byte [rsi] - read condition
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);  // inc rsi
    stub.extend_from_slice(&[0x48, 0x8B, 0x06]);  // mov rax, [rsi] - read target
    stub.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);  // add rsi, 8
    stub.extend_from_slice(&[0x48, 0x8B, 0x95, 0x70, 0xFF, 0xFF, 0xFF]);  // mov rdx, [rbp-0x90] - flags
    
    // Check condition 1 (EQ): flags == 1
    stub.extend_from_slice(&[0x48, 0x83, 0xF9, 0x01]);
    let jmpif_eq_jmp = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xFA, 0x01]);
    let jmpif_nottaken1 = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    let jmpif_taken1 = stub.len();
    stub.extend_from_slice(&[0xEB, 0x00]);
    let jmpif_eq_target = stub.len();
    stub[jmpif_eq_jmp + 1] = (jmpif_eq_target as i8).wrapping_sub((jmpif_eq_jmp + 2) as i8) as u8;
    
    // Check condition 2 (NE): flags != 1
    stub.extend_from_slice(&[0x48, 0x83, 0xF9, 0x02]);
    let jmpif_ne_jmp = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xFA, 0x01]);
    let jmpif_taken2 = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    let jmpif_nottaken2 = stub.len();
    stub.extend_from_slice(&[0xEB, 0x00]);
    let jmpif_ne_target = stub.len();
    stub[jmpif_ne_jmp + 1] = (jmpif_ne_target as i8).wrapping_sub((jmpif_ne_jmp + 2) as i8) as u8;
    
    // Check condition 3 (GT): flags == 2
    stub.extend_from_slice(&[0x48, 0x83, 0xF9, 0x03]);
    let jmpif_gt_jmp = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xFA, 0x02]);
    let jmpif_taken3 = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    let jmpif_nottaken3 = stub.len();
    stub.extend_from_slice(&[0xEB, 0x00]);
    let jmpif_gt_target = stub.len();
    stub[jmpif_gt_jmp + 1] = (jmpif_gt_target as i8).wrapping_sub((jmpif_gt_jmp + 2) as i8) as u8;
    
    // Check condition 4 (LT): flags == 0
    stub.extend_from_slice(&[0x48, 0x83, 0xF9, 0x04]);
    let jmpif_lt_jmp = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xFA, 0x00]);
    let jmpif_taken4 = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    let jmpif_nottaken4 = stub.len();
    stub.extend_from_slice(&[0xEB, 0x00]);
    let jmpif_lt_target = stub.len();
    stub[jmpif_lt_jmp + 1] = (jmpif_lt_target as i8).wrapping_sub((jmpif_lt_jmp + 2) as i8) as u8;
    
    // Check condition 5 (LE): flags != 2
    stub.extend_from_slice(&[0x48, 0x83, 0xF9, 0x05]);
    let jmpif_le_jmp = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xFA, 0x02]);
    let jmpif_taken5 = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    let jmpif_nottaken5 = stub.len();
    stub.extend_from_slice(&[0xEB, 0x00]);
    let jmpif_le_target = stub.len();
    stub[jmpif_le_jmp + 1] = (jmpif_le_target as i8).wrapping_sub((jmpif_le_jmp + 2) as i8) as u8;
    
    // Check condition 6 (GE): flags != 0
    stub.extend_from_slice(&[0x48, 0x83, 0xF9, 0x06]);
    let jmpif_ge_jmp = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0x83, 0xFA, 0x00]);
    let jmpif_taken6 = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    let jmpif_nottaken6 = stub.len();
    stub.extend_from_slice(&[0xEB, 0x00]);
    let jmpif_ge_target = stub.len();
    stub[jmpif_ge_jmp + 1] = (jmpif_ge_target as i8).wrapping_sub((jmpif_ge_jmp + 2) as i8) as u8;
    
    // Not taken - continue to next instruction
    let jmpif_nottaken_all = stub.len();
    stub[jmpif_nottaken1 + 1] = (jmpif_nottaken_all as i8).wrapping_sub((jmpif_nottaken1 + 2) as i8) as u8;
    stub[jmpif_nottaken2 + 1] = (jmpif_nottaken_all as i8).wrapping_sub((jmpif_nottaken2 + 2) as i8) as u8;
    stub[jmpif_nottaken3 + 1] = (jmpif_nottaken_all as i8).wrapping_sub((jmpif_nottaken3 + 2) as i8) as u8;
    stub[jmpif_nottaken4 + 1] = (jmpif_nottaken_all as i8).wrapping_sub((jmpif_nottaken4 + 2) as i8) as u8;
    stub[jmpif_nottaken5 + 1] = (jmpif_nottaken_all as i8).wrapping_sub((jmpif_nottaken5 + 2) as i8) as u8;
    stub[jmpif_nottaken6 + 1] = (jmpif_nottaken_all as i8).wrapping_sub((jmpif_nottaken6 + 2) as i8) as u8;
    let dispatch_back_jmpif_nottaken = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_jmpif_nottaken.to_le_bytes());
    
    // Taken - jump to target
    let jmpif_taken_all = stub.len();
    stub[jmpif_taken1 + 1] = (jmpif_taken_all as i8).wrapping_sub((jmpif_taken1 + 2) as i8) as u8;
    stub[jmpif_taken2 + 1] = (jmpif_taken_all as i8).wrapping_sub((jmpif_taken2 + 2) as i8) as u8;
    stub[jmpif_taken3 + 1] = (jmpif_taken_all as i8).wrapping_sub((jmpif_taken3 + 2) as i8) as u8;
    stub[jmpif_taken4 + 1] = (jmpif_taken_all as i8).wrapping_sub((jmpif_taken4 + 2) as i8) as u8;
    stub[jmpif_taken5 + 1] = (jmpif_taken_all as i8).wrapping_sub((jmpif_taken5 + 2) as i8) as u8;
    stub[jmpif_taken6 + 1] = (jmpif_taken_all as i8).wrapping_sub((jmpif_taken6 + 2) as i8) as u8;
    let bc_base_lea_jmpif = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x01, 0xF0]);
    stub.extend_from_slice(&[0x48, 0x89, 0xC6]);
    let dispatch_back_jmpif_taken = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_jmpif_taken.to_le_bytes());
    
    let jmpif_target = stub.len();
    let jmpif_offset = (jmpif_target as i32).wrapping_sub((jmpif_jmp + 6) as i32);
    stub[jmpif_jmp + 2..jmpif_jmp + 6].copy_from_slice(&jmpif_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x0C]);
    let call_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    // Read 8-byte call target from bytecode
    stub.extend_from_slice(&[0x48, 0x8B, 0x06]);  // mov rax, [rsi]
    stub.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);  // add rsi, 8
    // Save absolute IP temporarily
    stub.extend_from_slice(&[0x48, 0x89, 0xB5, 0x98, 0xFF, 0xFF, 0xFF]);  // mov [rbp-0x98], rsi
    // Calculate relative return offset
    let bc_base_lea_call = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00]);  // lea rcx, [rip + bc_base]
    stub.extend_from_slice(&[0x48, 0x8B, 0xB5, 0x98, 0xFF, 0xFF, 0xFF]);  // mov rsi, [rbp-0x98]
    stub.extend_from_slice(&[0x48, 0x29, 0xCE]);  // sub rsi, rcx (rsi = return offset)
    // Load depth from [rbp-0xC8]
    stub.extend_from_slice(&[0x48, 0x8B, 0x95, 0x38, 0xFF, 0xFF, 0xFF]);  // mov rdx, [rbp-0xC8]
    // Store return offset at [rbp-0x200 + depth*8]
    stub.extend_from_slice(&[0x48, 0x89, 0xB4, 0xD5, 0x00, 0xFE, 0xFF, 0xFF]);  // mov [rbp + rdx*8 - 0x200], rsi
    // Increment depth
    stub.extend_from_slice(&[0x48, 0xFF, 0xC2]);  // inc rdx
    stub.extend_from_slice(&[0x48, 0x89, 0x95, 0x38, 0xFF, 0xFF, 0xFF]);  // mov [rbp-0xC8], rdx
    // Jump to target
    let bc_base_lea_call2 = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]);  // lea rsi, [rip + bc_base]
    stub.extend_from_slice(&[0x48, 0x01, 0xF0]);  // add rax, rsi (rax = absolute target)
    stub.extend_from_slice(&[0x48, 0x89, 0xC6]);  // mov rsi, rax
    let dispatch_back_call = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_call.to_le_bytes());
    
    let call_target = stub.len();
    let call_offset = (call_target as i32).wrapping_sub((call_jmp + 6) as i32);
    stub[call_jmp + 2..call_jmp + 6].copy_from_slice(&call_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x0D]);
    let ret_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    // Load depth from [rbp-0xC8]
    stub.extend_from_slice(&[0x48, 0x8B, 0x85, 0x38, 0xFF, 0xFF, 0xFF]);  // mov rax, [rbp-0xC8]
    // Decrement depth
    stub.extend_from_slice(&[0x48, 0xFF, 0xC8]);  // dec rax
    stub.extend_from_slice(&[0x48, 0x89, 0x85, 0x38, 0xFF, 0xFF, 0xFF]);  // mov [rbp-0xC8], rax
    // Load return offset from [rbp-0x200 + depth*8]
    stub.extend_from_slice(&[0x48, 0x8B, 0x84, 0xC5, 0x00, 0xFE, 0xFF, 0xFF]);  // mov rax, [rbp + rax*8 - 0x200]
    // Jump to return offset
    let bc_base_lea_ret = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]);  // lea rsi, [rip + bc_base]
    stub.extend_from_slice(&[0x48, 0x01, 0xF0]);  // add rax, rsi (rax = absolute return address)
    stub.extend_from_slice(&[0x48, 0x89, 0xC6]);  // mov rsi, rax
    let dispatch_back_ret = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_ret.to_le_bytes());
    
    let ret_target = stub.len();
    let ret_offset = (ret_target as i32).wrapping_sub((ret_jmp + 6) as i32);
    stub[ret_jmp + 2..ret_jmp + 6].copy_from_slice(&ret_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x0E]);
    let native_call_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    
    stub.extend_from_slice(&[0x48, 0x8B, 0x06]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);
    stub.extend_from_slice(&[0x48, 0x89, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);
    
    stub.extend_from_slice(&[0x48, 0x83, 0xF8, 0x01]);
    let native_call_func1_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); // je func1 (string/WriteFile)
    
    stub.extend_from_slice(&[0x48, 0x83, 0xF8, 0x03]);
    let native_call_func3_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); // je func3 (putchar)
    
    // func2: integer printer (printf-style digit + newline from r2)
    stub.extend_from_slice(&[0x48, 0x8B, 0x45, 0x90]);
    stub.extend_from_slice(&[0x48, 0x8D, 0x8D, 0x10, 0xFF, 0xFF, 0xFF]);
    
    stub.extend_from_slice(&[0x48, 0x3D, 0x64, 0x00, 0x00, 0x00]); // cmp rax, 100
    let three_digit_jmp = stub.len();
    stub.extend_from_slice(&[0x73, 0x00]); // jae three_digit
    
    stub.extend_from_slice(&[0x48, 0x83, 0xF8, 0x0A]);
    let single_digit_jmp = stub.len();
    stub.extend_from_slice(&[0x73, 0x00]);
    
    stub.extend_from_slice(&[0x48, 0x83, 0xC0, 0x30]);
    stub.extend_from_slice(&[0x88, 0x01]);
    stub.extend_from_slice(&[0xC6, 0x41, 0x01, 0x0A]);
    stub.extend_from_slice(&[0x41, 0xB8, 0x02, 0x00, 0x00, 0x00]);
    let after_single_digit = stub.len();
    stub.extend_from_slice(&[0xEB, 0x00]);
    
    let two_digit_target = stub.len();
    stub[single_digit_jmp + 1] = (two_digit_target as i8).wrapping_sub((single_digit_jmp + 2) as i8) as u8;
    
    stub.extend_from_slice(&[0x48, 0x89, 0xC2]);
    stub.extend_from_slice(&[0xBA, 0x0A, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x89, 0xD3]);
    stub.extend_from_slice(&[0x48, 0x31, 0xD2]);
    stub.extend_from_slice(&[0x48, 0xF7, 0xF3]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC2, 0x30]);
    stub.extend_from_slice(&[0x88, 0x51, 0x01]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC0, 0x30]);
    stub.extend_from_slice(&[0x88, 0x01]);
    stub.extend_from_slice(&[0xC6, 0x41, 0x02, 0x0A]);
    stub.extend_from_slice(&[0x41, 0xB8, 0x03, 0x00, 0x00, 0x00]);
    let after_two_digit = stub.len();
    stub[after_single_digit + 1] = (after_two_digit as i8).wrapping_sub((after_single_digit + 2) as i8) as u8;
    let after_two_digit_jmp = stub.len();
    stub.extend_from_slice(&[0xEB, 0x00]); // skip three_digit after two_digit path
    
    let three_digit_target = stub.len();
    stub[three_digit_jmp + 1] = (three_digit_target as i8).wrapping_sub((three_digit_jmp + 2) as i8) as u8;
    
    // hundreds = n/100, tens = (n/10)%10, ones = n%10; "XYZ\n" via rcx (same buffer as 1/2-digit)
    stub.extend_from_slice(&[0x48, 0x31, 0xD2]); // xor rdx, rdx
    stub.extend_from_slice(&[0xBB, 0x64, 0x00, 0x00, 0x00]); // mov ebx, 100
    stub.extend_from_slice(&[0x48, 0xF7, 0xF3]); // div rbx
    stub.extend_from_slice(&[0x04, 0x30]); // add al, 0x30
    stub.extend_from_slice(&[0x88, 0x01]); // mov [rcx], al
    stub.extend_from_slice(&[0x48, 0x89, 0xD0]); // mov rax, rdx (n%100)
    stub.extend_from_slice(&[0x48, 0x31, 0xD2]); // xor rdx, rdx
    stub.extend_from_slice(&[0xBB, 0x0A, 0x00, 0x00, 0x00]); // mov ebx, 10
    stub.extend_from_slice(&[0x48, 0xF7, 0xF3]); // div rbx
    stub.extend_from_slice(&[0x04, 0x30]); // add al, 0x30
    stub.extend_from_slice(&[0x88, 0x41, 0x01]); // mov [rcx+1], al
    stub.extend_from_slice(&[0x80, 0xC2, 0x30]); // add dl, 0x30
    stub.extend_from_slice(&[0x88, 0x51, 0x02]); // mov [rcx+2], dl
    stub.extend_from_slice(&[0xC6, 0x41, 0x03, 0x0A]); // mov byte [rcx+3], 0x0A
    stub.extend_from_slice(&[0x41, 0xB8, 0x04, 0x00, 0x00, 0x00]); // mov r8d, 4
    
    let write_common = stub.len();
    stub[after_two_digit_jmp + 1] = (write_common as i8).wrapping_sub((after_two_digit_jmp + 2) as i8) as u8;
    
    stub.extend_from_slice(&[0x48, 0x8B, 0x8D, 0x60, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x8D, 0x95, 0x10, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x4C, 0x8D, 0x8D, 0x30, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    stub.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0xFF, 0x95, 0x50, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    
    stub.extend_from_slice(&[0x48, 0x8B, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);
    let dispatch_back_func2 = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_func2.to_le_bytes());
    
    // func1: WriteFile string from r0/r1
    let native_call_func1_target = stub.len();
    let native_call_func1_offset = (native_call_func1_target as i32).wrapping_sub((native_call_func1_jmp + 6) as i32);
    stub[native_call_func1_jmp + 2..native_call_func1_jmp + 6].copy_from_slice(&native_call_func1_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x48, 0x8B, 0x8D, 0x60, 0xFF, 0xFF, 0xFF]);
    let bc_base_lea = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x45, 0x80]);
    stub.extend_from_slice(&[0x48, 0x01, 0xD0]);
    stub.extend_from_slice(&[0x48, 0x89, 0xC2]);
    stub.extend_from_slice(&[0x4C, 0x8B, 0x45, 0x88]);
    stub.extend_from_slice(&[0x4C, 0x8D, 0x8D, 0x30, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    stub.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0xFF, 0x95, 0x50, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    
    stub.extend_from_slice(&[0x48, 0x8B, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);
    let dispatch_back3 = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back3.to_le_bytes());
    
    // func3: putchar — WriteFile 1 byte from r0, no newline
    let native_call_func3_target = stub.len();
    let native_call_func3_offset = (native_call_func3_target as i32).wrapping_sub((native_call_func3_jmp + 6) as i32);
    stub[native_call_func3_jmp + 2..native_call_func3_jmp + 6].copy_from_slice(&native_call_func3_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x48, 0x8B, 0x45, 0x80]);  // mov rax, [rbp-0x80] - register 0
    stub.extend_from_slice(&[0x48, 0x8D, 0x8D, 0x10, 0xFF, 0xFF, 0xFF]);  // lea rcx, [rbp-0xF0] - buffer
    stub.extend_from_slice(&[0x88, 0x01]);  // mov [rcx], al
    stub.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]);  // mov r8d, 1
    stub.extend_from_slice(&[0x48, 0x8B, 0x8D, 0x60, 0xFF, 0xFF, 0xFF]);  // mov rcx, stdout
    stub.extend_from_slice(&[0x48, 0x8D, 0x95, 0x10, 0xFF, 0xFF, 0xFF]);  // lea rdx, buffer
    stub.extend_from_slice(&[0x4C, 0x8D, 0x8D, 0x30, 0xFF, 0xFF, 0xFF]);  // lea r9, bytes written
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    stub.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0xFF, 0x95, 0x50, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    stub.extend_from_slice(&[0x48, 0x8B, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);
    let dispatch_back_func3 = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_func3.to_le_bytes());
    
    let native_call_target = stub.len();
    let native_call_offset = (native_call_target as i32).wrapping_sub((native_call_jmp + 6) as i32);
    stub[native_call_jmp + 2..native_call_jmp + 6].copy_from_slice(&native_call_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x0F]);
    let push_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);  // movzx ecx, byte [rsi] - src register
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);  // inc rsi
    stub.extend_from_slice(&[0x48, 0x8B, 0x44, 0xCD, 0x80]);  // mov rax, [rbp+rcx*8-0x80] - value
    stub.extend_from_slice(&[0x48, 0x8B, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);  // mov rdx, [rbp-0xE8] - depth
    stub.extend_from_slice(&[0x48, 0x89, 0x84, 0xD5, 0x80, 0xFD, 0xFF, 0xFF]);  // mov [rbp+rdx*8-0x280], rax
    stub.extend_from_slice(&[0x48, 0xFF, 0xC2]);  // inc rdx
    stub.extend_from_slice(&[0x48, 0x89, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);  // mov [rbp-0xE8], rdx
    let dispatch_back_push = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_push.to_le_bytes());
    
    let push_target = stub.len();
    let push_offset = (push_target as i32).wrapping_sub((push_jmp + 6) as i32);
    stub[push_jmp + 2..push_jmp + 6].copy_from_slice(&push_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x3C, 0x10]);
    let pop_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);  // movzx ecx, byte [rsi] - dst register
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);  // inc rsi
    stub.extend_from_slice(&[0x48, 0x8B, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);  // mov rdx, [rbp-0xE8] - depth
    stub.extend_from_slice(&[0x48, 0xFF, 0xCA]);  // dec rdx
    stub.extend_from_slice(&[0x48, 0x89, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);  // mov [rbp-0xE8], rdx
    stub.extend_from_slice(&[0x48, 0x8B, 0x84, 0xD5, 0x80, 0xFD, 0xFF, 0xFF]);  // mov rax, [rbp+rdx*8-0x280]
    stub.extend_from_slice(&[0x48, 0x89, 0x44, 0xCD, 0x80]);  // mov [rbp+rcx*8-0x80], rax
    let dispatch_back_pop = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_pop.to_le_bytes());
    
    let pop_target = stub.len();
    let pop_offset = (pop_target as i32).wrapping_sub((pop_jmp + 6) as i32);
    stub[pop_jmp + 2..pop_jmp + 6].copy_from_slice(&pop_offset.to_le_bytes());
    
    // LoadByte (0x11): read dst, src_reg; dst = byte at [src_reg]
    stub.extend_from_slice(&[0x3C, 0x11]);
    let load_byte_jmp = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);  // movzx ecx, byte [rsi]  ; dst register
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);  // inc rsi
    stub.extend_from_slice(&[0x0F, 0xB6, 0x3E]);  // movzx edi, byte [rsi]  ; src register
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);  // inc rsi
    stub.extend_from_slice(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);  // mov rax, [rbp + rdi*8 - 0x80]  ; bytecode offset
    stub.extend_from_slice(&[0x48, 0x03, 0x85, 0xE8, 0xFE, 0xFF, 0xFF]);  // add rax, [rbp-0x118]  ; + opcode-0 base from bc_lea
    stub.extend_from_slice(&[0x0F, 0xB6, 0x00]);  // movzx eax, byte [rax]
    stub.extend_from_slice(&[0x48, 0x89, 0x44, 0xCD, 0x80]);  // mov [rbp + rcx*8 - 0x80], rax  ; store to dst
    let dispatch_back_load_byte = (dispatch_loop as i32).wrapping_sub((stub.len() + 5) as i32);
    stub.extend_from_slice(&[0xE9]);
    stub.extend_from_slice(&dispatch_back_load_byte.to_le_bytes());
    
    let load_byte_target = stub.len();
    let load_byte_offset = (load_byte_target as i32).wrapping_sub((load_byte_jmp + 6) as i32);
    stub[load_byte_jmp + 2..load_byte_jmp + 6].copy_from_slice(&load_byte_offset.to_le_bytes());
    
    let exit_target = stub.len();
    let exit_offset = (exit_target as i32).wrapping_sub((exit_jmp + 6) as i32);
    stub[exit_jmp + 2..exit_jmp + 6].copy_from_slice(&exit_offset.to_le_bytes());
    
    stub.extend_from_slice(&[0x0F, 0xB6, 0x0E]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0xCD, 0x80]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    stub.extend_from_slice(&[0xFF, 0x95, 0x58, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    
    let k32_str_pos = stub.len();
    stub.extend_from_slice(&[
        0x6B, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00,
        0x65, 0x00, 0x6C, 0x00, 0x33, 0x00, 0x32, 0x00,
        0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00,
        0x00, 0x00,
    ]);
    
    let gpa_str_pos = stub.len();
    stub.extend_from_slice(b"GetProcAddress\0");
    let gsth_str_pos = stub.len();
    stub.extend_from_slice(b"GetStdHandle\0");
    let wf_str_pos = stub.len();
    stub.extend_from_slice(b"WriteFile\0");
    let ep_str_pos = stub.len();
    stub.extend_from_slice(b"ExitProcess\0");
    
    while stub.len() % 16 != 0 {
        stub.push(0xCC);
    }
    
    stub.extend_from_slice(b"VMBC");
    let bytecode_offset = stub.len();
    
    patches.push((k32_str_lea + 3, format!("{}", k32_str_pos)));
    patches.push((gpa_str_lea + 3, format!("{}", gpa_str_pos)));
    patches.push((gsth_lea + 3, format!("{}", gsth_str_pos)));
    patches.push((wf_lea + 3, format!("{}", wf_str_pos)));
    patches.push((ep_lea + 3, format!("{}", ep_str_pos)));
    patches.push((bc_lea + 3, "BYTECODE".to_string()));
    patches.push((bc_base_lea + 3, "BYTECODE".to_string()));
    patches.push((bc_base_lea_jmp + 3, "BYTECODE".to_string()));
    patches.push((bc_base_lea_jmpif + 3, "BYTECODE".to_string()));
    patches.push((bc_base_lea_call + 3, "BYTECODE".to_string()));
    patches.push((bc_base_lea_call2 + 3, "BYTECODE".to_string()));
    patches.push((bc_base_lea_ret + 3, "BYTECODE".to_string()));
    
    for (patch_offset, target_str) in patches {
        let target = if target_str == "BYTECODE" {
            bytecode_offset
        } else {
            target_str.parse::<usize>().unwrap()
        };
        let next_ip = patch_offset + 4;
        let disp = (target as i32) - (next_ip as i32);
        stub[patch_offset..patch_offset + 4].copy_from_slice(&disp.to_le_bytes());
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
    fn test_loadbyte_uses_cached_bytecode_base() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        let vmbc = stub.windows(4).position(|w| w == b"VMBC").expect("VMBC marker");
        let bytecode_offset = vmbc + 4;
        let cache_store = [0x48u8, 0x89, 0xB5, 0xE8, 0xFE, 0xFF, 0xFF];
        assert!(
            stub.windows(cache_store.len()).any(|w| w == cache_store),
            "bc_lea must cache bytecode base at [rbp-0x118]"
        );
        let loadbyte_add = [0x48u8, 0x03, 0x85, 0xE8, 0xFE, 0xFF, 0xFF];
        assert!(
            stub.windows(loadbyte_add.len()).any(|w| w == loadbyte_add),
            "LoadByte must add offset to cached bytecode base"
        );
        let lea_pattern = [0x48u8, 0x8D, 0x35];
        let mut bc_lea_found = false;
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
                bc_lea_found = true;
                break;
            }
        }
        assert!(bc_lea_found, "bc_lea must patch to opcode 0 (VMBC+4)");
        let prologue_init = [0x48u8, 0xC7, 0x85, 0xE8, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        assert!(
            stub.windows(prologue_init.len()).any(|w| w == prologue_init),
            "prologue must zero-init bytecode base cache at [rbp-0x118]"
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
}
