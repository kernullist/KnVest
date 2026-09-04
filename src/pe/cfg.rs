use super::imports::ImportTable;
use super::lifter::{decode_instruction, X64Instruction, X64InstrKind};
use super::parser::{PEFile, PEResult};
use super::thunk::is_non_liftable_target;
use std::collections::{HashSet, VecDeque};

/// Maximum bytes to disassemble per CFG function (safety bound).
pub const MAX_FUNCTION_BYTES: usize = 0x400;

/// Maximum bytes to scan backward for a prologue when resolving a call target.
pub const PROLOGUE_SCAN_BACK: usize = 48;

/// Max user functions to lift (main + pre-main callees).
pub const MAX_CFG_FUNCTIONS: usize = 16;

/// L2 pre-main distance cap from main.
pub const MAX_PREMAIN_DISTANCE: usize = 0x800;

/// Collect liftable function entry points: main/`--rva` entry plus pre-main user callees.
/// Does NOT follow calls into import thunks, IAT slots, or CRT code at/after main.
pub fn collect_cfg_entries(
    pe: &PEFile,
    entry_file_offset: usize,
    main_file_offset: usize,
    text_start: usize,
    text_end: usize,
    imports: &ImportTable,
    explicit_rva: bool,
) -> PEResult<Vec<usize>> {
    let mut worklist = VecDeque::new();
    let mut visited = HashSet::new();

    let entry = resolve_callee_entry(&pe.data, entry_file_offset, main_file_offset, text_start, text_end);
    worklist.push_back(entry);

    while let Some(func_off) = worklist.pop_front() {
        if visited.len() >= MAX_CFG_FUNCTIONS {
            break;
        }
        if func_off < text_start || func_off >= text_end {
            continue;
        }
        if !visited.insert(func_off) {
            continue;
        }

        let max_end = (func_off + MAX_FUNCTION_BYTES).min(text_end);
        let code = &pe.data[func_off..max_end];
        let instrs = disassemble_cfg_function(code, func_off);

        for instr in &instrs {
            let target = match &instr.kind {
                X64InstrKind::Call { target_offset } => {
                    (instr.offset as i32 + instr.bytes.len() as i32 + *target_offset) as usize
                }
                X64InstrKind::CallIndRip { .. } => continue,
                _ => continue,
            };

            if !should_follow_call_target(
                pe,
                imports,
                target,
                main_file_offset,
                entry_file_offset,
                text_start,
                text_end,
                explicit_rva,
            ) {
                continue;
            }

            let callee =
                resolve_callee_entry(&pe.data, target, main_file_offset, text_start, text_end);
            if !visited.contains(&callee) {
                worklist.push_back(callee);
            }
        }
    }

    let mut result: Vec<usize> = visited.into_iter().collect();
    result.sort_unstable();
    Ok(result)
}

fn should_follow_call_target(
    pe: &PEFile,
    imports: &ImportTable,
    target: usize,
    main_file_offset: usize,
    entry_file_offset: usize,
    text_start: usize,
    text_end: usize,
    explicit_rva: bool,
) -> bool {
    if target < text_start || target >= text_end {
        return false;
    }
    if is_non_liftable_target(pe, imports, target) {
        return false;
    }

    if explicit_rva && entry_file_offset != main_file_offset {
        // `--rva`: follow reachable user callees around the chosen entry, but never into
        // the post-main CRT region that MinGW links into .text.
        if target >= main_file_offset {
            return false;
        }
        let dist = if target < entry_file_offset {
            entry_file_offset - target
        } else {
            target - entry_file_offset
        };
        return dist < MAX_PREMAIN_DISTANCE;
    }

    // Default (auto main): L2 rule — only pre-main callees within distance window.
    if target >= main_file_offset {
        return false;
    }
    main_file_offset - target < MAX_PREMAIN_DISTANCE
}

/// Disassemble one function from `entry` until `ret` or byte limit.
pub fn disassemble_cfg_function(code: &[u8], entry_file_offset: usize) -> Vec<X64Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0usize;
    let max_instrs = 200;

    while offset < code.len() && instructions.len() < max_instrs {
        let start_offset = entry_file_offset + offset;
        let remaining = &code[offset..];
        if remaining.is_empty() {
            break;
        }

        let mut instr_bytes = Vec::new();
        let rel_offset = offset;
        let kind = decode_instruction(remaining, &mut instr_bytes, &mut offset, start_offset as u64);

        instructions.push(X64Instruction {
            offset: start_offset,
            bytes: instr_bytes,
            kind: kind.clone(),
        });

        if matches!(kind, X64InstrKind::Ret) {
            break;
        }
        if offset == rel_offset {
            break;
        }
    }

    instructions
}

/// Disassemble main only until the first `ret` (L2 main window).
pub fn disassemble_main_window(
    pe_data: &[u8],
    main_file_offset: usize,
    text_end: usize,
) -> Vec<X64Instruction> {
    let max_len = (main_file_offset + 500).min(text_end).saturating_sub(main_file_offset);
    if max_len == 0 {
        return Vec::new();
    }
    let code = &pe_data[main_file_offset..main_file_offset + max_len];
    let mut instructions = Vec::new();
    let mut offset = 0usize;

    while offset < code.len() && instructions.len() < 100 {
        let start_offset = main_file_offset + offset;
        let remaining = &code[offset..];
        let mut instr_bytes = Vec::new();
        let rel = offset;
        let kind = decode_instruction(remaining, &mut instr_bytes, &mut offset, start_offset as u64);
        instructions.push(X64Instruction {
            offset: start_offset,
            bytes: instr_bytes,
            kind: kind.clone(),
        });
        if matches!(kind, X64InstrKind::Ret) {
            break;
        }
        if offset == rel {
            break;
        }
    }
    instructions
}

fn resolve_callee_entry(
    pe_data: &[u8],
    target: usize,
    main_file_offset: usize,
    text_start: usize,
    text_end: usize,
) -> usize {
    if target < text_start || target >= text_end {
        return target;
    }
    if main_file_offset > target && main_file_offset - target >= MAX_PREMAIN_DISTANCE {
        return target;
    }
    if is_prologue_start(pe_data, target) {
        return target;
    }
    let search_start = target.saturating_sub(PROLOGUE_SCAN_BACK).max(text_start);
    for off in (search_start..target).rev() {
        if is_prologue_start(pe_data, off) {
            return off;
        }
    }
    target
}

fn is_prologue_start(pe_data: &[u8], off: usize) -> bool {
    pe_data.get(off) == Some(&0x55)
        && pe_data.get(off + 1) == Some(&0x48)
        && pe_data.get(off + 2) == Some(&0x89)
        && pe_data.get(off + 3) == Some(&0xE5)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::parser::PEFile;
    use crate::pe::test_pe;

    #[test]
    fn cfg_collects_callee_from_main() {
        let pe_data = test_pe::create_pe64_with_callee();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let imports = pe.parse_imports().unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_start = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let text_end = text_start + text.size_of_raw_data as usize;
        let main_off = text_start + 0x20;
        let entries =
            collect_cfg_entries(&pe, main_off, main_off, text_start, text_end, &imports, false)
                .unwrap();
        assert!(entries.contains(&main_off));
        assert!(entries.iter().any(|&e| e < main_off));
        assert!(entries.len() <= MAX_CFG_FUNCTIONS);
    }

    #[test]
    fn cfg_does_not_follow_forward_crt_call() {
        let pe_data = test_pe::create_pe64_with_forward_crt_call();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let imports = pe.parse_imports().unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_start = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let text_end = text_start + text.size_of_raw_data as usize;
        let main_off = text_start + 0x20;
        let entries =
            collect_cfg_entries(&pe, main_off, main_off, text_start, text_end, &imports, false)
                .unwrap();
        assert_eq!(entries.len(), 1, "only main, not CRT: {:?}", entries);
    }

    #[test]
    fn disassemble_cfg_function_stops_at_ret() {
        let code = [0xB8u8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90];
        let instrs = disassemble_cfg_function(&code, 0x100);
        assert!(instrs.iter().any(|i| matches!(i.kind, X64InstrKind::Ret)));
    }
}
