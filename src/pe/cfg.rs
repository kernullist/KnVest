use super::lifter::{decode_instruction, X64Instruction, X64InstrKind};
use super::parser::{PEFile, PEResult};
use std::collections::{HashSet, VecDeque};

/// Maximum bytes to disassemble per CFG function (safety bound for CRT).
pub const MAX_FUNCTION_BYTES: usize = 0x2000;

/// Maximum bytes to scan backward for a prologue when resolving a call target.
pub const PROLOGUE_SCAN_BACK: usize = 64;

/// Collect file offsets of functions reachable from `entry_file_offset` via direct
/// near calls within the `.text` (or `CODE`) section.
pub fn collect_cfg_entries(
    pe: &PEFile,
    entry_file_offset: usize,
    text_start: usize,
    text_end: usize,
) -> PEResult<Vec<usize>> {
    let mut worklist = VecDeque::new();
    let mut visited_entries = HashSet::new();
    let mut result = Vec::new();

    let entry = resolve_function_entry(&pe.data, entry_file_offset, text_start, text_end);
    worklist.push_back(entry);

    while let Some(func_off) = worklist.pop_front() {
        if func_off < text_start || func_off >= text_end {
            continue;
        }
        if !visited_entries.insert(func_off) {
            continue;
        }
        result.push(func_off);

        let max_end = (func_off + MAX_FUNCTION_BYTES).min(text_end);
        let code = &pe.data[func_off..max_end];
        let instrs = disassemble_cfg_function(code, func_off);

        for instr in &instrs {
            if let X64InstrKind::Call { target_offset } = instr.kind {
                let target = (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                if target >= text_start && target < text_end {
                    let callee_entry =
                        resolve_function_entry(&pe.data, target, text_start, text_end);
                    if !visited_entries.contains(&callee_entry) {
                        worklist.push_back(callee_entry);
                    }
                }
            }
        }
    }

    result.sort_unstable();
    Ok(result)
}

/// Disassemble one function from `entry` until `ret` or byte limit (no 0x55 boundary break).
pub fn disassemble_cfg_function(code: &[u8], entry_file_offset: usize) -> Vec<X64Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0usize;
    let max_instrs = 512;

    while offset < code.len() && instructions.len() < max_instrs {
        let start_offset = entry_file_offset + offset;
        let remaining = &code[offset..];
        if remaining.is_empty() {
            break;
        }

        let mut instr_bytes = Vec::new();
        let rel_offset = offset;
        let kind =
            decode_instruction(remaining, &mut instr_bytes, &mut offset);

        instructions.push(X64Instruction {
            offset: start_offset,
            bytes: instr_bytes,
            kind: kind.clone(),
        });

        if matches!(kind, X64InstrKind::Ret) {
            break;
        }

        // Guard against infinite loops on bad data.
        if offset == rel_offset {
            break;
        }
    }

    instructions
}

/// Resolve a call target to a function entry: prefer `push rbp` prologue scan, else use target.
pub fn resolve_function_entry(
    pe_data: &[u8],
    target: usize,
    text_start: usize,
    text_end: usize,
) -> usize {
    if target < text_start || target >= text_end {
        return target;
    }

    // Already at a known prologue.
    if is_prologue_start(pe_data, target) {
        return target;
    }

    let scan_start = target.saturating_sub(PROLOGUE_SCAN_BACK).max(text_start);
    for off in (scan_start..target).rev() {
        if is_prologue_start(pe_data, off) {
            return off;
        }
    }

    // Prologue-less / MSVC-ish: use the call target as the entry when it decodes cleanly.
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
        let text = pe.get_section(".text").unwrap();
        let text_start = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let text_end = text_start + text.size_of_raw_data as usize;

        // main is at .text+0x20 in the fixture
        let main_off = text_start + 0x20;
        let entries = collect_cfg_entries(&pe, main_off, text_start, text_end).unwrap();
        assert!(entries.contains(&main_off), "main entry: {:?}", entries);
        assert!(
            entries.iter().any(|&e| e < main_off),
            "CFG should collect a callee before main: {:?}",
            entries
        );
        assert!(entries.len() >= 2);
    }

    #[test]
    fn cfg_prologue_less_entry_accepted() {
        let pe_data = test_pe::create_pe64_with_callee();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_start = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let text_end = text_start + text.size_of_raw_data as usize;

        // Direct target without push rbp prologue at text_start+0x10
        let bare = text_start + 0x10;
        let entry = resolve_function_entry(&pe.data, bare, text_start, text_end);
        assert_eq!(entry, bare);
    }

    #[test]
    fn disassemble_cfg_function_stops_at_ret() {
        let code = [0xB8u8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90];
        let instrs = disassemble_cfg_function(&code, 0x100);
        assert!(instrs.iter().any(|i| matches!(i.kind, X64InstrKind::Ret)));
        assert_eq!(instrs.last().map(|i| i.offset), Some(0x105));
    }
}
