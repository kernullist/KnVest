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

/// One basic block in a lifted function window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    pub id: usize,
    pub start: usize,
    pub end: usize,
    pub leader_idx: usize,
    pub tail_idx: usize,
    pub has_back_edge: bool,
    pub native_eligible: bool,
    /// True when another BB branches backward to this block's entry (loop head).
    pub is_loop_header: bool,
}

/// Split a linear instruction list into basic blocks from `entry` until the first `ret`.
pub fn build_basic_blocks(instrs: &[X64Instruction], entry: usize) -> Vec<BasicBlock> {
    if instrs.is_empty() {
        return Vec::new();
    }

    let main_indices: Vec<usize> = instrs
        .iter()
        .enumerate()
        .filter(|(_, i)| i.offset >= entry)
        .map(|(idx, _)| idx)
        .collect();
    if main_indices.is_empty() {
        return Vec::new();
    }

    let mut leaders = HashSet::new();
    leaders.insert(main_indices[0]);

    for &idx in &main_indices {
        let instr = &instrs[idx];
        if let Some(target) = branch_target_offset(instr) {
            let abs = (instr.offset as i64 + instr.bytes.len() as i64 + target as i64) as usize;
            if instrs.iter().any(|i| i.offset == abs) {
                leaders.insert(idx_for_offset(instrs, abs));
            }
        }
        if is_block_end(&instr.kind) {
            if idx + 1 < instrs.len() && instrs[idx + 1].offset >= entry {
                leaders.insert(idx + 1);
            }
        }
    }

    let mut leader_list: Vec<usize> = leaders.into_iter().collect();
    leader_list.sort_unstable_by_key(|&idx| instrs[idx].offset);

    let mut blocks = Vec::new();
    for (id, &leader_idx) in leader_list.iter().enumerate() {
        let start = instrs[leader_idx].offset;
        let next_leader = leader_list
            .iter()
            .copied()
            .find(|&idx| instrs[idx].offset > start)
            .unwrap_or(main_indices[main_indices.len() - 1] + 1);
        let tail_idx = if next_leader > 0 {
            next_leader - 1
        } else {
            leader_idx
        };
        let end = instrs[tail_idx].offset + instrs[tail_idx].bytes.len();
        let has_back_edge = (leader_idx..=tail_idx).any(|idx| {
            branch_target_offset(&instrs[idx]).map_or(false, |rel| {
                let target = (instrs[idx].offset as i64
                    + instrs[idx].bytes.len() as i64
                    + rel as i64) as usize;
                target <= start
            })
        });
        let is_loop_header = false;
        let native_eligible = is_native_eligible(instrs, leader_idx, tail_idx);
        blocks.push(BasicBlock {
            id,
            start,
            end,
            leader_idx,
            tail_idx,
            has_back_edge,
            native_eligible,
            is_loop_header,
        });
    }

    let incoming: Vec<bool> = blocks
        .iter()
        .map(|bb| incoming_back_edge_target(&blocks, instrs, bb.start))
        .collect();
    for (bb, inc) in blocks.iter_mut().zip(incoming) {
        if inc {
            bb.is_loop_header = true;
            bb.has_back_edge = true;
        }
    }

    blocks
}

fn incoming_back_edge_target(
    blocks: &[BasicBlock],
    instrs: &[X64Instruction],
    target_start: usize,
) -> bool {
    for bb in blocks {
        for idx in bb.leader_idx..=bb.tail_idx {
            if let Some(rel) = branch_target_offset(&instrs[idx]) {
                let src = instrs[idx].offset;
                let target =
                    (src as i64 + instrs[idx].bytes.len() as i64 + rel as i64) as usize;
                if target == target_start && target < src {
                    return true;
                }
            }
        }
    }
    false
}

fn idx_for_offset(instrs: &[X64Instruction], offset: usize) -> usize {
    instrs
        .iter()
        .enumerate()
        .find(|(_, i)| i.offset == offset)
        .map(|(idx, _)| idx)
        .unwrap_or(0)
}

fn branch_target_offset(instr: &X64Instruction) -> Option<i32> {
    match &instr.kind {
        X64InstrKind::Jmp { target_offset }
        | X64InstrKind::Je { target_offset }
        | X64InstrKind::Jne { target_offset }
        | X64InstrKind::Jl { target_offset }
        | X64InstrKind::Jle { target_offset }
        | X64InstrKind::Jg { target_offset }
        | X64InstrKind::Jge { target_offset }
        | X64InstrKind::Call { target_offset } => Some(*target_offset),
        _ => None,
    }
}

fn is_block_end(kind: &X64InstrKind) -> bool {
    matches!(
        kind,
        X64InstrKind::Jmp { .. }
            | X64InstrKind::Je { .. }
            | X64InstrKind::Jne { .. }
            | X64InstrKind::Jl { .. }
            | X64InstrKind::Jle { .. }
            | X64InstrKind::Jg { .. }
            | X64InstrKind::Jge { .. }
            | X64InstrKind::Ret
            | X64InstrKind::Call { .. }
            | X64InstrKind::CallIndRip { .. }
    )
}

fn is_native_eligible(instrs: &[X64Instruction], leader_idx: usize, tail_idx: usize) -> bool {
    for idx in leader_idx..tail_idx {
        if branch_target_offset(&instrs[idx]).is_some() {
            return false;
        }
    }
    match &instrs[tail_idx].kind {
        X64InstrKind::Ret => true,
        X64InstrKind::Call { .. } | X64InstrKind::CallIndRip { .. } => false,
        X64InstrKind::Jmp { .. }
        | X64InstrKind::Je { .. }
        | X64InstrKind::Jne { .. }
        | X64InstrKind::Jl { .. }
        | X64InstrKind::Jle { .. }
        | X64InstrKind::Jg { .. }
        | X64InstrKind::Jge { .. } => false,
        _ => tail_idx == leader_idx || true,
    }
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

/// Control-transfer edge `(pred_bb_id, succ_bb_id)` within one lifted function window.
pub fn collect_cfg_edges(blocks: &[BasicBlock], instrs: &[X64Instruction]) -> Vec<(u16, u16)> {
    if blocks.is_empty() {
        return Vec::new();
    }
    let mut edges = Vec::new();
    let mut block_by_start = std::collections::HashMap::new();
    for bb in blocks {
        block_by_start.insert(bb.start, bb.id);
    }

    for bb in blocks {
        let tail = &instrs[bb.tail_idx];
        let next_bb = blocks
            .iter()
            .find(|b| b.start >= bb.end)
            .map(|b| b.id as u16);

        match &tail.kind {
            X64InstrKind::Call { target_offset } => {
                let target = branch_target_abs(tail, *target_offset);
                if let Some(&succ) = block_by_start.get(&target) {
                    edges.push((bb.id as u16, succ as u16));
                }
                if let Some(succ) = next_bb {
                    edges.push((bb.id as u16, succ));
                }
            }
            X64InstrKind::Jmp { target_offset } => {
                let target = branch_target_abs(tail, *target_offset);
                if let Some(&succ) = block_by_start.get(&target) {
                    edges.push((bb.id as u16, succ as u16));
                }
            }
            X64InstrKind::Je { target_offset }
            | X64InstrKind::Jne { target_offset }
            | X64InstrKind::Jl { target_offset }
            | X64InstrKind::Jle { target_offset }
            | X64InstrKind::Jg { target_offset }
            | X64InstrKind::Jge { target_offset } => {
                let target = branch_target_abs(tail, *target_offset);
                if let Some(&succ) = block_by_start.get(&target) {
                    edges.push((bb.id as u16, succ as u16));
                }
                if let Some(succ) = next_bb {
                    edges.push((bb.id as u16, succ));
                }
            }
            X64InstrKind::Ret => {}
            _ => {
                if let Some(succ) = next_bb {
                    edges.push((bb.id as u16, succ));
                }
            }
        }
    }

    edges.push((crate::vm::block_map::ENTRY_PRED_BB, 0));
    edges.sort_unstable();
    edges.dedup();
    edges
}

pub fn incoming_edge_counts(edges: &[(u16, u16)]) -> std::collections::HashMap<u16, usize> {
    let mut counts = std::collections::HashMap::new();
    for &(_, succ) in edges {
        counts.entry(succ).and_modify(|c| *c += 1).or_insert(1);
    }
    counts
}

fn branch_target_abs(instr: &X64Instruction, rel: i32) -> usize {
    (instr.offset as i64 + instr.bytes.len() as i64 + rel as i64) as usize
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
