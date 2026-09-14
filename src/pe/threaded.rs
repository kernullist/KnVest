use crate::vm::block_map::{BlockMapPlan, META_WIRE_BYTE, META_OPERAND_LEN};
use crate::vm::dispatch::THREAD_TARGET_SIZE;
use crate::vm::isa_mode::IsaMode;
use crate::vm::layout::BytecodeLayout;
use crate::vm::opcode_map::OpcodeMap;
use crate::vm::OpCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InsnKind {
    Semantic(OpCode),
    SetBlockMap,
}

#[derive(Clone, Copy, Debug)]
struct InsnLayout {
    start: usize,
    kind: InsnKind,
    raw_len: usize,
}

fn enumerate_instructions(
    bytecode: &[u8],
    base_map: &OpcodeMap,
    block_plan: &BlockMapPlan,
    layout: &BytecodeLayout,
    dispatch_mode: crate::vm::DispatchMode,
    isa_mode: IsaMode,
) -> Vec<InsnLayout> {
    let mut out = Vec::new();
    let mut offset = 0;
    let mut current_bb: Option<u16> = None;
    while offset < bytecode.len() {
        let wire = bytecode[offset];
        if wire == META_WIRE_BYTE {
            let total = layout.insn_len(
                OpCode::SetBlockMap,
                META_OPERAND_LEN,
                dispatch_mode,
                true,
            );
            if offset + total > bytecode.len() {
                break;
            }
            let op_off = offset + layout.operands_offset_dispatch(OpCode::SetBlockMap, true, dispatch_mode);
            let bb_id = u16::from_le_bytes([bytecode[op_off], bytecode[op_off + 1]]);
            current_bb = Some(bb_id);
            out.push(InsnLayout {
                start: offset,
                kind: InsnKind::SetBlockMap,
                raw_len: total,
            });
            offset += total;
            continue;
        }
        let map = current_bb
            .map(|id| block_plan.map_for_tx_or_base(id, base_map))
            .unwrap_or_else(|| base_map.clone());
        let op = match map.decode(wire) {
            Some(op) => op,
            None => break,
        };
        let operand_len = op.operand_len_for_isa(isa_mode);
        let raw_len = layout.insn_len(op, operand_len, dispatch_mode, false);
        if offset + raw_len > bytecode.len() {
            break;
        }
        out.push(InsnLayout {
            start: offset,
            kind: InsnKind::Semantic(op),
            raw_len,
        });
        offset += raw_len;
    }
    out
}

/// Map a table-layout bytecode position to the threaded-layout position.
fn relocate_offset(insns: &[InsnLayout], old_pos: usize) -> usize {
    let pad = insns
        .iter()
        .filter(|i| i.start < old_pos)
        .count()
        * THREAD_TARGET_SIZE;
    old_pos + pad
}

fn code_section_end(insns: &[InsnLayout]) -> usize {
    insns
        .last()
        .map(|i| i.start + i.raw_len)
        .unwrap_or(0)
}

fn is_string_or_data_offset(insns: &[InsnLayout], value: usize, bytecode_len: usize) -> bool {
    let end = code_section_end(insns);
    // Pool offsets live in the tail past the lifted insn stream; small immediates do not.
    value >= end && value < bytecode_len
}

fn is_insn_start(insns: &[InsnLayout], value: usize) -> bool {
    insns.iter().any(|i| i.start == value)
}

fn patch_operands_for_threaded(
    kind: InsnKind,
    operands: &mut [u8],
    insns: &[InsnLayout],
    bytecode_len: usize,
    relocate: &dyn Fn(usize) -> usize,
) {
    let op = match kind {
        InsnKind::Semantic(op) => op,
        InsnKind::SetBlockMap => return,
    };
    match op {
        OpCode::Jmp | OpCode::Call => {
            if operands.len() >= 8 {
                let old = u64::from_le_bytes(operands[0..8].try_into().unwrap()) as usize;
                if is_insn_start(insns, old) {
                    let new = relocate(old);
                    operands[0..8].copy_from_slice(&(new as u64).to_le_bytes());
                }
            }
        }
        OpCode::JmpIf => {
            if operands.len() >= 9 {
                let old = u64::from_le_bytes(operands[1..9].try_into().unwrap()) as usize;
                if is_insn_start(insns, old) {
                    let new = relocate(old);
                    operands[1..9].copy_from_slice(&(new as u64).to_le_bytes());
                }
            }
        }
        OpCode::LoadImm | OpCode::LoadStr => {
            if operands.len() >= 9 {
                let old = u64::from_le_bytes(operands[1..9].try_into().unwrap()) as usize;
                if is_string_or_data_offset(insns, old, bytecode_len) {
                    let new = relocate(old);
                    operands[1..9].copy_from_slice(&(new as u64).to_le_bytes());
                }
            }
        }
        _ => {}
    }
}

/// Embed per-instruction handler rel32 targets after each opcode wire byte (L4c threaded).
/// Relocates jmp/call targets and embedded string offsets for the wider instruction encoding.
pub fn embed_thread_targets(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    block_plan: &BlockMapPlan,
    layout: &BytecodeLayout,
    isa_mode: IsaMode,
    handler_off_from_table: &dyn Fn(OpCode) -> i32,
    set_map_off: i32,
) -> Vec<u8> {
    let insns = enumerate_instructions(
        bytecode,
        opcode_map,
        block_plan,
        layout,
        crate::vm::DispatchMode::Table,
        isa_mode,
    );
    let code_end = code_section_end(&insns);
    let relocate = |old: usize| relocate_offset(&insns, old);

    let mut out = Vec::with_capacity(
        bytecode.len() + insns.len() * THREAD_TARGET_SIZE,
    );
    for insn in &insns {
        let handler_off = match insn.kind {
            InsnKind::SetBlockMap => set_map_off,
            InsnKind::Semantic(op) => handler_off_from_table(op),
        };
        out.push(bytecode[insn.start]);
        out.extend_from_slice(&handler_off.to_le_bytes());
        let tail_start = insn.start + 1;
        let tail_end = insn.start + insn.raw_len;
        if insn.kind == InsnKind::SetBlockMap {
            out.extend_from_slice(&bytecode[tail_start..tail_end]);
            continue;
        }
        let op = match insn.kind {
            InsnKind::Semantic(op) => op,
            InsnKind::SetBlockMap => unreachable!(),
        };
        let op_off = insn.start + layout.operands_offset(op, false);
        let operand_len = op.operand_len_for_isa(isa_mode);
        out.extend_from_slice(&bytecode[tail_start..op_off]);
        let mut operands = bytecode[op_off..op_off + operand_len].to_vec();
        patch_operands_for_threaded(insn.kind, &mut operands, &insns, bytecode.len(), &relocate);
        out.extend_from_slice(&operands);
        out.extend_from_slice(&bytecode[op_off + operand_len..tail_end]);
    }
    if code_end < bytecode.len() {
        out.extend_from_slice(&bytecode[code_end..]);
    }
    out
}

/// Handler offset from `handler_table` for a logical opcode (reads finalized stub bytes).
pub fn handler_offset_for_op(stub: &[u8], opcode_map: &OpcodeMap, op: OpCode) -> i32 {
    let table_base = handler_table_base(stub);
    let wire = opcode_map.encode(op) as usize;
    let patch_at = table_base + wire * 4;
    if patch_at + 4 > stub.len() {
        return 0;
    }
    i32::from_le_bytes(stub[patch_at..patch_at + 4].try_into().unwrap())
}

/// Handler offset for the L4e block-map refresh meta handler.
pub fn handler_offset_for_set_block_map(stub: &[u8]) -> i32 {
    let sig = [0x44u8, 0x0F, 0xB7, 0x06]; // movzx r8d, word [rsi]
    let table_base = handler_table_base(stub);
    let pos = stub
        .windows(sig.len())
        .position(|w| w == sig)
        .expect("h_set_block_map signature missing from stub");
    (pos as i64 - table_base as i64) as i32
}

pub fn handler_table_base(stub: &[u8]) -> usize {
    // L4e table: lea r10,[handler_table]; mov rbx,[rbp-0x128]; movsxd rax,[rbx+rax*4]
    for i in 0..stub.len().saturating_sub(18) {
        if stub[i..i + 3] == [0x4Cu8, 0x8D, 0x15]
            && stub[i + 7..i + 10] == [0x48, 0x8B, 0x9D]
            && stub[i + 14..i + 18] == [0x48, 0x63, 0x04, 0x83]
        {
            let disp = i32::from_le_bytes(stub[i + 3..i + 7].try_into().unwrap());
            return ((i + 7) as isize + disp as isize) as usize;
        }
    }
    // L4c threaded: movsxd rax,[rsi+1]; lea rbx,[handler_table]; add rax,rbx
    for i in 0..stub.len().saturating_sub(16) {
        if stub[i..i + 4] == [0x48, 0x63, 0x46, 0x01] {
            for j in i + 4..i.saturating_add(24).min(stub.len().saturating_sub(7)) {
                if stub[j..j + 3] == [0x48, 0x8D, 0x1D] {
                    let disp = i32::from_le_bytes(stub[j + 3..j + 7].try_into().unwrap());
                    return ((j + 7) as isize + disp as isize) as usize;
                }
            }
        }
    }
    // Legacy table: lea rbx,[handler_table] immediately before movsxd rax,[rbx+rax*4]
    let table_indexed = [0x48u8, 0x63, 0x04, 0x83];
    if let Some(idx) = stub.windows(table_indexed.len()).position(|w| w == table_indexed) {
        for i in (idx.saturating_sub(32)..idx).rev() {
            if stub[i..i + 3] == [0x48, 0x8D, 0x1D] {
                let disp = i32::from_le_bytes(stub[i + 3..i + 7].try_into().unwrap());
                return ((i + 7) as isize + disp as isize) as usize;
            }
        }
    }
    panic!("dispatch lea handler_table not found");
}

fn bytecode_starts_with_at(bytecode: &[u8], off: usize, needle: &[u8]) -> bool {
    bytecode.get(off..).is_some_and(|tail| tail.starts_with(needle))
}

/// First offset in `bytecode` where `needle` appears as a contiguous prefix match.
pub fn bytecode_prefix_offset(bytecode: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    bytecode
        .windows(needle.len())
        .position(|w| w.starts_with(needle))
}

/// Walk threaded bytecode and collect every `load_imm` immediate.
pub fn threaded_load_imm_immediates(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
) -> Vec<usize> {
    threaded_load_imm_immediates_with_blocks(bytecode, opcode_map, None)
}

/// Block-map-aware variant for L4e threaded bytecode.
pub fn threaded_load_imm_immediates_with_blocks(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    block_plan: Option<&BlockMapPlan>,
) -> Vec<usize> {
    threaded_load_imm_immediates_with_blocks_layout(
        bytecode,
        opcode_map,
        block_plan,
        &BytecodeLayout::identity(),
    )
}

pub fn threaded_load_imm_immediates_with_blocks_layout(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    block_plan: Option<&BlockMapPlan>,
    layout: &BytecodeLayout,
) -> Vec<usize> {
    let plan = block_plan.cloned().unwrap_or_default();
    let insns = enumerate_instructions(
        bytecode,
        opcode_map,
        &plan,
        layout,
        crate::vm::DispatchMode::Threaded,
        crate::vm::IsaMode::Reg,
    );
    let mut out = Vec::new();
    for insn in insns {
        if insn.kind != InsnKind::Semantic(OpCode::LoadImm) {
            continue;
        }
        let reg_off = insn.start
            + layout.operands_offset_dispatch(OpCode::LoadImm, false, crate::vm::DispatchMode::Threaded);
        let imm_off = reg_off + 1;
        if imm_off + 8 <= bytecode.len() {
            let imm = u64::from_le_bytes(bytecode[imm_off..imm_off + 8].try_into().unwrap()) as usize;
            out.push(imm);
        }
    }
    out
}

/// True when some threaded `load_imm` immediate equals `target`.
pub fn threaded_load_imm_points_at(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    target: usize,
) -> bool {
    threaded_load_imm_immediates(bytecode, opcode_map).contains(&target)
}

pub fn threaded_load_imm_points_at_with_blocks(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    block_plan: Option<&BlockMapPlan>,
    target: usize,
) -> bool {
    threaded_load_imm_immediates_with_blocks(bytecode, opcode_map, block_plan).contains(&target)
}

pub fn threaded_load_imm_points_at_with_blocks_layout(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    block_plan: Option<&BlockMapPlan>,
    layout: &BytecodeLayout,
    target: usize,
) -> bool {
    threaded_load_imm_immediates_with_blocks_layout(bytecode, opcode_map, block_plan, layout)
        .contains(&target)
}

/// Walk threaded bytecode and find a `load_imm` whose immediate points at `needle`.
/// Uses prefix matching so embedded pools may include a trailing NUL after `needle`.
pub fn threaded_load_imm_target(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    needle: &[u8],
) -> Option<usize> {
    threaded_load_imm_target_with_blocks(bytecode, opcode_map, None, needle)
}

pub fn threaded_load_imm_target_with_blocks(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    block_plan: Option<&BlockMapPlan>,
    needle: &[u8],
) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    for imm in threaded_load_imm_immediates_with_blocks(bytecode, opcode_map, block_plan) {
        if bytecode_starts_with_at(bytecode, imm, needle) {
            return Some(imm);
        }
    }
    None
}

/// Verify an embedded string pool: `needle` is present and a `load_imm` points at it.
pub fn threaded_string_pool_link(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    needle: &[u8],
) -> Option<(usize, usize)> {
    threaded_string_pool_link_with_blocks(bytecode, opcode_map, None, needle)
}

pub fn threaded_string_pool_link_with_blocks(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    block_plan: Option<&BlockMapPlan>,
    needle: &[u8],
) -> Option<(usize, usize)> {
    threaded_string_pool_link_with_blocks_layout(
        bytecode,
        opcode_map,
        block_plan,
        &BytecodeLayout::identity(),
        needle,
    )
}

pub fn threaded_string_pool_link_with_blocks_layout(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    block_plan: Option<&BlockMapPlan>,
    layout: &BytecodeLayout,
    needle: &[u8],
) -> Option<(usize, usize)> {
    let str_off = bytecode_prefix_offset(bytecode, needle)?;
    if threaded_load_imm_points_at_with_blocks_layout(bytecode, opcode_map, block_plan, layout, str_off) {
        return Some((str_off, str_off));
    }
    for imm in threaded_load_imm_immediates_with_blocks_layout(bytecode, opcode_map, block_plan, layout) {
        if bytecode_starts_with_at(bytecode, imm, needle) {
            return Some((str_off, imm));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::vm_stub::create_vm_interpreter_stub;
    use crate::vm::{BlockMapPlan, DispatchMode};

    fn stub_for(map: &OpcodeMap) -> Vec<u8> {
        create_vm_interpreter_stub(0, 0, map, DispatchMode::Table, 0, crate::vm::IsaMode::Reg, &crate::vm::BytecodeLayout::identity(), &[], &BlockMapPlan::default(), &[], &[], &crate::vm::NestedVmPlan::disabled())
            .0
    }

    fn embed(map: &OpcodeMap, stub: &[u8], raw: &[u8]) -> Vec<u8> {
        let plan = BlockMapPlan::default();
        let layout = BytecodeLayout::identity();
        let set_map = handler_offset_for_set_block_map(stub);
        embed_thread_targets(
            raw,
            map,
            &plan,
            &layout,
            crate::vm::IsaMode::Reg,
            &|op| handler_offset_for_op(stub, map, op),
            set_map,
        )
    }

    #[test]
    fn embed_thread_targets_preserves_logical_operands() {
        let map = OpcodeMap::from_seed(7);
        let stub = stub_for(&map);
        let raw = {
            let mut b = vec![map.encode(OpCode::LoadImm), 0];
            b.extend_from_slice(&42u64.to_le_bytes());
            b.push(map.encode(OpCode::Exit));
            b.push(0);
            b
        };
        let threaded = embed(&map, &stub, &raw);
        assert_eq!(threaded.len(), raw.len() + 2 * THREAD_TARGET_SIZE);
        assert_eq!(threaded[0], raw[0]);
        assert_eq!(
            &threaded[1 + THREAD_TARGET_SIZE..1 + THREAD_TARGET_SIZE + 9],
            &raw[1..10]
        );
    }

    #[test]
    fn embed_thread_targets_relocates_jmp_operand() {
        let map = OpcodeMap::from_seed(1);
        let stub = stub_for(&map);
        let mut raw = vec![map.encode(OpCode::LoadImm), 0];
        raw.extend_from_slice(&1u64.to_le_bytes());
        raw.push(map.encode(OpCode::Jmp));
        raw.extend_from_slice(&19u64.to_le_bytes());
        raw.push(map.encode(OpCode::LoadImm));
        raw.push(0);
        raw.extend_from_slice(&2u64.to_le_bytes());
        raw.push(map.encode(OpCode::Exit));
        raw.push(0);

        let threaded = embed(&map, &stub, &raw);
        let jmp_insn_start = 1 + THREAD_TARGET_SIZE + 9;
        let target = u64::from_le_bytes(
            threaded[jmp_insn_start + 1 + THREAD_TARGET_SIZE..jmp_insn_start + 1 + THREAD_TARGET_SIZE + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(target, 27, "jmp target must account for threaded rel32 padding");
        assert_eq!(threaded[27], map.encode(OpCode::LoadImm));
    }

    #[test]
    fn embed_thread_targets_appends_aligned_string_pool() {
        let map = OpcodeMap::from_seed(2);
        let stub = stub_for(&map);
        let msg = b"Hello, World!\n\0";
        let mut raw = vec![map.encode(OpCode::LoadImm), 0];
        raw.extend_from_slice(&0u64.to_le_bytes());
        raw.push(map.encode(OpCode::Exit));
        raw.push(0);
        let string_off = ((raw.len() + 15) / 16) * 16;
        while raw.len() < string_off {
            raw.push(0x00);
        }
        raw[2..10].copy_from_slice(&(string_off as u64).to_le_bytes());
        raw.extend_from_slice(msg);

        let threaded = embed(&map, &stub, &raw);
        assert!(
            threaded.windows(msg.len()).any(|w| w == msg),
            "threaded embed must preserve trailing string pool"
        );
        let ptr = threaded_load_imm_target(&threaded, &map, b"Hello, World!")
            .expect("load_imm string ptr");
        assert!(threaded[ptr..].starts_with(b"Hello, World!"));
        let (pool, imm) = threaded_string_pool_link(&threaded, &map, b"Hello, World!")
            .expect("string pool link");
        assert_eq!(pool, imm);
    }

    #[test]
    fn embed_thread_targets_relocates_unaligned_string_pool() {
        let map = OpcodeMap::from_seed(2);
        let stub = stub_for(&map);
        let msg = b"knvest\0";
        let mut raw = vec![map.encode(OpCode::LoadImm), 0];
        raw.extend_from_slice(&0u64.to_le_bytes());
        raw.push(map.encode(OpCode::Exit));
        raw.push(0);
        // Deliberately unaligned pool tail (not a multiple of 16).
        let string_off = raw.len();
        raw[2..10].copy_from_slice(&(string_off as u64).to_le_bytes());
        raw.extend_from_slice(msg);

        let threaded = embed(&map, &stub, &raw);
        let imm = u64::from_le_bytes(
            threaded[1 + THREAD_TARGET_SIZE + 1..1 + THREAD_TARGET_SIZE + 9]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(&threaded[imm..imm + msg.len()], msg);
        threaded_string_pool_link(&threaded, &map, b"knvest")
            .expect("unaligned pool must stay linked to load_imm");
    }

    #[test]
    fn embed_thread_targets_relocates_string_offset() {
        let map = OpcodeMap::from_seed(2);
        let stub = stub_for(&map);
        let msg = b"knvest\0";
        let mut raw = vec![map.encode(OpCode::LoadImm), 0];
        raw.extend_from_slice(&0u64.to_le_bytes());
        let string_off = ((raw.len() + 15) / 16) * 16;
        while raw.len() < string_off {
            raw.push(0x00);
        }
        raw[2..10].copy_from_slice(&(string_off as u64).to_le_bytes());
        raw.extend_from_slice(msg);

        let threaded = embed(&map, &stub, &raw);
        let imm = u64::from_le_bytes(
            threaded[1 + THREAD_TARGET_SIZE + 1..1 + THREAD_TARGET_SIZE + 9]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(&threaded[imm..imm + msg.len()], msg);
    }
}
