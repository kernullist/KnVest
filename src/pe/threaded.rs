use crate::vm::block_map::{BlockMapPlan, META_WIRE_BYTE, META_OPERAND_LEN};
use crate::vm::dispatch::THREAD_TARGET_SIZE;
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

fn enumerate_instructions(bytecode: &[u8], base_map: &OpcodeMap, block_plan: &BlockMapPlan) -> Vec<InsnLayout> {
    let mut out = Vec::new();
    let mut offset = 0;
    let mut current_bb: Option<u16> = None;
    while offset < bytecode.len() {
        let wire = bytecode[offset];
        if wire == META_WIRE_BYTE {
            if offset + 1 + META_OPERAND_LEN > bytecode.len() {
                break;
            }
            let bb_id = u16::from_le_bytes([bytecode[offset + 1], bytecode[offset + 2]]);
            current_bb = Some(bb_id);
            out.push(InsnLayout {
                start: offset,
                kind: InsnKind::SetBlockMap,
                raw_len: 1 + META_OPERAND_LEN,
            });
            offset += 1 + META_OPERAND_LEN;
            continue;
        }
        let map = current_bb
            .map(|id| block_plan.map_for_bb_or_base(id, base_map))
            .unwrap_or_else(|| base_map.clone());
        let op = match map.decode(wire) {
            Some(op) => op,
            None => break,
        };
        let operand_len = op.operand_len();
        let raw_len = 1 + operand_len;
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
    handler_off_from_table: &dyn Fn(OpCode) -> i32,
    set_map_off: i32,
) -> Vec<u8> {
    let insns = enumerate_instructions(bytecode, opcode_map, block_plan);
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
        if insn.kind == InsnKind::SetBlockMap {
            out.extend_from_slice(&bytecode[insn.start + 1..insn.start + insn.raw_len]);
            continue;
        }
        let mut operands = bytecode[insn.start + 1..insn.start + insn.raw_len].to_vec();
        patch_operands_for_threaded(insn.kind, &mut operands, &insns, bytecode.len(), &relocate);
        out.extend_from_slice(&operands);
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
    let sig = [0x45u8, 0x0F, 0xB7, 0x06]; // movzx r8d, word [rsi]
    let table_base = handler_table_base(stub);
    let pos = stub
        .windows(sig.len())
        .position(|w| w == sig)
        .expect("h_set_block_map signature missing from stub");
    (pos as i64 - table_base as i64) as i32
}

pub fn handler_table_base(stub: &[u8]) -> usize {
    let dispatch_lea = [0x48u8, 0x8D, 0x1D];
    for i in 0..stub.len().saturating_sub(7) {
        if stub[i..i + 3] == dispatch_lea {
            let disp = i32::from_le_bytes([stub[i + 3], stub[i + 4], stub[i + 5], stub[i + 6]]);
            return ((i + 7) as isize + disp as isize) as usize;
        }
    }
    panic!("dispatch lea rbx,[handler_table] not found");
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
    let mut out = Vec::new();
    let mut offset = 0;
    let mut current_map = opcode_map.clone();
    while offset < bytecode.len() {
        if bytecode[offset] == META_WIRE_BYTE {
            if offset + 1 + META_OPERAND_LEN <= bytecode.len() {
                let bb_id = u16::from_le_bytes([bytecode[offset + 1], bytecode[offset + 2]]);
                current_map = block_plan
                    .map(|p| p.map_for_bb_or_base(bb_id, opcode_map))
                    .unwrap_or_else(|| BlockMapPlan::block_opcode_map(opcode_map.seed(), bb_id as usize));
                offset += 1 + META_OPERAND_LEN + THREAD_TARGET_SIZE;
                continue;
            }
            break;
        }
        let wire = bytecode[offset];
        let op = match current_map.decode(wire) {
            Some(op) => op,
            None => break,
        };
        let operand_len = op.operand_len();
        let threaded_insn_len = 1 + THREAD_TARGET_SIZE + operand_len;
        if offset + threaded_insn_len > bytecode.len() {
            break;
        }
        if op == OpCode::LoadImm && operand_len >= 9 {
            let imm = u64::from_le_bytes(
                bytecode[offset + 1 + THREAD_TARGET_SIZE + 1..offset + 1 + THREAD_TARGET_SIZE + 9]
                    .try_into()
                    .unwrap(),
            ) as usize;
            out.push(imm);
        }
        offset += threaded_insn_len;
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
    let str_off = bytecode_prefix_offset(bytecode, needle)?;
    if threaded_load_imm_points_at_with_blocks(bytecode, opcode_map, block_plan, str_off) {
        return Some((str_off, str_off));
    }
    threaded_load_imm_target_with_blocks(bytecode, opcode_map, block_plan, needle)
        .map(|imm| (str_off, imm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::vm_stub::create_vm_interpreter_stub;
    use crate::vm::{BlockMapPlan, DispatchMode};

    fn stub_for(map: &OpcodeMap) -> Vec<u8> {
        create_vm_interpreter_stub(0, 0, map, DispatchMode::Table, &[], &BlockMapPlan::default(), &[], &[])
            .0
    }

    fn embed(map: &OpcodeMap, stub: &[u8], raw: &[u8]) -> Vec<u8> {
        let plan = BlockMapPlan::default();
        let set_map = handler_offset_for_set_block_map(stub);
        embed_thread_targets(raw, map, &plan, &|op| handler_offset_for_op(stub, map, op), set_map)
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
