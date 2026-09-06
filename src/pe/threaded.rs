use crate::vm::dispatch::THREAD_TARGET_SIZE;
use crate::vm::opcode_map::OpcodeMap;
use crate::vm::OpCode;

#[derive(Clone, Copy, Debug)]
struct InsnLayout {
    start: usize,
    op: OpCode,
    raw_len: usize,
}

fn enumerate_instructions(bytecode: &[u8], opcode_map: &OpcodeMap) -> Vec<InsnLayout> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < bytecode.len() {
        let wire = bytecode[offset];
        let op = match opcode_map.decode(wire) {
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
            op,
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

fn is_string_or_data_offset(insns: &[InsnLayout], value: usize) -> bool {
    let end = code_section_end(insns);
    // Embedded literals are 16-byte aligned past the insn stream; small immediates are not.
    value >= end && value % 16 == 0
}

fn is_insn_start(insns: &[InsnLayout], value: usize) -> bool {
    insns.iter().any(|i| i.start == value)
}

fn patch_operands_for_threaded(
    op: OpCode,
    operands: &mut [u8],
    insns: &[InsnLayout],
    relocate: &dyn Fn(usize) -> usize,
) {
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
                if is_string_or_data_offset(insns, old) {
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
    handler_off_from_table: &dyn Fn(OpCode) -> i32,
) -> Vec<u8> {
    let insns = enumerate_instructions(bytecode, opcode_map);
    let code_end = code_section_end(&insns);
    let relocate = |old: usize| relocate_offset(&insns, old);

    let mut out = Vec::with_capacity(
        bytecode.len() + insns.len() * THREAD_TARGET_SIZE,
    );
    for insn in &insns {
        let handler_off = handler_off_from_table(insn.op);
        out.push(bytecode[insn.start]);
        out.extend_from_slice(&handler_off.to_le_bytes());
        let mut operands = bytecode[insn.start + 1..insn.start + insn.raw_len].to_vec();
        patch_operands_for_threaded(insn.op, &mut operands, &insns, &relocate);
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

/// Walk threaded bytecode and find a load_imm whose immediate points at `needle`.
pub fn threaded_load_imm_target(bytecode: &[u8], opcode_map: &OpcodeMap, needle: &[u8]) -> Option<usize> {
    let mut offset = 0;
    while offset < bytecode.len() {
        let wire = bytecode[offset];
        let op = match opcode_map.decode(wire) {
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
            if bytecode.get(imm..imm + needle.len()) == Some(needle) {
                return Some(imm);
            }
        }
        offset += threaded_insn_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::vm_stub::create_vm_interpreter_stub;
    use crate::vm::DispatchMode;

    fn stub_for(map: &OpcodeMap) -> Vec<u8> {
        create_vm_interpreter_stub(0, 0, map, DispatchMode::Table, &[], &[], &[])
            .0
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
        let threaded = embed_thread_targets(&raw, &map, &|op| handler_offset_for_op(&stub, &map, op));
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

        let threaded = embed_thread_targets(&raw, &map, &|op| handler_offset_for_op(&stub, &map, op));
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

        let threaded = embed_thread_targets(&raw, &map, &|op| handler_offset_for_op(&stub, &map, op));
        assert!(
            threaded.windows(msg.len()).any(|w| w == msg),
            "threaded embed must preserve trailing string pool"
        );
        let ptr = threaded_load_imm_target(&threaded, &map, msg).expect("load_imm string ptr");
        assert_eq!(&threaded[ptr..ptr + msg.len()], msg);
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

        let threaded = embed_thread_targets(&raw, &map, &|op| handler_offset_for_op(&stub, &map, op));
        let imm = u64::from_le_bytes(
            threaded[1 + THREAD_TARGET_SIZE + 1..1 + THREAD_TARGET_SIZE + 9]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(&threaded[imm..imm + msg.len()], msg);
    }
}
