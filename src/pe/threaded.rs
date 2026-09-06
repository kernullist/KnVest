use crate::vm::dispatch::{DispatchMode, THREAD_TARGET_SIZE};
use crate::vm::opcode_map::OpcodeMap;
use crate::vm::OpCode;

/// Embed per-instruction handler rel32 targets after each opcode wire byte (L4c threaded).
pub fn embed_thread_targets(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    handler_off_from_table: &dyn Fn(OpCode) -> i32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        bytecode.len() + bytecode.iter().count() * THREAD_TARGET_SIZE,
    );
    let mut offset = 0;
    while offset < bytecode.len() {
        let wire = bytecode[offset];
        let op = opcode_map
            .decode(wire)
            .unwrap_or(OpCode::Nop);
        let operand_len = op.operand_len();
        let insn_len = 1 + operand_len;
        if offset + insn_len > bytecode.len() {
            break;
        }
        let handler_off = handler_off_from_table(op);
        out.push(wire);
        out.extend_from_slice(&handler_off.to_le_bytes());
        out.extend_from_slice(&bytecode[offset + 1..offset + insn_len]);
        offset += insn_len;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::vm_stub::create_vm_interpreter_stub;
    use crate::vm::DispatchMode;

    #[test]
    fn embed_thread_targets_preserves_logical_operands() {
        let map = OpcodeMap::from_seed(7);
        let (stub, _) = create_vm_interpreter_stub(
            0,
            0,
            &map,
            DispatchMode::Table,
            &[],
            &[],
            &[],
        );
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
}
