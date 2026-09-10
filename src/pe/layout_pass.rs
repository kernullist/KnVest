use crate::vm::block_map::{BlockMapPlan, META_OPERAND_LEN, META_WIRE_BYTE};
use crate::vm::layout::{BytecodeLayout, RawInsnKind, enumerate_raw_instructions};
use crate::vm::opcode_map::OpcodeMap;
use crate::vm::OpCode;

const PAD_FILL: u8 = 0xCC;

/// Insert seed-derived post-wire padding before operand slots (L5c axis A).
pub fn apply_layout_diversification(
    bytecode: &[u8],
    layout: &BytecodeLayout,
    opcode_map: &OpcodeMap,
    block_plan: &BlockMapPlan,
) -> Vec<u8> {
    let insns = enumerate_raw_instructions(
        bytecode,
        opcode_map,
        block_plan,
        &BytecodeLayout::identity(),
        crate::vm::DispatchMode::Table,
    );
    if insns.is_empty() {
        return bytecode.to_vec();
    }
    let code_end = insns.last().map(|i| i.start + i.raw_len).unwrap_or(0);
    let wire_pad_total = total_wire_padding(&insns, layout);
    let relocate_insn = |old: usize| relocate_offset(&insns, layout, old);
    let relocate = |old: usize| {
        if is_string_or_data_offset(&insns, old, bytecode.len()) {
            old + wire_pad_total
        } else {
            relocate_insn(old)
        }
    };

    let mut out = Vec::with_capacity(bytecode.len() + insns.len() * 4);
    for insn in &insns {
        out.push(bytecode[insn.start]);
        let pad_wire = match insn.kind {
            RawInsnKind::SetBlockMap => layout.meta_post_wire_pad,
            RawInsnKind::Semantic(op) => layout.post_wire_pad_for(op),
        };
        for _ in 0..pad_wire {
            out.push(PAD_FILL);
        }
        let op_start = insn.start + 1;
        let operand_len = match insn.kind {
            RawInsnKind::SetBlockMap => META_OPERAND_LEN,
            RawInsnKind::Semantic(op) => op.operand_len_lift(),
        };
        let mut operands = bytecode[op_start..op_start + operand_len].to_vec();
        if let RawInsnKind::Semantic(op) = insn.kind {
            patch_operands_for_layout(op, &mut operands, &insns, bytecode.len(), &relocate);
        }
        out.extend_from_slice(&operands);
    }
    if code_end < bytecode.len() {
        out.extend_from_slice(&bytecode[code_end..]);
    }
    out
}

fn total_wire_padding(
    insns: &[crate::vm::layout::RawInsn],
    layout: &BytecodeLayout,
) -> usize {
    insns.iter().map(|insn| {
        match insn.kind {
            RawInsnKind::SetBlockMap => layout.meta_post_wire_pad as usize,
            RawInsnKind::Semantic(op) => layout.post_wire_pad_for(op) as usize,
        }
    }).sum()
}

fn relocate_offset(
    insns: &[crate::vm::layout::RawInsn],
    layout: &BytecodeLayout,
    old_pos: usize,
) -> usize {
    let mut new_pos = 0usize;
    for insn in insns {
        if insn.start == old_pos {
            return new_pos;
        }
        let pad_wire = match insn.kind {
            RawInsnKind::SetBlockMap => layout.meta_post_wire_pad,
            RawInsnKind::Semantic(op) => layout.post_wire_pad_for(op),
        };
        let operand_len = match insn.kind {
            RawInsnKind::SetBlockMap => META_OPERAND_LEN,
            RawInsnKind::Semantic(op) => op.operand_len_lift(),
        };
        new_pos += 1 + pad_wire as usize + operand_len;
    }
    old_pos
}

fn is_insn_start(insns: &[crate::vm::layout::RawInsn], value: usize) -> bool {
    insns.iter().any(|i| i.start == value)
}

fn code_section_end(insns: &[crate::vm::layout::RawInsn]) -> usize {
    insns.last().map(|i| i.start + i.raw_len).unwrap_or(0)
}

fn is_string_or_data_offset(insns: &[crate::vm::layout::RawInsn], value: usize, bytecode_len: usize) -> bool {
    let end = code_section_end(insns);
    value >= end && value < bytecode_len
}

fn patch_operands_for_layout(
    op: OpCode,
    operands: &mut [u8],
    insns: &[crate::vm::layout::RawInsn],
    bytecode_len: usize,
    relocate: &dyn Fn(usize) -> usize,
) {
    match op {
        OpCode::Jmp | OpCode::Call => {
            if operands.len() >= 8 {
                let old = u64::from_le_bytes(operands[0..8].try_into().unwrap()) as usize;
                if is_insn_start(insns, old) {
                    operands[0..8].copy_from_slice(&(relocate(old) as u64).to_le_bytes());
                }
            }
        }
        OpCode::JmpIf => {
            if operands.len() >= 9 {
                let old = u64::from_le_bytes(operands[1..9].try_into().unwrap()) as usize;
                if is_insn_start(insns, old) {
                    operands[1..9].copy_from_slice(&(relocate(old) as u64).to_le_bytes());
                }
            }
        }
        OpCode::LoadImm | OpCode::LoadStr => {
            if operands.len() >= 9 {
                let old = u64::from_le_bytes(operands[1..9].try_into().unwrap()) as usize;
                if is_string_or_data_offset(insns, old, bytecode_len) {
                    operands[1..9].copy_from_slice(&(relocate(old) as u64).to_le_bytes());
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::DispatchMode;

    #[test]
    fn layout_pass_preserves_string_pool_offsets() {
        let map = OpcodeMap::from_seed(10);
        let layout = BytecodeLayout::from_seed(0x5A5A_5A5A);
        let plan = BlockMapPlan::default();
        let msg = b"pool\0";
        let mut raw = vec![map.encode(OpCode::LoadImm), 0];
        raw.extend_from_slice(&0u64.to_le_bytes());
        raw.push(map.encode(OpCode::Exit));
        raw.push(0);
        let pool_off = raw.len();
        raw.extend_from_slice(msg);
        raw[2..10].copy_from_slice(&(pool_off as u64).to_le_bytes());

        let laid = apply_layout_diversification(&raw, &layout, &map, &plan);
        let insns = enumerate_raw_instructions(
            &laid,
            &map,
            &plan,
            &layout,
            DispatchMode::Table,
        );
        let wire_pad = total_wire_padding(
            &enumerate_raw_instructions(
                &raw,
                &map,
                &plan,
                &BytecodeLayout::identity(),
                DispatchMode::Table,
            ),
            &layout,
        );
        let expected_pool = pool_off + wire_pad;
        let load = insns
            .iter()
            .find(|i| matches!(i.kind, RawInsnKind::Semantic(OpCode::LoadImm)))
            .expect("load_imm");
        let imm_off = load.start + layout.operands_offset(OpCode::LoadImm, false) + 1;
        let imm = u64::from_le_bytes(laid[imm_off..imm_off + 8].try_into().unwrap()) as usize;
        assert_eq!(imm, expected_pool, "load_imm must track padded tail offset");
        assert!(
            laid[imm..].starts_with(msg),
            "load_imm must still reference string pool bytes"
        );
    }

    #[test]
    fn layout_pass_changes_wire_bytes() {
        let map = OpcodeMap::from_seed(10);
        let layout_a = BytecodeLayout::from_seed(10);
        let layout_b = BytecodeLayout::from_seed(20);
        let plan = BlockMapPlan::default();
        let mut raw = vec![map.encode(OpCode::LoadImm), 0];
        raw.extend_from_slice(&42u64.to_le_bytes());
        raw.push(map.encode(OpCode::Exit));
        raw.push(0);
        let laid_a = apply_layout_diversification(&raw, &layout_a, &map, &plan);
        let laid_b = apply_layout_diversification(&raw, &layout_b, &map, &plan);
        assert_ne!(laid_a, laid_b);
        let insns_a = crate::ir::Instruction::disassemble_with_layout(
            &laid_a,
            &map,
            None,
            DispatchMode::Table,
            &layout_a,
        );
        let insns_b = crate::ir::Instruction::disassemble_with_layout(
            &laid_b,
            &map,
            None,
            DispatchMode::Table,
            &layout_b,
        );
        assert_eq!(insns_a.len(), insns_b.len());
        assert_eq!(insns_a[0].opcode, OpCode::LoadImm);
        assert_eq!(insns_b[0].opcode, OpCode::LoadImm);
    }
}
