use crate::vm::dispatch::{DispatchMode, THREAD_TARGET_SIZE};
use crate::vm::block_map::{BlockMapPlan, META_WIRE_BYTE, META_OPERAND_LEN};
use crate::vm::opcode_map::OpcodeMap;
use crate::vm::OpCode;
use crate::vm::virt_isa::VIRT_ISA_SPLIT_TEMP;
use crate::pe::mba::{MBA_TEMP_NEG, MBA_TEMP_T0, MBA_TEMP_T1, MBA_TEMP_ZERO};
use std::fmt;

pub struct Instruction {
    pub offset: usize,
    pub opcode: OpCode,
    pub operands: Vec<Operand>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Register(u8),
    Immediate(u64),
    Unknown(Vec<u8>),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Register(r) => write!(f, "r{}", r),
            Operand::Immediate(imm) => write!(f, "{:#x}", imm),
            Operand::Unknown(bytes) => {
                write!(f, "[")?;
                for (i, byte) in bytes.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{:02x}", byte)?;
                }
                write!(f, "]")
            }
        }
    }
}

impl Instruction {
    pub fn disassemble(bytecode: &[u8], opcode_map: &OpcodeMap, dispatch_mode: DispatchMode) -> Vec<Self> {
        Self::disassemble_with_block_maps(bytecode, opcode_map, None, dispatch_mode)
    }

    pub fn disassemble_with_block_maps(
        bytecode: &[u8],
        base_map: &OpcodeMap,
        block_plan: Option<&BlockMapPlan>,
        dispatch_mode: DispatchMode,
    ) -> Vec<Self> {
        let mut instructions = Vec::new();
        let mut offset = 0;
        let mut consecutive_invalid = 0;
        let mut current_map = base_map.clone();

        while offset < bytecode.len() {
            let start_offset = offset;
            let opcode_byte = bytecode[offset];
            offset += 1;
            if dispatch_mode == DispatchMode::Threaded {
                offset += THREAD_TARGET_SIZE;
            }

            if opcode_byte == META_WIRE_BYTE {
                consecutive_invalid = 0;
                if offset + META_OPERAND_LEN <= bytecode.len() {
                    let bb_id = u16::from_le_bytes([bytecode[offset], bytecode[offset + 1]]);
                    offset += META_OPERAND_LEN;
                    if let Some(plan) = block_plan {
                        current_map = plan.map_for_bb_or_base(bb_id, base_map);
                    }
                    instructions.push(Instruction {
                        offset: start_offset,
                        opcode: OpCode::SetBlockMap,
                        operands: vec![Operand::Immediate(u64::from(bb_id))],
                    });
                    continue;
                }
            }

            let opcode = match current_map.decode(opcode_byte) {
                Some(op) => op,
                None => {
                    consecutive_invalid += 1;
                    if consecutive_invalid >= 3 {
                        break;
                    }
                    instructions.push(Instruction {
                        offset: start_offset,
                        opcode: OpCode::Nop,
                        operands: vec![Operand::Unknown(vec![opcode_byte])],
                    });
                    continue;
                }
            };
            
            consecutive_invalid = 0;

            let mut operands = Vec::new();

            match opcode {
                OpCode::Nop | OpCode::SetBlockMap => {},
                
                OpCode::LoadImm => {
                    if offset < bytecode.len() {
                        operands.push(Operand::Register(bytecode[offset]));
                        offset += 1;
                    }
                    if offset + 8 <= bytecode.len() {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&bytecode[offset..offset + 8]);
                        operands.push(Operand::Immediate(u64::from_le_bytes(bytes)));
                        offset += 8;
                    }
                },
                
                OpCode::LoadMem | OpCode::StoreMem | OpCode::Move => {
                    if offset < bytecode.len() {
                        operands.push(Operand::Register(bytecode[offset]));
                        offset += 1;
                    }
                    if offset < bytecode.len() {
                        operands.push(Operand::Register(bytecode[offset]));
                        offset += 1;
                    }
                },
                
                OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Xor | OpCode::And => {
                    for _ in 0..3 {
                        if offset < bytecode.len() {
                            operands.push(Operand::Register(bytecode[offset]));
                            offset += 1;
                        }
                    }
                },
                
                OpCode::Cmp | OpCode::Cmp32 => {
                    for _ in 0..2 {
                        if offset < bytecode.len() {
                            operands.push(Operand::Register(bytecode[offset]));
                            offset += 1;
                        }
                    }
                },
                
                OpCode::Jmp => {
                    if offset + 8 <= bytecode.len() {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&bytecode[offset..offset + 8]);
                        operands.push(Operand::Immediate(u64::from_le_bytes(bytes)));
                        offset += 8;
                    }
                },
                
                OpCode::JmpIf => {
                    if offset < bytecode.len() {
                        operands.push(Operand::Register(bytecode[offset]));
                        offset += 1;
                    }
                    if offset + 8 <= bytecode.len() {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&bytecode[offset..offset + 8]);
                        operands.push(Operand::Immediate(u64::from_le_bytes(bytes)));
                        offset += 8;
                    }
                },
                
                OpCode::Call | OpCode::NativeCall => {
                    if offset + 8 <= bytecode.len() {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&bytecode[offset..offset + 8]);
                        operands.push(Operand::Immediate(u64::from_le_bytes(bytes)));
                        offset += 8;
                    }
                },
                
                OpCode::Ret => {},
                
                OpCode::Push | OpCode::Pop | OpCode::Exit => {
                    if offset < bytecode.len() {
                        operands.push(Operand::Register(bytecode[offset]));
                        offset += 1;
                    }
                },
                
                OpCode::LoadByte => {
                    if offset < bytecode.len() {
                        operands.push(Operand::Register(bytecode[offset]));
                        offset += 1;
                    }
                    if offset < bytecode.len() {
                        operands.push(Operand::Register(bytecode[offset]));
                        offset += 1;
                    }
                },
                
                OpCode::LoadStr => {
                    if offset < bytecode.len() {
                        operands.push(Operand::Register(bytecode[offset]));
                        offset += 1;
                    }
                    if offset + 8 <= bytecode.len() {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&bytecode[offset..offset + 8]);
                        operands.push(Operand::Immediate(u64::from_le_bytes(bytes)));
                        offset += 8;
                    }
                },

                OpCode::RunNative | OpCode::BailNative => {
                    if offset + 8 <= bytecode.len() {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&bytecode[offset..offset + 8]);
                        operands.push(Operand::Immediate(u64::from_le_bytes(bytes)));
                        offset += 8;
                    }
                    if offset + 8 <= bytecode.len() {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&bytecode[offset..offset + 8]);
                        operands.push(Operand::Immediate(u64::from_le_bytes(bytes)));
                        offset += 8;
                    }
                },
            }

            instructions.push(Instruction {
                offset: start_offset,
                opcode,
                operands,
            });
        }

        instructions
    }

    pub fn pretty_print(instructions: &[Self]) -> String {
        Self::pretty_print_annotated(instructions, false, true)
    }

    pub fn pretty_print_with_mba(instructions: &[Self], mba_level: u8) -> String {
        Self::pretty_print_annotated(instructions, mba_level >= 1, true)
    }

    pub fn pretty_print_annotated(
        instructions: &[Self],
        annotate_mba: bool,
        annotate_virt_isa: bool,
    ) -> String {
        let mut output = String::new();
        output.push_str("Address  | Opcode       | Operands\n");
        output.push_str("---------+--------------+---------\n");

        let mba_starts = if annotate_mba {
            find_mba_substitution_starts(instructions)
        } else {
            std::collections::HashMap::new()
        };
        let virt_isa_notes = if annotate_virt_isa {
            find_virt_isa_annotations(instructions)
        } else {
            std::collections::HashMap::new()
        };

        for (idx, instr) in instructions.iter().enumerate() {
            if let Some(note) = mba_starts.get(&idx) {
                output.push_str(&format!("         | ; MBA       | {note}\n"));
            }
            if let Some(note) = virt_isa_notes.get(&idx) {
                output.push_str(&format!("         | ; virt-isa  | {note}\n"));
            }
            output.push_str(&format!(
                "{:08x} | {:<12} | ",
                instr.offset,
                instr.opcode.name()
            ));

            for (i, operand) in instr.operands.iter().enumerate() {
                if i > 0 {
                    output.push_str(", ");
                }
                output.push_str(&operand.to_string());
            }

            output.push('\n');
        }

        output
    }
}

fn reg_operand(op: &Operand) -> Option<u8> {
    match op {
        Operand::Register(r) => Some(*r),
        _ => None,
    }
}

fn reg_at(ops: &[Operand], idx: usize) -> Option<u8> {
    ops.get(idx).and_then(reg_operand)
}

fn mba_note_add_neg(a: u8, b: u8, dst: u8) -> String {
    format!("add r{dst}, r{a}, r{b}  ==  r{a}-(0-r{b})")
}

fn mba_note_add_xor_and(a: u8, b: u8, dst: u8) -> String {
    format!("add r{dst}, r{a}, r{b}  ==  (r{a}^r{b})+2*(r{a}&r{b})")
}

fn mba_note_sub_neg(a: u8, b: u8, dst: u8) -> String {
    format!("sub r{dst}, r{a}, r{b}  ==  r{a}+(0-r{b})")
}

fn mba_note_xor_add_and(a: u8, b: u8, dst: u8) -> String {
    format!("xor r{dst}, r{a}, r{b}  ==  (r{a}+r{b})-2*(r{a}&r{b})")
}

fn mba_note_and_or_xor(a: u8, b: u8, dst: u8) -> String {
    format!("and r{dst}, r{a}, r{b}  ==  (r{a}+r{b}-(r{a}&r{b}))-(r{a}^r{b})")
}

fn alu_src_pair(ins: &Instruction) -> Option<(u8, u8)> {
    let a = reg_at(&ins.operands, 1)?;
    let b = reg_at(&ins.operands, 2)?;
    Some((a, b))
}

fn same_src_pair(a: &Instruction, b: &Instruction) -> Option<(u8, u8)> {
    let (a1, a2) = alu_src_pair(a)?;
    let (b1, b2) = alu_src_pair(b)?;
    if a1 == b1 && a2 == b2 {
        Some((a1, a2))
    } else {
        None
    }
}

fn triple_add(ins: &Instruction) -> Option<u8> {
    if ins.opcode != OpCode::Add {
        return None;
    }
    let dst = reg_at(&ins.operands, 0)?;
    let s1 = reg_at(&ins.operands, 1)?;
    let s2 = reg_at(&ins.operands, 2)?;
    if dst == s1 && s1 == s2 {
        Some(dst)
    } else {
        None
    }
}

/// Detect MBA catalog expansions in lifted bytecode.
fn find_mba_substitution_starts(
    instructions: &[Instruction],
) -> std::collections::HashMap<usize, String> {
    let mut out = std::collections::HashMap::new();
    if instructions.len() < 3 {
        return out;
    }
    for i in 0..instructions.len().saturating_sub(2) {
        if out.contains_key(&i) {
            continue;
        }

        // add via neg: load_imm t0,0 ; sub t1,t0,b ; sub dst,a,t1
        if i + 2 < instructions.len() {
            let z = &instructions[i];
            let n = &instructions[i + 1];
            let f = &instructions[i + 2];
            if z.opcode == OpCode::LoadImm
                && matches!(z.operands.get(1), Some(Operand::Immediate(0)))
                && n.opcode == OpCode::Sub
                && f.opcode == OpCode::Sub
            {
                let Some(zero) = reg_at(&z.operands, 0) else { continue };
                let Some(neg) = reg_at(&n.operands, 0) else { continue };
                let Some(zero2) = reg_at(&n.operands, 1) else { continue };
                let Some(b) = reg_at(&n.operands, 2) else { continue };
                let Some(final_dst) = reg_at(&f.operands, 0) else { continue };
                let Some(a) = reg_at(&f.operands, 1) else { continue };
                let Some(neg2) = reg_at(&f.operands, 2) else { continue };
                if zero == zero2 && neg == neg2 {
                    out.insert(i, mba_note_add_neg(a, b, final_dst));
                    continue;
                }
            }
        }

        // sub via neg: load_imm t0,0 ; sub t1,t0,b ; add dst,a,t1
        if i + 2 < instructions.len() {
            let z = &instructions[i];
            let n = &instructions[i + 1];
            let f = &instructions[i + 2];
            if z.opcode == OpCode::LoadImm
                && matches!(z.operands.get(1), Some(Operand::Immediate(0)))
                && n.opcode == OpCode::Sub
                && f.opcode == OpCode::Add
            {
                let Some(zero) = reg_at(&z.operands, 0) else { continue };
                let Some(neg) = reg_at(&n.operands, 0) else { continue };
                let Some(zero2) = reg_at(&n.operands, 1) else { continue };
                let Some(b) = reg_at(&n.operands, 2) else { continue };
                let Some(final_dst) = reg_at(&f.operands, 0) else { continue };
                let Some(a) = reg_at(&f.operands, 1) else { continue };
                let Some(neg2) = reg_at(&f.operands, 2) else { continue };
                if zero == zero2 && neg == neg2 {
                    out.insert(i, mba_note_sub_neg(a, b, final_dst));
                    continue;
                }
            }
        }

        // add via xor/and: [move ta,a][move tb,b] xor ; and ; add t,t,t ; add dst,...
        for start in i..=i.saturating_add(2).min(instructions.len().saturating_sub(4)) {
            let mut off = start;
            let mut orig_a = None;
            let mut orig_b = None;
            if instructions[off].opcode == OpCode::Move {
                orig_a = reg_at(&instructions[off].operands, 1);
                off += 1;
            }
            if off < instructions.len() && instructions[off].opcode == OpCode::Move {
                orig_b = reg_at(&instructions[off].operands, 1);
                off += 1;
            }
            if off + 3 >= instructions.len() {
                continue;
            }
            let x = &instructions[off];
            let n = &instructions[off + 1];
            let dbl = &instructions[off + 2];
            let fin = &instructions[off + 3];
            if x.opcode != OpCode::Xor || n.opcode != OpCode::And || fin.opcode != OpCode::Add {
                continue;
            }
            let Some((ta, tb)) = same_src_pair(x, n) else { continue };
            if triple_add(dbl) != reg_at(&n.operands, 0) {
                continue;
            }
            let Some(dst) = reg_at(&fin.operands, 0) else { continue };
            let Some(xdst) = reg_at(&x.operands, 0) else { continue };
            let Some(ndst) = reg_at(&fin.operands, 2) else { continue };
            if reg_at(&fin.operands, 1) != Some(xdst) || reg_at(&n.operands, 0) != Some(ndst) {
                continue;
            }
            let a = orig_a.unwrap_or(ta);
            let b = orig_b.unwrap_or(tb);
            out.insert(start, mba_note_add_xor_and(a, b, dst));
            break;
        }

        // xor via add/and: [moves] and ; add t,t,t ; add sum ; sub dst,sum,t
        if i + 3 < instructions.len() {
            let z = &instructions[i];
            let n = &instructions[i + 1];
            if z.opcode == OpCode::And && triple_add(n) == reg_at(&z.operands, 0) {
                let sum = &instructions[i + 2];
                let fin = &instructions[i + 3];
                if sum.opcode == OpCode::Add && fin.opcode == OpCode::Sub {
                    let Some((a, b)) = alu_src_pair(&z) else { continue };
                    if alu_src_pair(sum) == Some((a, b)) {
                        if let Some(dst) = reg_at(&fin.operands, 0) {
                            out.insert(i, mba_note_xor_add_and(a, b, dst));
                            continue;
                        }
                    }
                }
            }
        }

        // and via or/xor: [moves] and ; add ; sub ; xor ; sub dst
        if i + 4 < instructions.len() {
            let z = &instructions[i];
            let sum = &instructions[i + 1];
            let sub1 = &instructions[i + 2];
            let x = &instructions[i + 3];
            let fin = &instructions[i + 4];
            if z.opcode == OpCode::And
                && sum.opcode == OpCode::Add
                && sub1.opcode == OpCode::Sub
                && x.opcode == OpCode::Xor
                && fin.opcode == OpCode::Sub
            {
                let Some((a, b)) = alu_src_pair(&z) else { continue };
                let Some(t0) = reg_at(&z.operands, 0) else { continue };
                let Some(t1) = reg_at(&sum.operands, 0) else { continue };
                if alu_src_pair(sum) != Some((a, b)) {
                    continue;
                }
                if reg_at(&sub1.operands, 0) != Some(t1)
                    || reg_at(&sub1.operands, 1) != Some(t1)
                    || reg_at(&sub1.operands, 2) != Some(t0)
                {
                    continue;
                }
                if alu_src_pair(&x) != Some((a, b)) || reg_at(&x.operands, 0) != Some(t0) {
                    continue;
                }
                if let Some(dst) = reg_at(&fin.operands, 0) {
                    out.insert(i, mba_note_and_or_xor(a, b, dst));
                }
            }
        }
    }
    out
}

/// Detect L5a merge: `test r,r` lifts as load_imm r15,0 ; cmp r,r15.
fn find_virt_isa_annotations(
    instructions: &[Instruction],
) -> std::collections::HashMap<usize, String> {
    let mut out = std::collections::HashMap::new();
    if instructions.len() < 2 {
        return out;
    }
    for i in 0..instructions.len().saturating_sub(1) {
        let z = &instructions[i];
        let c = &instructions[i + 1];
        if z.opcode == OpCode::Move
            && reg_at(&z.operands, 0) == Some(VIRT_ISA_SPLIT_TEMP)
            && c.opcode == OpCode::Sub
        {
            let Some(temp) = reg_at(&c.operands, 1) else {
                continue;
            };
            if temp != VIRT_ISA_SPLIT_TEMP {
                continue;
            }
            let Some(dst) = reg_at(&c.operands, 0) else {
                continue;
            };
            let Some(src) = reg_at(&c.operands, 2) else {
                continue;
            };
            let Some(lhs) = reg_at(&z.operands, 1) else {
                continue;
            };
            out.insert(
                i,
                format!(
                    "split | x86 sub → move r{temp},r{lhs} ; sub r{dst},r{temp},r{src}"
                ),
            );
            continue;
        }
        if z.opcode == OpCode::LoadImm
            && matches!(z.operands.get(1), Some(Operand::Immediate(0)))
            && c.opcode == OpCode::Cmp
        {
            let Some(holder) = reg_at(&z.operands, 0) else {
                continue;
            };
            let Some(cmp_a) = reg_at(&c.operands, 0) else {
                continue;
            };
            let Some(cmp_b) = reg_at(&c.operands, 1) else {
                continue;
            };
            if cmp_b == holder {
                if holder == 0 && cmp_a == 0 {
                    out.insert(
                        i,
                        "merge | x86 xor eax,eax → load_imm r0,0".to_string(),
                    );
                } else {
                    out.insert(
                        i,
                        format!("merge | x86 test r{cmp_a},r{cmp_a} → load_imm r{holder},0 ; cmp r{cmp_a},r{holder}"),
                    );
                }
            }
            continue;
        }
        if z.opcode == OpCode::LoadImm
            && matches!(z.operands.get(1), Some(Operand::Immediate(0)))
            && reg_at(&z.operands, 0) == Some(0)
            && (c.opcode != OpCode::Cmp || reg_at(&c.operands, 1) != Some(0))
        {
            out.insert(
                i,
                "merge | x86 xor eax,eax → load_imm r0,0".to_string(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::OpcodeMap;

    #[test]
    fn test_disassemble_load_imm_with_map() {
        let map = OpcodeMap::from_seed(99);
        let mut bytecode = vec![map.encode(OpCode::LoadImm), 0];
        bytecode.extend_from_slice(&42u64.to_le_bytes());
        
        let instructions = Instruction::disassemble(&bytecode, &map, DispatchMode::Table);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, OpCode::LoadImm);
        assert_eq!(instructions[0].operands.len(), 2);
    }

    #[test]
    fn test_pretty_print_with_shuffled_map() {
        let map = OpcodeMap::from_seed(7);
        let mut bytecode = vec![map.encode(OpCode::LoadImm), 0];
        bytecode.extend_from_slice(&42u64.to_le_bytes());
        bytecode.push(map.encode(OpCode::Exit));
        bytecode.push(0);
        
        let instructions = Instruction::disassemble(&bytecode, &map, DispatchMode::Table);
        let output = Instruction::pretty_print(&instructions);
        assert!(output.contains("load_imm"));
        assert!(output.contains("exit"));
    }

    #[test]
    fn test_raw_bytes_fail_without_map() {
        let map_a = OpcodeMap::from_seed(1);
        let map_b = OpcodeMap::from_seed(2);
        let mut bytecode = vec![map_a.encode(OpCode::LoadImm), 0];
        bytecode.extend_from_slice(&1u64.to_le_bytes());
        let wrong = Instruction::disassemble(&bytecode, &map_b, DispatchMode::Table);
        assert!(wrong.iter().any(|i| !i.operands.is_empty() && matches!(i.operands[0], Operand::Unknown(_))));
    }

    #[test]
    fn test_mba_ir_annotation() {
        let insns = vec![
            Instruction {
                offset: 0,
                opcode: OpCode::LoadImm,
                operands: vec![Operand::Register(MBA_TEMP_ZERO), Operand::Immediate(0)],
            },
            Instruction {
                offset: 10,
                opcode: OpCode::Sub,
                operands: vec![
                    Operand::Register(MBA_TEMP_NEG),
                    Operand::Register(MBA_TEMP_ZERO),
                    Operand::Register(3),
                ],
            },
            Instruction {
                offset: 14,
                opcode: OpCode::Sub,
                operands: vec![
                    Operand::Register(1),
                    Operand::Register(2),
                    Operand::Register(MBA_TEMP_NEG),
                ],
            },
        ];
        let out = Instruction::pretty_print_with_mba(&insns, 1);
        assert!(out.contains("; MBA"));
        assert!(out.contains("add r1, r2, r3"));
    }

    #[test]
    fn test_mba_xor_and_add_annotation() {
        let insns = vec![
            Instruction {
                offset: 0,
                opcode: OpCode::Xor,
                operands: vec![
                    Operand::Register(MBA_TEMP_T0),
                    Operand::Register(1),
                    Operand::Register(2),
                ],
            },
            Instruction {
                offset: 4,
                opcode: OpCode::And,
                operands: vec![
                    Operand::Register(MBA_TEMP_T1),
                    Operand::Register(1),
                    Operand::Register(2),
                ],
            },
            Instruction {
                offset: 8,
                opcode: OpCode::Add,
                operands: vec![
                    Operand::Register(MBA_TEMP_T1),
                    Operand::Register(MBA_TEMP_T1),
                    Operand::Register(MBA_TEMP_T1),
                ],
            },
            Instruction {
                offset: 12,
                opcode: OpCode::Add,
                operands: vec![
                    Operand::Register(0),
                    Operand::Register(MBA_TEMP_T0),
                    Operand::Register(MBA_TEMP_T1),
                ],
            },
        ];
        let out = Instruction::pretty_print_with_mba(&insns, 1);
        assert!(out.contains("(r1^r2)+2*(r1&r2)"));
    }
}
