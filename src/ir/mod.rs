use crate::vm::dispatch::{DispatchMode, THREAD_TARGET_SIZE};
use crate::vm::block_map::{BlockMapPlan, META_WIRE_BYTE, META_OPERAND_LEN};
use crate::vm::opcode_map::OpcodeMap;
use crate::vm::OpCode;
use crate::pe::mba::{MBA_TEMP_NEG, MBA_TEMP_ZERO};
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
        Self::pretty_print_with_mba(instructions, false)
    }

    pub fn pretty_print_with_mba(instructions: &[Self], annotate_mba: bool) -> String {
        let mut output = String::new();
        output.push_str("Address  | Opcode       | Operands\n");
        output.push_str("---------+--------------+---------\n");

        let mba_starts = if annotate_mba {
            find_mba_substitution_starts(instructions)
        } else {
            std::collections::HashMap::new()
        };

        for (idx, instr) in instructions.iter().enumerate() {
            if let Some(note) = mba_starts.get(&idx) {
                output.push_str(&format!("         | ; MBA       | {note}\n"));
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

fn mba_note_for(a: u8, b: u8, dst: u8) -> String {
    format!("add r{dst}, r{a}, r{b}  ==  r{a}-(0-r{b})")
}

/// Detect L4f MBA expansion: load_imm r14,0 ; sub r15,r14,b ; sub dst,a,r15
fn find_mba_substitution_starts(instructions: &[Instruction]) -> std::collections::HashMap<usize, String> {
    let mut out = std::collections::HashMap::new();
    if instructions.len() < 3 {
        return out;
    }
    for i in 0..instructions.len().saturating_sub(2) {
        let z = &instructions[i];
        let n = &instructions[i + 1];
        let f = &instructions[i + 2];
        if z.opcode != OpCode::LoadImm || n.opcode != OpCode::Sub || f.opcode != OpCode::Sub {
            continue;
        }
        let Some(zero_dst) = reg_at(&z.operands, 0) else { continue };
        if zero_dst != MBA_TEMP_ZERO {
            continue;
        }
        if !matches!(z.operands.get(1), Some(Operand::Immediate(0))) {
            continue;
        }
        let Some(neg_dst) = reg_at(&n.operands, 0) else { continue };
        let Some(neg_s1) = reg_at(&n.operands, 1) else { continue };
        let Some(b) = reg_at(&n.operands, 2) else { continue };
        if neg_dst != MBA_TEMP_NEG || neg_s1 != MBA_TEMP_ZERO {
            continue;
        }
        let Some(final_dst) = reg_at(&f.operands, 0) else { continue };
        let Some(a) = reg_at(&f.operands, 1) else { continue };
        let Some(neg_src) = reg_at(&f.operands, 2) else { continue };
        if neg_src != MBA_TEMP_NEG {
            continue;
        }
        out.insert(i, mba_note_for(a, b, final_dst));
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
        let out = Instruction::pretty_print_with_mba(&insns, true);
        assert!(out.contains("; MBA"));
        assert!(out.contains("add r1, r2, r3"));
    }
}
