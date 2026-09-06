use crate::vm::dispatch::{DispatchMode, THREAD_TARGET_SIZE};
use crate::vm::block_map::{BlockMapPlan, META_WIRE_BYTE, META_OPERAND_LEN};
use crate::vm::opcode_map::OpcodeMap;
use crate::vm::OpCode;
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
        let mut output = String::new();
        output.push_str("Address  | Opcode       | Operands\n");
        output.push_str("---------+--------------+---------\n");

        for instr in instructions {
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
}
