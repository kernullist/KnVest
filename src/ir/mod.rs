use crate::vm::OpCode;
use std::fmt;

pub struct Instruction {
    pub offset: usize,
    pub opcode: OpCode,
    pub operands: Vec<Operand>,
}

#[derive(Debug, Clone)]
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
    pub fn disassemble(bytecode: &[u8]) -> Vec<Self> {
        let mut instructions = Vec::new();
        let mut offset = 0;
        let mut consecutive_invalid = 0;

        while offset < bytecode.len() {
            let start_offset = offset;
            let opcode_byte = bytecode[offset];
            offset += 1;

            let opcode = match OpCode::from_u8(opcode_byte) {
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
                OpCode::Nop => {},
                
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
                
                OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Xor => {
                    for _ in 0..3 {
                        if offset < bytecode.len() {
                            operands.push(Operand::Register(bytecode[offset]));
                            offset += 1;
                        }
                    }
                },
                
                OpCode::Cmp => {
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

    #[test]
    fn test_disassemble_load_imm() {
        let mut bytecode = vec![OpCode::LoadImm as u8, 0];
        bytecode.extend_from_slice(&42u64.to_le_bytes());
        
        let instructions = Instruction::disassemble(&bytecode);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, OpCode::LoadImm);
        assert_eq!(instructions[0].operands.len(), 2);
    }

    #[test]
    fn test_pretty_print() {
        let mut bytecode = vec![OpCode::LoadImm as u8, 0];
        bytecode.extend_from_slice(&42u64.to_le_bytes());
        bytecode.push(OpCode::Exit as u8);
        bytecode.push(0);
        
        let instructions = Instruction::disassemble(&bytecode);
        let output = Instruction::pretty_print(&instructions);
        assert!(output.contains("load_imm"));
        assert!(output.contains("exit"));
    }
}
