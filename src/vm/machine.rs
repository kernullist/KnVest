use super::opcode::OpCode;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VMError {
    #[error("Invalid opcode: {0:#x}")]
    InvalidOpcode(u8),
    #[error("Invalid register index: {0}")]
    InvalidRegister(u8),
    #[error("Stack underflow")]
    StackUnderflow,
    #[error("Stack overflow")]
    StackOverflow,
    #[error("Memory access violation at {0:#x}")]
    MemoryViolation(usize),
    #[error("Program counter out of bounds")]
    PCOutOfBounds,
    #[error("Division by zero")]
    DivisionByZero,
    #[error("Native call error: {0}")]
    NativeCallError(String),
}

pub type VMResult<T> = Result<T, VMError>;

const NUM_REGISTERS: usize = 16;
const STACK_SIZE: usize = 4096;
const MEMORY_SIZE: usize = 65536;

pub struct VirtualMachine {
    registers: [u64; NUM_REGISTERS],
    pc: usize,
    sp: usize,
    flags: u64,
    stack: Vec<u64>,
    memory: Vec<u8>,
    bytecode: Vec<u8>,
    native_functions: HashMap<u64, fn(&mut VirtualMachine) -> VMResult<()>>,
    pub exit_code: Option<i32>,
    pub data_section: Vec<u8>,
}

impl VirtualMachine {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            registers: [0; NUM_REGISTERS],
            pc: 0,
            sp: 0,
            flags: 0,
            stack: Vec::with_capacity(STACK_SIZE),
            memory: vec![0; MEMORY_SIZE],
            bytecode,
            native_functions: HashMap::new(),
            exit_code: None,
            data_section: Vec::new(),
        }
    }

    pub fn register_native(&mut self, id: u64, func: fn(&mut VirtualMachine) -> VMResult<()>) {
        self.native_functions.insert(id, func);
    }

    pub fn get_register(&self, reg: u8) -> VMResult<u64> {
        if (reg as usize) < NUM_REGISTERS {
            Ok(self.registers[reg as usize])
        } else {
            Err(VMError::InvalidRegister(reg))
        }
    }

    pub fn set_register(&mut self, reg: u8, value: u64) -> VMResult<()> {
        if (reg as usize) < NUM_REGISTERS {
            self.registers[reg as usize] = value;
            Ok(())
        } else {
            Err(VMError::InvalidRegister(reg))
        }
    }

    fn read_u8(&mut self) -> VMResult<u8> {
        if self.pc >= self.bytecode.len() {
            return Err(VMError::PCOutOfBounds);
        }
        let value = self.bytecode[self.pc];
        self.pc += 1;
        Ok(value)
    }

    fn read_u64(&mut self) -> VMResult<u64> {
        if self.pc + 8 > self.bytecode.len() {
            return Err(VMError::PCOutOfBounds);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.bytecode[self.pc..self.pc + 8]);
        self.pc += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    fn push_stack(&mut self, value: u64) -> VMResult<()> {
        if self.stack.len() >= STACK_SIZE {
            return Err(VMError::StackOverflow);
        }
        self.stack.push(value);
        self.sp += 1;
        Ok(())
    }

    fn pop_stack(&mut self) -> VMResult<u64> {
        if self.sp == 0 {
            return Err(VMError::StackUnderflow);
        }
        self.sp -= 1;
        self.stack.pop().ok_or(VMError::StackUnderflow)
    }

    pub fn run(&mut self) -> VMResult<()> {
        while self.exit_code.is_none() && self.pc < self.bytecode.len() {
            self.step()?;
        }
        Ok(())
    }

    pub fn step(&mut self) -> VMResult<()> {
        let opcode_byte = self.read_u8()?;
        let opcode = OpCode::from_u8(opcode_byte)
            .ok_or(VMError::InvalidOpcode(opcode_byte))?;

        match opcode {
            OpCode::Nop => {},
            
            OpCode::LoadImm => {
                let reg = self.read_u8()?;
                let value = self.read_u64()?;
                self.set_register(reg, value)?;
            },
            
            OpCode::LoadMem => {
                let dst = self.read_u8()?;
                let addr_reg = self.read_u8()?;
                let addr = self.get_register(addr_reg)? as usize;
                if addr + 8 > MEMORY_SIZE {
                    return Err(VMError::MemoryViolation(addr));
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&self.memory[addr..addr + 8]);
                self.set_register(dst, u64::from_le_bytes(bytes))?;
            },
            
            OpCode::StoreMem => {
                let addr_reg = self.read_u8()?;
                let src = self.read_u8()?;
                let addr = self.get_register(addr_reg)? as usize;
                let value = self.get_register(src)?;
                if addr + 8 > MEMORY_SIZE {
                    return Err(VMError::MemoryViolation(addr));
                }
                self.memory[addr..addr + 8].copy_from_slice(&value.to_le_bytes());
            },
            
            OpCode::Move => {
                let dst = self.read_u8()?;
                let src = self.read_u8()?;
                let value = self.get_register(src)?;
                self.set_register(dst, value)?;
            },
            
            OpCode::Add => {
                let dst = self.read_u8()?;
                let src1 = self.read_u8()?;
                let src2 = self.read_u8()?;
                let val1 = self.get_register(src1)?;
                let val2 = self.get_register(src2)?;
                self.set_register(dst, val1.wrapping_add(val2))?;
            },
            
            OpCode::Sub => {
                let dst = self.read_u8()?;
                let src1 = self.read_u8()?;
                let src2 = self.read_u8()?;
                let val1 = self.get_register(src1)?;
                let val2 = self.get_register(src2)?;
                self.set_register(dst, val1.wrapping_sub(val2))?;
            },
            
            OpCode::Mul => {
                let dst = self.read_u8()?;
                let src1 = self.read_u8()?;
                let src2 = self.read_u8()?;
                let val1 = self.get_register(src1)?;
                let val2 = self.get_register(src2)?;
                self.set_register(dst, val1.wrapping_mul(val2))?;
            },
            
            OpCode::Xor => {
                let dst = self.read_u8()?;
                let src1 = self.read_u8()?;
                let src2 = self.read_u8()?;
                let val1 = self.get_register(src1)?;
                let val2 = self.get_register(src2)?;
                self.set_register(dst, val1 ^ val2)?;
            },
            
            OpCode::Cmp => {
                let src1 = self.read_u8()?;
                let src2 = self.read_u8()?;
                let val1 = self.get_register(src1)?;
                let val2 = self.get_register(src2)?;
                let result = val1.wrapping_sub(val2);
                let zf = val1 == val2;
                let sf = (result as i64) < 0;
                let cf = val1 < val2;
                let of = ((val1 ^ val2) & (val1 ^ result)) >> 63 != 0;
                self.flags = (if zf { 0x40 } else { 0 })
                    | (if sf { 0x80 } else { 0 })
                    | (if cf { 0x01 } else { 0 })
                    | (if of { 0x800 } else { 0 });
            },

            OpCode::Jmp => {
                let offset = self.read_u64()? as usize;
                self.pc = offset;
            },

            OpCode::JmpIf => {
                let condition = self.read_u8()?;
                let offset = self.read_u64()? as usize;
                let zf = self.flags & 0x40 != 0;
                let sf = self.flags & 0x80 != 0;
                let of = self.flags & 0x800 != 0;
                let should_jump = match condition {
                    1 => zf,                          // JE: ZF=1
                    2 => !zf,                         // JNE: ZF=0
                    3 => sf != of,                    // JL: SF!=OF
                    4 => zf || sf != of,              // JLE
                    5 => !zf && sf == of,             // JG
                    6 => sf == of,                    // JGE
                    _ => false,
                };
                if should_jump {
                    self.pc = offset;
                }
            },
            
            OpCode::Call => {
                let offset = self.read_u64()? as usize;
                self.push_stack(self.pc as u64)?;
                self.pc = offset;
            },
            
            OpCode::Ret => {
                let return_addr = self.pop_stack()? as usize;
                self.pc = return_addr;
            },
            
            OpCode::NativeCall => {
                let func_id = self.read_u64()?;
                if let Some(func) = self.native_functions.get(&func_id) {
                    func(self)?;
                } else {
                    return Err(VMError::NativeCallError(format!("Unknown function ID: {}", func_id)));
                }
            },
            
            OpCode::Push => {
                let reg = self.read_u8()?;
                let value = self.get_register(reg)?;
                self.push_stack(value)?;
            },
            
            OpCode::Pop => {
                let reg = self.read_u8()?;
                let value = self.pop_stack()?;
                self.set_register(reg, value)?;
            },
            
            OpCode::LoadByte => {
                let dst = self.read_u8()?;
                let addr_reg = self.read_u8()?;
                let addr = self.get_register(addr_reg)? as usize;
                
                let byte_val = if addr < self.data_section.len() {
                    self.data_section[addr]
                } else if addr >= 0x10000 && addr < 0x10000 + self.memory.len() {
                    self.memory[addr - 0x10000]
                } else {
                    0
                };
                
                self.set_register(dst, byte_val as u64)?;
            },
            
            OpCode::LoadStr => {
                let dst = self.read_u8()?;
                let offset = self.read_u64()? as usize;
                self.set_register(dst, offset as u64)?;
            },
            
            OpCode::Exit => {
                let code_reg = self.read_u8()?;
                let code = self.get_register(code_reg)? as i32;
                self.exit_code = Some(code);
            },
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_imm() {
        let mut bytecode = vec![
            OpCode::LoadImm as u8, 0, // Load into register 0
        ];
        bytecode.extend_from_slice(&42u64.to_le_bytes());
        bytecode.push(OpCode::Exit as u8);
        bytecode.push(0);

        let mut vm = VirtualMachine::new(bytecode);
        vm.run().unwrap();
        assert_eq!(vm.get_register(0).unwrap(), 42);
    }

    #[test]
    fn test_add() {
        let mut bytecode = vec![
            OpCode::LoadImm as u8, 0,
        ];
        bytecode.extend_from_slice(&10u64.to_le_bytes());
        bytecode.push(OpCode::LoadImm as u8);
        bytecode.push(1);
        bytecode.extend_from_slice(&20u64.to_le_bytes());
        bytecode.extend_from_slice(&[OpCode::Add as u8, 2, 0, 1]);
        bytecode.push(OpCode::Exit as u8);
        bytecode.push(2);

        let mut vm = VirtualMachine::new(bytecode);
        vm.run().unwrap();
        assert_eq!(vm.get_register(2).unwrap(), 30);
    }

    #[test]
    fn test_stack_operations() {
        let mut bytecode = vec![
            OpCode::LoadImm as u8, 0,
        ];
        bytecode.extend_from_slice(&100u64.to_le_bytes());
        bytecode.extend_from_slice(&[OpCode::Push as u8, 0]);
        bytecode.extend_from_slice(&[OpCode::Pop as u8, 1]);
        bytecode.push(OpCode::Exit as u8);
        bytecode.push(1);

        let mut vm = VirtualMachine::new(bytecode);
        vm.run().unwrap();
        assert_eq!(vm.get_register(1).unwrap(), 100);
    }
}
