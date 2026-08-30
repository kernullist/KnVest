use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Nop = 0x00,
    LoadImm = 0x01,
    LoadMem = 0x02,
    StoreMem = 0x03,
    Move = 0x04,
    Add = 0x05,
    Sub = 0x06,
    Xor = 0x07,
    Cmp = 0x08,
    Jmp = 0x09,
    JmpIf = 0x0A,
    Call = 0x0B,
    Ret = 0x0C,
    NativeCall = 0x0D,
    Push = 0x0E,
    Pop = 0x0F,
    Exit = 0xFF,
}

impl OpCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(OpCode::Nop),
            0x01 => Some(OpCode::LoadImm),
            0x02 => Some(OpCode::LoadMem),
            0x03 => Some(OpCode::StoreMem),
            0x04 => Some(OpCode::Move),
            0x05 => Some(OpCode::Add),
            0x06 => Some(OpCode::Sub),
            0x07 => Some(OpCode::Xor),
            0x08 => Some(OpCode::Cmp),
            0x09 => Some(OpCode::Jmp),
            0x0A => Some(OpCode::JmpIf),
            0x0B => Some(OpCode::Call),
            0x0C => Some(OpCode::Ret),
            0x0D => Some(OpCode::NativeCall),
            0x0E => Some(OpCode::Push),
            0x0F => Some(OpCode::Pop),
            0xFF => Some(OpCode::Exit),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            OpCode::Nop => "nop",
            OpCode::LoadImm => "load_imm",
            OpCode::LoadMem => "load_mem",
            OpCode::StoreMem => "store_mem",
            OpCode::Move => "move",
            OpCode::Add => "add",
            OpCode::Sub => "sub",
            OpCode::Xor => "xor",
            OpCode::Cmp => "cmp",
            OpCode::Jmp => "jmp",
            OpCode::JmpIf => "jmp_if",
            OpCode::Call => "call",
            OpCode::Ret => "ret",
            OpCode::NativeCall => "native_call",
            OpCode::Push => "push",
            OpCode::Pop => "pop",
            OpCode::Exit => "exit",
        }
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
