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
    Mul = 0x07,
    Xor = 0x08,
    Cmp = 0x09,
    Jmp = 0x0A,
    JmpIf = 0x0B,
    Call = 0x0C,
    Ret = 0x0D,
    NativeCall = 0x0E,
    Push = 0x0F,
    Pop = 0x10,
    LoadByte = 0x11,
    LoadStr = 0x12,
    /// 32-bit dword compare (MinGW `cmpl` on stack locals); nested u32 only.
    Cmp32 = 0x13,
    And = 0x14,
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
            0x07 => Some(OpCode::Mul),
            0x08 => Some(OpCode::Xor),
            0x09 => Some(OpCode::Cmp),
            0x0A => Some(OpCode::Jmp),
            0x0B => Some(OpCode::JmpIf),
            0x0C => Some(OpCode::Call),
            0x0D => Some(OpCode::Ret),
            0x0E => Some(OpCode::NativeCall),
            0x0F => Some(OpCode::Push),
            0x10 => Some(OpCode::Pop),
            0x11 => Some(OpCode::LoadByte),
            0x12 => Some(OpCode::LoadStr),
            0x13 => Some(OpCode::Cmp32),
            0x14 => Some(OpCode::And),
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
            OpCode::Mul => "mul",
            OpCode::Xor => "xor",
            OpCode::Cmp => "cmp",
            OpCode::Jmp => "jmp",
            OpCode::JmpIf => "jmp_if",
            OpCode::Call => "call",
            OpCode::Ret => "ret",
            OpCode::NativeCall => "native_call",
            OpCode::Push => "push",
            OpCode::Pop => "pop",
            OpCode::LoadByte => "load_byte",
            OpCode::LoadStr => "load_str",
            OpCode::Cmp32 => "cmp32",
            OpCode::And => "and",
            OpCode::Exit => "exit",
        }
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
