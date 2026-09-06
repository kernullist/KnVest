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
    /// Execute a native sled copied into `.knvest` (L4d partial virt).
    RunNative = 0x15,
    /// Bail out to a single native instruction sled (L4d unknown lift).
    BailNative = 0x16,
    /// L4e block-map refresh at BB entry (meta wire 0xFD only; not in wire shuffle).
    SetBlockMap = 0xFE,
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
            0x15 => Some(OpCode::RunNative),
            0x16 => Some(OpCode::BailNative),
            0xFE => Some(OpCode::SetBlockMap),
            0xFF => Some(OpCode::Exit),
            _ => None,
        }
    }

    /// Operand bytes following the opcode wire byte (L4a logical layout).
    pub fn operand_len(self) -> usize {
        match self {
            OpCode::Nop | OpCode::Ret => 0,
            OpCode::LoadImm | OpCode::LoadStr => 1 + 8,
            OpCode::Move | OpCode::LoadByte | OpCode::LoadMem | OpCode::StoreMem => 2,
            OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Xor | OpCode::And => 3,
            OpCode::Cmp | OpCode::Cmp32 => 2,
            OpCode::Jmp | OpCode::Call | OpCode::NativeCall => 8,
            OpCode::JmpIf => 1 + 8,
            OpCode::Push | OpCode::Pop | OpCode::Exit => 1,
            OpCode::RunNative | OpCode::BailNative => 8 + 8,
            OpCode::SetBlockMap => 2,
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
            OpCode::RunNative => "run_native",
            OpCode::BailNative => "bail_native",
            OpCode::SetBlockMap => "set_block_map",
            OpCode::Exit => "exit",
        }
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
