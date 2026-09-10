use super::dispatch::DispatchMode;
use super::opcode::OpCode;
use super::OpcodeMap;
use std::cell::Cell;

/// Virtual ISA operand model (L5e): register-3-operand vs stack-machine ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum IsaMode {
    #[default]
    Reg,
    Stack,
}

impl IsaMode {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "reg" | "register" => Ok(IsaMode::Reg),
            "stack" => Ok(IsaMode::Stack),
            other => Err(format!(
                "invalid --isa mode {other:?}; expected reg or stack"
            )),
        }
    }

    pub fn as_wire(self) -> u8 {
        match self {
            IsaMode::Reg => 0,
            IsaMode::Stack => 1,
        }
    }

    pub fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(IsaMode::Reg),
            1 => Some(IsaMode::Stack),
            _ => None,
        }
    }

    pub fn is_stack(self) -> bool {
        self == IsaMode::Stack
    }
}

impl std::fmt::Display for IsaMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsaMode::Reg => write!(f, "reg"),
            IsaMode::Stack => write!(f, "stack"),
        }
    }
}

std::thread_local! {
    static ACTIVE_ISA: Cell<IsaMode> = const { Cell::new(IsaMode::Reg) };
}

pub fn set_isa_mode(mode: IsaMode) {
    ACTIVE_ISA.set(mode);
}

pub fn clear_isa_mode() {
    ACTIVE_ISA.set(IsaMode::Reg);
}

pub fn current_isa_mode() -> IsaMode {
    ACTIVE_ISA.get()
}

/// ALU / compare ops whose bytecode operand layout differs in stack mode.
pub fn is_stack_alu_op(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::Add
            | OpCode::Sub
            | OpCode::Mul
            | OpCode::Xor
            | OpCode::And
            | OpCode::Cmp
            | OpCode::Cmp32
    )
}

pub fn operand_len_for(op: OpCode, isa: IsaMode) -> usize {
    if isa.is_stack() && is_stack_alu_op(op) {
        match op {
            OpCode::Cmp | OpCode::Cmp32 => 0,
            _ => 1, // dst only; operands arrive via preceding push ops
        }
    } else {
        op.operand_len_reg()
    }
}

pub fn format_ir_header(isa: IsaMode, map: &OpcodeMap, dispatch_mode: DispatchMode) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "L5e ISA mode | isa={} | seed={:#x} | dispatch={}\n",
        isa,
        map.seed(),
        dispatch_mode
    ));
    if isa.is_stack() {
        out.push_str("Stack ALU encoding:\n");
        out.push_str("  push rA ; push rB ; alu rDst  (pop B, pop A, store rDst)\n");
        out.push_str("  push rA ; push rB ; cmp       (pop B, pop A, set flags)\n");
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_isa_cli_names() {
        assert_eq!(IsaMode::from_str("reg").unwrap(), IsaMode::Reg);
        assert_eq!(IsaMode::from_str("stack").unwrap(), IsaMode::Stack);
        assert!(IsaMode::from_str("bogus").is_err());
    }

    #[test]
    fn wire_roundtrip() {
        for mode in [IsaMode::Reg, IsaMode::Stack] {
            assert_eq!(IsaMode::from_wire(mode.as_wire()), Some(mode));
        }
    }

    #[test]
    fn stack_operand_lens() {
        assert_eq!(operand_len_for(OpCode::Add, IsaMode::Stack), 1);
        assert_eq!(operand_len_for(OpCode::Cmp, IsaMode::Stack), 0);
        assert_eq!(operand_len_for(OpCode::Move, IsaMode::Stack), 2);
        assert_eq!(operand_len_for(OpCode::Add, IsaMode::Reg), 3);
    }
}
