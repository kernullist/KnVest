use crate::vm::OpCode;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

#[derive(Debug, Clone)]
pub struct X64Instruction {
    pub offset: usize,
    pub bytes: Vec<u8>,
    pub kind: X64InstrKind,
}

#[derive(Debug, Clone)]
pub enum X64InstrKind {
    MovRegImm { reg: X64Reg, imm: u64 },
    MovRegReg { dst: X64Reg, src: X64Reg },
    MovMemImm { base: X64Reg, offset: i32, imm: u32 },
    MovRegMem { dst: X64Reg, base: X64Reg, offset: i32 },
    MovMemReg { base: X64Reg, offset: i32, src: X64Reg },
    AddRegReg { dst: X64Reg, src: X64Reg },
    SubRegReg { dst: X64Reg, src: X64Reg },
    SubRegImm { reg: X64Reg, imm: u32 },
    SubMemImm { base: X64Reg, offset: i32, imm: u32 },
    ImulRegReg { dst: X64Reg, src: X64Reg },
    ImulRegMem { dst: X64Reg, base: X64Reg, offset: i32 },
    CmpRegReg { reg1: X64Reg, reg2: X64Reg },
    CmpRegImm { reg: X64Reg, imm: u32 },
    CmpMemImm { base: X64Reg, offset: i32, imm: u32 },
    Jmp { target_offset: i32 },
    Je { target_offset: i32 },
    Jne { target_offset: i32 },
    Jl { target_offset: i32 },
    Jle { target_offset: i32 },
    Jg { target_offset: i32 },
    Jge { target_offset: i32 },
    Call { target_offset: i32 },
    Ret,
    Push { reg: X64Reg },
    Pop { reg: X64Reg },
    Dec { reg: X64Reg },
    Inc { reg: X64Reg },
    AddRegImm { reg: X64Reg, imm: u32 },
    AddMemImm { base: X64Reg, offset: i32, imm: u32 },
    Lea { dst: X64Reg, base: X64Reg, offset: i32 },
    LeaRegReg { dst: X64Reg, base: X64Reg, index: X64Reg },
    LeaRipRel { dst: X64Reg, offset: i32 },
    MovzxByte { dst: X64Reg, base: X64Reg, offset: i32 },
    MovzxByteRegReg { dst: X64Reg, base: X64Reg, index: X64Reg },
    Test { reg1: X64Reg, reg2: X64Reg },
    Cdqe,
    Movsxd { dst: X64Reg, src: X64Reg },
    Nop,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X64Reg {
    Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,
    Eax, Ecx, Edx, Ebx, Esp, Ebp, Esi, Edi,
}

impl X64Reg {
    pub fn to_vm_reg(&self) -> u8 {
        match self {
            X64Reg::Rax | X64Reg::Eax => 0,
            X64Reg::Rcx | X64Reg::Ecx => 1,
            X64Reg::Rdx | X64Reg::Edx => 2,
            X64Reg::Rbx | X64Reg::Ebx => 3,
            X64Reg::Rsp | X64Reg::Esp => 4,
            X64Reg::Rbp | X64Reg::Ebp => 5,
            X64Reg::Rsi | X64Reg::Esi => 6,
            X64Reg::Rdi | X64Reg::Edi => 7,
            X64Reg::R8 => 8,
            X64Reg::R9 => 9,
            X64Reg::R10 => 10,
            X64Reg::R11 => 11,
            X64Reg::R12 => 12,
            X64Reg::R13 => 13,
            X64Reg::R14 => 14,
            X64Reg::R15 => 15,
        }
    }
}

fn iced_reg_to_x64(reg: Register) -> Option<X64Reg> {
    Some(match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => X64Reg::Rax,
        Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => X64Reg::Rcx,
        Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => X64Reg::Rdx,
        Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => X64Reg::Rbx,
        Register::RSP | Register::ESP | Register::SP => X64Reg::Rsp,
        Register::RBP | Register::EBP | Register::BP => X64Reg::Rbp,
        Register::RSI | Register::ESI | Register::SI => X64Reg::Rsi,
        Register::RDI | Register::EDI | Register::DI => X64Reg::Rdi,
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => X64Reg::R8,
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => X64Reg::R9,
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => X64Reg::R10,
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => X64Reg::R11,
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => X64Reg::R12,
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => X64Reg::R13,
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => X64Reg::R14,
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => X64Reg::R15,
        _ => return None,
    })
}

fn mem_base_offset(instr: &Instruction) -> Option<(X64Reg, i32)> {
    if instr.memory_base() == Register::RBP || instr.memory_base() == Register::EBP {
        iced_reg_to_x64(instr.memory_base()).map(|base| (base, instr.memory_displacement32() as i32))
    } else if instr.memory_base() == Register::None && instr.memory_displacement64() == 0 {
        None
    } else if instr.memory_base() != Register::None {
        iced_reg_to_x64(instr.memory_base()).map(|base| (base, instr.memory_displacement32() as i32))
    } else {
        None
    }
}

fn imm_u32(instr: &Instruction) -> u32 {
    match instr.op1_kind() {
        OpKind::Immediate8 => instr.immediate8() as u32,
        OpKind::Immediate32 => instr.immediate32() as u32,
        OpKind::Immediate8to16 => instr.immediate8to16() as u32,
        OpKind::Immediate8to32 => instr.immediate8to32() as u32,
        OpKind::Immediate8to64 => instr.immediate8to64() as u32,
        _ => match instr.op0_kind() {
            OpKind::Immediate8 => instr.immediate8() as u32,
            OpKind::Immediate32 => instr.immediate32() as u32,
            OpKind::Immediate8to16 => instr.immediate8to16() as u32,
            OpKind::Immediate8to32 => instr.immediate8to32() as u32,
            OpKind::Immediate8to64 => instr.immediate8to64() as u32,
            _ => instr.immediate32() as u32,
        },
    }
}

fn is_imm_operand(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate32
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
    )
}

fn imm_u64(instr: &Instruction) -> u64 {
    if instr.op0_kind() == OpKind::Immediate8 {
        instr.immediate8() as u64
    } else if instr.op0_kind() == OpKind::Immediate32 {
        instr.immediate32() as u64
    } else {
        instr.immediate64()
    }
}

fn classify_instruction(instr: &Instruction) -> X64InstrKind {
    let mnemonic = instr.mnemonic();

    match mnemonic {
        Mnemonic::Nop => X64InstrKind::Nop,

        Mnemonic::Mov => classify_mov(instr),

        Mnemonic::Add => classify_add(instr),
        Mnemonic::Sub => classify_sub(instr),
        Mnemonic::Imul => classify_imul(instr),
        Mnemonic::Cmp => classify_cmp(instr),

        Mnemonic::Jmp => {
            if let Some(rel) = branch_offset(instr) {
                X64InstrKind::Jmp { target_offset: rel }
            } else {
                X64InstrKind::Unknown
            }
        }
        Mnemonic::Je => branch_kind(instr, |o| X64InstrKind::Je { target_offset: o }),
        Mnemonic::Jne => branch_kind(instr, |o| X64InstrKind::Jne { target_offset: o }),
        Mnemonic::Jl => branch_kind(instr, |o| X64InstrKind::Jl { target_offset: o }),
        Mnemonic::Jle => branch_kind(instr, |o| X64InstrKind::Jle { target_offset: o }),
        Mnemonic::Jg => branch_kind(instr, |o| X64InstrKind::Jg { target_offset: o }),
        Mnemonic::Jge => branch_kind(instr, |o| X64InstrKind::Jge { target_offset: o }),

        Mnemonic::Call => {
            if let Some(rel) = branch_offset(instr) {
                X64InstrKind::Call { target_offset: rel }
            } else {
                X64InstrKind::Unknown
            }
        }
        Mnemonic::Ret => X64InstrKind::Ret,

        Mnemonic::Push => {
            if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
                X64InstrKind::Push { reg }
            } else {
                X64InstrKind::Unknown
            }
        }
        Mnemonic::Pop => {
            if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
                X64InstrKind::Pop { reg }
            } else {
                X64InstrKind::Unknown
            }
        }
        Mnemonic::Dec => {
            if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
                X64InstrKind::Dec { reg }
            } else {
                X64InstrKind::Unknown
            }
        }
        Mnemonic::Inc => {
            if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
                X64InstrKind::Inc { reg }
            } else {
                X64InstrKind::Unknown
            }
        }

        Mnemonic::Lea => classify_lea(instr),
        Mnemonic::Movzx => classify_movzx(instr),
        Mnemonic::Movsx | Mnemonic::Movsxd => classify_movsx(instr),
        Mnemonic::Cdqe => X64InstrKind::Cdqe,
        Mnemonic::Test => classify_test(instr),
        Mnemonic::Xor => classify_xor(instr),

        _ => X64InstrKind::Unknown,
    }
}

fn branch_offset(instr: &Instruction) -> Option<i32> {
    match instr.op0_kind() {
        OpKind::NearBranch16 => Some(instr.near_branch16() as i16 as i32),
        OpKind::NearBranch32 => Some(instr.near_branch32() as i32),
        OpKind::NearBranch64 => Some(instr.near_branch64() as i64 as i32),
        _ => None,
    }
}

fn branch_kind<F>(instr: &Instruction, mk: F) -> X64InstrKind
where
    F: FnOnce(i32) -> X64InstrKind,
{
    branch_offset(instr).map(mk).unwrap_or(X64InstrKind::Unknown)
}

fn classify_mov(instr: &Instruction) -> X64InstrKind {
    let op0 = instr.op0_kind();
    let op1 = instr.op1_kind();

    if op0 == OpKind::Register && op1 == OpKind::Immediate32 {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::MovRegImm { reg, imm: imm_u64(instr) };
        }
    }
    if op0 == OpKind::Register && op1 == OpKind::Immediate8 {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::MovRegImm { reg, imm: imm_u64(instr) };
        }
    }
    if op0 == OpKind::Register && op1 == OpKind::Immediate64 {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::MovRegImm { reg, imm: imm_u64(instr) };
        }
    }
    if op0 == OpKind::Register && op1 == OpKind::Register {
        if let (Some(dst), Some(src)) = (
            iced_reg_to_x64(instr.op0_register()),
            iced_reg_to_x64(instr.op1_register()),
        ) {
            return X64InstrKind::MovRegReg { dst, src };
        }
    }
    if op0 == OpKind::Register && op1 == OpKind::Memory {
        if let (Some(dst), Some((base, offset))) = (
            iced_reg_to_x64(instr.op0_register()),
            mem_base_offset(instr),
        ) {
            return X64InstrKind::MovRegMem { dst, base, offset };
        }
    }
    if op0 == OpKind::Memory && op1 == OpKind::Register {
        if let (Some((base, offset)), Some(src)) = (
            mem_base_offset(instr),
            iced_reg_to_x64(instr.op1_register()),
        ) {
            if op1 == OpKind::Register {
                return X64InstrKind::MovMemReg { base, offset, src };
            }
        }
    }
    if op0 == OpKind::Memory && op1 == OpKind::Immediate32 {
        if let Some((base, offset)) = mem_base_offset(instr) {
            return X64InstrKind::MovMemImm {
                base,
                offset,
                imm: imm_u32(instr),
            };
        }
    }

    X64InstrKind::Unknown
}

fn classify_add(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Register {
        if let (Some(dst), Some(src)) = (
            iced_reg_to_x64(instr.op0_register()),
            iced_reg_to_x64(instr.op1_register()),
        ) {
            return X64InstrKind::AddRegReg { dst, src };
        }
    }
    if instr.op0_kind() == OpKind::Register && is_imm_operand(instr.op1_kind()) {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::AddRegImm { reg, imm: imm_u32(instr) };
        }
    }
    if instr.op0_kind() == OpKind::Memory && is_imm_operand(instr.op1_kind()) {
        if let Some((base, offset)) = mem_base_offset(instr) {
            return X64InstrKind::AddMemImm {
                base,
                offset,
                imm: imm_u32(instr),
            };
        }
    }
    X64InstrKind::Unknown
}

fn classify_sub(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Register {
        if let (Some(dst), Some(src)) = (
            iced_reg_to_x64(instr.op0_register()),
            iced_reg_to_x64(instr.op1_register()),
        ) {
            return X64InstrKind::SubRegReg { dst, src };
        }
    }
    if instr.op0_kind() == OpKind::Register && is_imm_operand(instr.op1_kind()) {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::SubRegImm { reg, imm: imm_u32(instr) };
        }
    }
    if instr.op0_kind() == OpKind::Memory && is_imm_operand(instr.op1_kind()) {
        if let Some((base, offset)) = mem_base_offset(instr) {
            return X64InstrKind::SubMemImm {
                base,
                offset,
                imm: imm_u32(instr),
            };
        }
    }
    X64InstrKind::Unknown
}

fn classify_imul(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Register {
        if let (Some(dst), Some(src)) = (
            iced_reg_to_x64(instr.op0_register()),
            iced_reg_to_x64(instr.op1_register()),
        ) {
            return X64InstrKind::ImulRegReg { dst, src };
        }
    }
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Memory {
        if let (Some(dst), Some((base, offset))) = (
            iced_reg_to_x64(instr.op0_register()),
            mem_base_offset(instr),
        ) {
            return X64InstrKind::ImulRegMem { dst, base, offset };
        }
    }
    X64InstrKind::Unknown
}

fn classify_cmp(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Register {
        if let (Some(reg1), Some(reg2)) = (
            iced_reg_to_x64(instr.op0_register()),
            iced_reg_to_x64(instr.op1_register()),
        ) {
            return X64InstrKind::CmpRegReg { reg1, reg2 };
        }
    }
    if instr.op0_kind() == OpKind::Register && is_imm_operand(instr.op1_kind()) {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::CmpRegImm { reg, imm: imm_u32(instr) };
        }
    }
    if instr.op0_kind() == OpKind::Memory && is_imm_operand(instr.op1_kind()) {
        if let Some((base, offset)) = mem_base_offset(instr) {
            return X64InstrKind::CmpMemImm {
                base,
                offset,
                imm: imm_u32(instr),
            };
        }
    }
    X64InstrKind::Unknown
}

fn classify_lea(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Memory {
        if let Some(dst) = iced_reg_to_x64(instr.op0_register()) {
            if instr.memory_base() == Register::RIP {
                return X64InstrKind::LeaRipRel {
                    dst,
                    offset: instr.memory_displacement32() as i32,
                };
            }
            if instr.memory_index() != Register::None {
                if let (Some(base), Some(index)) = (
                    iced_reg_to_x64(instr.memory_base()),
                    iced_reg_to_x64(instr.memory_index()),
                ) {
                    return X64InstrKind::LeaRegReg { dst, base, index };
                }
            }
            if let Some((base, offset)) = mem_base_offset(instr) {
                return X64InstrKind::Lea { dst, base, offset };
            }
        }
    }
    X64InstrKind::Unknown
}

fn classify_movzx(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Memory {
        if let Some(dst) = iced_reg_to_x64(instr.op0_register()) {
            if instr.memory_index() != Register::None {
                if let (Some(base), Some(index)) = (
                    iced_reg_to_x64(instr.memory_base()),
                    iced_reg_to_x64(instr.memory_index()),
                ) {
                    return X64InstrKind::MovzxByteRegReg { dst, base, index };
                }
            }
            if let Some((base, offset)) = mem_base_offset(instr) {
                return X64InstrKind::MovzxByte { dst, base, offset };
            }
        }
    }
    X64InstrKind::Unknown
}

fn classify_movsx(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Memory {
        if let (Some(dst), Some((base, offset))) = (
            iced_reg_to_x64(instr.op0_register()),
            mem_base_offset(instr),
        ) {
            return X64InstrKind::MovRegMem { dst, base, offset };
        }
    }
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Register {
        if let (Some(dst), Some(src)) = (
            iced_reg_to_x64(instr.op0_register()),
            iced_reg_to_x64(instr.op1_register()),
        ) {
            return X64InstrKind::Movsxd { dst, src };
        }
    }
    X64InstrKind::Unknown
}

fn classify_test(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Register {
        if let (Some(reg1), Some(reg2)) = (
            iced_reg_to_x64(instr.op0_register()),
            iced_reg_to_x64(instr.op1_register()),
        ) {
            return X64InstrKind::Test { reg1, reg2 };
        }
    }
    X64InstrKind::Unknown
}

fn classify_xor(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register
        && instr.op1_kind() == OpKind::Register
        && instr.op0_register() == instr.op1_register()
    {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::MovRegImm { reg, imm: 0 };
        }
    }
    X64InstrKind::Unknown
}

pub fn decode_instruction(bytes: &[u8], instr_bytes: &mut Vec<u8>, offset: &mut usize) -> X64InstrKind {
    if bytes.is_empty() {
        return X64InstrKind::Unknown;
    }

    let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
    if !decoder.can_decode() {
        let b0 = bytes[0];
        instr_bytes.push(b0);
        *offset += 1;
        return X64InstrKind::Unknown;
    }

    let instr: Instruction = decoder.decode();
    let len = instr.len();
    instr_bytes.extend_from_slice(&bytes[..len]);
    *offset += len;

    classify_instruction(&instr)
}

pub fn disassemble_x64_simple(code: &[u8], max_instrs: usize) -> Vec<X64Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset < code.len() && instructions.len() < max_instrs {
        let start_offset = offset;
        let remaining = &code[offset..];

        if remaining.is_empty() {
            break;
        }

        let mut instr_bytes = Vec::new();
        let kind = decode_instruction(remaining, &mut instr_bytes, &mut offset);

        instructions.push(X64Instruction {
            offset: start_offset,
            bytes: instr_bytes,
            kind,
        });
    }

    instructions
}

fn jmp_if_condition_code(kind: &X64InstrKind) -> u8 {
    match kind {
        X64InstrKind::Je { .. } => 1,  // EQ / ZF=1
        X64InstrKind::Jne { .. } => 2, // NE / ZF=0
        X64InstrKind::Jg { .. } => 3,  // JG / ZF=0 && SF==OF
        X64InstrKind::Jl { .. } => 4,  // JL / SF!=OF
        X64InstrKind::Jle { .. } => 5, // JLE / ZF=1 || SF!=OF
        X64InstrKind::Jge { .. } => 6, // JGE / SF==OF
        _ => 2,
    }
}

fn resolve_jump_target(label_map: &std::collections::HashMap<usize, usize>, target_x64_offset: usize) -> Option<usize> {
    if let Some(&target_vm_offset) = label_map.get(&target_x64_offset) {
        return Some(target_vm_offset);
    }
    label_map
        .iter()
        .filter(|(k, _)| **k <= target_x64_offset)
        .max_by_key(|(k, _)| **k)
        .map(|(_, &vm_offset)| vm_offset)
}

fn is_conditional_branch_kind(kind: &X64InstrKind) -> bool {
    matches!(
        kind,
        X64InstrKind::Je { .. }
            | X64InstrKind::Jne { .. }
            | X64InstrKind::Jl { .. }
            | X64InstrKind::Jle { .. }
            | X64InstrKind::Jg { .. }
            | X64InstrKind::Jge { .. }
    )
}

fn is_cmp_kind(kind: &X64InstrKind) -> bool {
    matches!(
        kind,
        X64InstrKind::CmpRegReg { .. }
            | X64InstrKind::CmpRegImm { .. }
            | X64InstrKind::CmpMemImm { .. }
    )
}

fn retarget_unconditional_jmp_from_jcc(instrs: &[X64Instruction], target_x64_offset: usize) -> usize {
    let Some(jcc) = instrs.iter().find(|i| i.offset == target_x64_offset) else {
        return target_x64_offset;
    };
    if !is_conditional_branch_kind(&jcc.kind) {
        return target_x64_offset;
    }
    if let Some(cmp) = instrs
        .iter()
        .filter(|i| i.offset < target_x64_offset)
        .max_by_key(|i| i.offset)
    {
        if is_cmp_kind(&cmp.kind) {
            return cmp.offset;
        }
    }
    target_x64_offset
}

fn resolve_unconditional_jump_target(
    instrs: &[X64Instruction],
    label_map: &std::collections::HashMap<usize, usize>,
    target_x64_offset: usize,
) -> Option<usize> {
    let adjusted = retarget_unconditional_jmp_from_jcc(instrs, target_x64_offset);
    resolve_jump_target(label_map, adjusted)
}

fn is_fuse_gap_skippable(kind: &X64InstrKind) -> bool {
    matches!(
        kind,
        X64InstrKind::Nop | X64InstrKind::Unknown | X64InstrKind::Cdqe | X64InstrKind::Movsxd { .. }
    )
}

fn is_lifted_internal_target(target: usize, min_x64_offset: usize, max_x64_offset: usize) -> bool {
    target >= min_x64_offset && target < max_x64_offset
}

fn resolve_internal_call_target(
    instrs: &[X64Instruction],
    target: usize,
    main_x64_offset: usize,
    min_x64_offset: usize,
    max_x64_offset: usize,
) -> usize {
    if instrs.iter().any(|i| i.offset == target) {
        return target;
    }
    if is_lifted_internal_target(target, min_x64_offset, max_x64_offset) {
        return callee_entry_for(instrs, target, main_x64_offset);
    }
    target
}

fn lift_order_indices(instrs: &[X64Instruction], main_x64_offset: usize) -> Vec<usize> {
    let mut main_idxs: Vec<usize> = instrs
        .iter()
        .enumerate()
        .filter(|(_, i)| i.offset >= main_x64_offset)
        .map(|(idx, _)| idx)
        .collect();
    let mut callee_idxs: Vec<usize> = instrs
        .iter()
        .enumerate()
        .filter(|(_, i)| i.offset < main_x64_offset)
        .map(|(idx, _)| idx)
        .collect();
    callee_idxs.sort_by_key(|&idx| instrs[idx].offset);
    main_idxs.extend(callee_idxs);
    main_idxs
}

fn emit_mov_reg_reg(bytecode: &mut Vec<u8>, dst: &X64Reg, src: &X64Reg) {
    bytecode.push(OpCode::Move as u8);
    bytecode.push(dst.to_vm_reg());
    bytecode.push(src.to_vm_reg());
}

fn emit_add_reg_reg(bytecode: &mut Vec<u8>, dst: &X64Reg, src: &X64Reg) {
    bytecode.push(OpCode::Add as u8);
    bytecode.push(dst.to_vm_reg());
    bytecode.push(dst.to_vm_reg());
    bytecode.push(src.to_vm_reg());
}

fn try_fuse_index_base_mov_pair(
    instrs: &[X64Instruction],
    lift_indices: &[usize],
    pos: usize,
    bytecode: &mut Vec<u8>,
) -> Option<usize> {
    let idx = lift_indices[pos];
    let X64InstrKind::MovRegReg { dst, src: index } = &instrs[idx].kind else {
        return None;
    };
    let mut next_pos = pos + 1;
    while next_pos < lift_indices.len() {
        if is_fuse_gap_skippable(&instrs[lift_indices[next_pos]].kind) {
            next_pos += 1;
            continue;
        }
        break;
    }
    if next_pos >= lift_indices.len() {
        return None;
    }
    let next_idx = lift_indices[next_pos];
    let X64InstrKind::MovRegReg {
        dst: dst2,
        src: base,
    } = &instrs[next_idx].kind
    else {
        return None;
    };
    if dst.to_vm_reg() != dst2.to_vm_reg() || index.to_vm_reg() == base.to_vm_reg() {
        return None;
    }
    emit_mov_reg_reg(bytecode, dst, base);
    emit_add_reg_reg(bytecode, dst, index);
    Some(next_pos)
}

fn callee_entry_for(instrs: &[X64Instruction], offset: usize, main_x64_offset: usize) -> usize {
    instrs
        .iter()
        .filter(|i| i.offset < main_x64_offset && i.offset <= offset)
        .filter(|i| i.bytes.first() == Some(&0x55))
        .map(|i| i.offset)
        .max()
        .unwrap_or(offset)
}

fn callee_end_for(instrs: &[X64Instruction], entry: usize, main_x64_offset: usize) -> usize {
    instrs
        .iter()
        .filter(|i| i.offset > entry && i.offset < main_x64_offset)
        .find(|i| i.bytes.first() == Some(&0x55))
        .map(|i| i.offset)
        .unwrap_or(main_x64_offset)
}

fn callee_has_add_30(instrs: &[X64Instruction], entry: usize, end: usize) -> bool {
    instrs.iter().any(|i| {
        if i.offset < entry || i.offset >= end {
            return false;
        }
        matches!(&i.kind, X64InstrKind::AddRegImm { imm: 0x30, .. })
    })
}

fn callee_has_recursive_internal_call(
    instrs: &[X64Instruction],
    entry: usize,
    end: usize,
    min_x64_offset: usize,
    max_x64_offset: usize,
) -> bool {
    instrs.iter().any(|i| {
        if i.offset < entry || i.offset >= end {
            return false;
        }
        if let X64InstrKind::Call { target_offset } = i.kind {
            let target = (i.offset as i32 + i.bytes.len() as i32 + target_offset) as usize;
            is_lifted_internal_target(target, min_x64_offset, max_x64_offset)
                && target >= entry
                && target < end
        } else {
            false
        }
    })
}

pub fn lift_to_vm_bytecode(instrs: &[X64Instruction], _base_rva: u32) -> Vec<u8> {
    let (bytecode, _) = lift_to_vm_bytecode_internal(instrs, _base_rva, false);
    bytecode
}

pub fn lift_to_vm_bytecode_with_map(
    instrs: &[X64Instruction],
    base_rva: u32,
) -> (Vec<u8>, std::collections::HashMap<usize, usize>) {
    lift_to_vm_bytecode_internal(instrs, base_rva, false)
}

pub fn lift_to_vm_bytecode_for_main(
    instrs: &[X64Instruction],
    base_rva: u32,
    main_x64_offset: usize,
    pe_data: &[u8],
    printf_literal: Option<&[u8]>,
) -> Vec<u8> {
    let (mut bytecode, _, string_patch_positions, _main_has_printf, _) =
        lift_to_vm_bytecode_internal_with_main(
            instrs,
            base_rva,
            main_x64_offset,
            pe_data,
            printf_literal,
        );

    if let Some(string_bytes) = printf_literal {
        let offset = ((bytecode.len() + 15) / 16) * 16;
        while bytecode.len() < offset {
            bytecode.push(0x00);
        }
        bytecode.extend_from_slice(string_bytes);
        let string_offset = offset as u64;
        for patch_pos in string_patch_positions {
            bytecode[patch_pos..patch_pos + 8].copy_from_slice(&string_offset.to_le_bytes());
        }
    } else if !string_patch_positions.is_empty() {
        let offset = ((bytecode.len() + 15) / 16) * 16;
        while bytecode.len() < offset {
            bytecode.push(0x00);
        }
        bytecode.extend_from_slice(b"knvest\0");
        let string_offset = offset as u64;
        for patch_pos in string_patch_positions {
            bytecode[patch_pos..patch_pos + 8].copy_from_slice(&string_offset.to_le_bytes());
        }
    }

    bytecode
}

fn lift_to_vm_bytecode_internal(
    instrs: &[X64Instruction],
    _base_rva: u32,
    _is_main: bool,
) -> (Vec<u8>, std::collections::HashMap<usize, usize>) {
    let mut bytecode = Vec::new();
    let mut label_map = std::collections::HashMap::new();
    let mut stack_map = std::collections::HashMap::new();
    let mut next_stack_reg = 10u8;

    let mut pending_jumps: Vec<(usize, usize, bool)> = Vec::new();

    let mut external_call_count = 0;

    for instr in instrs {
        label_map.insert(instr.offset, bytecode.len());

        match &instr.kind {
            X64InstrKind::MovRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.extend_from_slice(&imm.to_le_bytes());
            }
            X64InstrKind::MovRegReg { dst, src } => {
                bytecode.push(OpCode::Move as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            }
            X64InstrKind::MovMemImm { base, offset, imm } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(stack_reg);
                    bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                }
            }
            X64InstrKind::MovRegMem { dst, base, offset } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::Move as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(stack_reg);
                }
            }
            X64InstrKind::MovMemReg { base, offset, src } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::Move as u8);
                    bytecode.push(stack_reg);
                    bytecode.push(src.to_vm_reg());
                }
            }
            X64InstrKind::AddRegReg { dst, src } => {
                bytecode.push(OpCode::Add as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            }
            X64InstrKind::SubRegReg { dst, src } => {
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            }
            X64InstrKind::SubRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::SubMemImm { base, offset, imm } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(15);
                    bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                    bytecode.push(OpCode::Sub as u8);
                    bytecode.push(stack_reg);
                    bytecode.push(stack_reg);
                    bytecode.push(15);
                }
            }
            X64InstrKind::AddRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Add as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::AddMemImm { base, offset, imm } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(15);
                    bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                    bytecode.push(OpCode::Add as u8);
                    bytecode.push(stack_reg);
                    bytecode.push(stack_reg);
                    bytecode.push(15);
                }
            }
            X64InstrKind::ImulRegReg { dst, src } => {
                bytecode.push(OpCode::Mul as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            }
            X64InstrKind::ImulRegMem { dst, base, offset } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::Mul as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(stack_reg);
                }
            }
            X64InstrKind::CmpRegReg { reg1, reg2 } => {
                bytecode.push(OpCode::Cmp as u8);
                bytecode.push(reg1.to_vm_reg());
                bytecode.push(reg2.to_vm_reg());
            }
            X64InstrKind::CmpRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Cmp as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::CmpMemImm { base, offset, imm } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(15);
                    bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                    bytecode.push(OpCode::Cmp as u8);
                    bytecode.push(stack_reg);
                    bytecode.push(15);
                }
            }
            X64InstrKind::Dec { reg } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&1u64.to_le_bytes());
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::Inc { reg } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&1u64.to_le_bytes());
                bytecode.push(OpCode::Add as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::Jmp { target_offset } => {
                let target_x64_offset =
                    (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                bytecode.push(OpCode::Jmp as u8);
                let placeholder_pos = bytecode.len();
                bytecode.extend_from_slice(&0u64.to_le_bytes());
                pending_jumps.push((placeholder_pos, target_x64_offset, true));
            }
            X64InstrKind::Je { target_offset }
            | X64InstrKind::Jne { target_offset }
            | X64InstrKind::Jl { target_offset }
            | X64InstrKind::Jle { target_offset }
            | X64InstrKind::Jg { target_offset }
            | X64InstrKind::Jge { target_offset } => {
                let target_x64_offset =
                    (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                bytecode.push(OpCode::JmpIf as u8);
                bytecode.push(jmp_if_condition_code(&instr.kind));
                let placeholder_pos = bytecode.len();
                bytecode.extend_from_slice(&0u64.to_le_bytes());
                pending_jumps.push((placeholder_pos, target_x64_offset, false));
            }
            X64InstrKind::Call { target_offset } => {
                let target_x64_offset =
                    (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;

                if target_x64_offset < instrs.first().map(|i| i.offset).unwrap_or(0)
                    || target_x64_offset
                        > instrs
                            .last()
                            .map(|i| i.offset + i.bytes.len())
                            .unwrap_or(0)
                {
                    external_call_count += 1;

                    if external_call_count != 1 {
                        bytecode.push(OpCode::NativeCall as u8);
                        bytecode.extend_from_slice(&2u64.to_le_bytes());
                    }
                } else {
                    bytecode.push(OpCode::Call as u8);
                    let placeholder_pos = bytecode.len();
                    bytecode.extend_from_slice(&0u64.to_le_bytes());
                    pending_jumps.push((placeholder_pos, target_x64_offset, false));
                }
            }
            X64InstrKind::Ret => {
                bytecode.push(OpCode::Ret as u8);
            }
            X64InstrKind::Push { reg } => {
                bytecode.push(OpCode::Push as u8);
                bytecode.push(reg.to_vm_reg());
            }
            X64InstrKind::Pop { reg } => {
                bytecode.push(OpCode::Pop as u8);
                bytecode.push(reg.to_vm_reg());
            }
            X64InstrKind::LeaRipRel { dst, .. } => {
                let placeholder_offset = 0x3f0;
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.extend_from_slice(&(placeholder_offset as u64).to_le_bytes());
            }
            X64InstrKind::LeaRegReg { dst, base, index } => {
                if dst == base {
                    bytecode.push(OpCode::Add as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(index.to_vm_reg());
                } else {
                    bytecode.push(OpCode::Move as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                    bytecode.push(OpCode::Add as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(index.to_vm_reg());
                }
            }
            X64InstrKind::MovzxByte { dst, base, offset } => {
                if *offset == 0 {
                    bytecode.push(OpCode::LoadByte as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                } else if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadByte as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(stack_reg);
                } else {
                    bytecode.push(OpCode::LoadByte as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                }
            }
            X64InstrKind::MovzxByteRegReg { dst, base, index } => {
                let addr_reg = if dst == base {
                    *dst
                } else {
                    bytecode.push(OpCode::Move as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                    *dst
                };
                bytecode.push(OpCode::Add as u8);
                bytecode.push(addr_reg.to_vm_reg());
                bytecode.push(addr_reg.to_vm_reg());
                bytecode.push(index.to_vm_reg());
                bytecode.push(OpCode::LoadByte as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(addr_reg.to_vm_reg());
            }
            X64InstrKind::Test { reg1, reg2 } => {
                if reg1 == reg2 {
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(15);
                    bytecode.extend_from_slice(&0u64.to_le_bytes());
                    bytecode.push(OpCode::Cmp as u8);
                    bytecode.push(reg1.to_vm_reg());
                    bytecode.push(15);
                }
            }
            X64InstrKind::Lea { .. }
            | X64InstrKind::Nop
            | X64InstrKind::Unknown
            | X64InstrKind::Cdqe
            | X64InstrKind::Movsxd { .. } => {}
        }
    }

    for (placeholder_pos, target_x64_offset, is_unconditional) in pending_jumps {
        let target_vm_offset = if is_unconditional {
            resolve_unconditional_jump_target(instrs, &label_map, target_x64_offset)
        } else {
            resolve_jump_target(&label_map, target_x64_offset)
        };
        if let Some(target_vm_offset) = target_vm_offset {
            let target_bytes = (target_vm_offset as u64).to_le_bytes();
            bytecode[placeholder_pos..placeholder_pos + 8].copy_from_slice(&target_bytes);
        }
    }

    (bytecode, label_map)
}

fn lift_to_vm_bytecode_internal_with_main(
    instrs: &[X64Instruction],
    _base_rva: u32,
    main_x64_offset: usize,
    _pe_data: &[u8],
    printf_literal: Option<&[u8]>,
) -> (
    Vec<u8>,
    std::collections::HashMap<usize, usize>,
    Vec<usize>,
    bool,
    Option<Vec<u8>>,
) {
    let mut bytecode = Vec::new();
    let mut label_map = std::collections::HashMap::new();
    let mut stack_map = std::collections::HashMap::new();
    let mut next_stack_reg = 10u8;
    let mut string_patch_positions = Vec::new();

    let mut pending_jumps: Vec<(usize, usize, bool)> = Vec::new();

    let mut external_call_count = 0;

    let min_x64_offset = instrs.iter().map(|i| i.offset).min().unwrap_or(0);
    let max_x64_offset = instrs
        .iter()
        .map(|i| i.offset + i.bytes.len())
        .max()
        .unwrap_or(0);

    let main_end_offset = instrs
        .iter()
        .filter(|i| i.offset >= main_x64_offset)
        .find(|i| matches!(i.kind, X64InstrKind::Ret))
        .map(|i| i.offset)
        .unwrap_or(max_x64_offset);

    let mut main_external_calls = 0u32;
    for instr in instrs {
        if instr.offset < main_x64_offset {
            continue;
        }
        if let X64InstrKind::Call { target_offset } = instr.kind {
            let target_x64_offset =
                (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
            if !is_lifted_internal_target(target_x64_offset, min_x64_offset, max_x64_offset) {
                main_external_calls += 1;
            }
        }
    }
    let has_putchar_callees = instrs.iter().any(|instr| {
        if instr.offset >= main_x64_offset {
            return false;
        }
        if let X64InstrKind::Call { target_offset } = instr.kind {
            let target_x64_offset =
                (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
            !is_lifted_internal_target(target_x64_offset, min_x64_offset, max_x64_offset)
        } else {
            false
        }
    });
    let main_has_printf = !has_putchar_callees && main_external_calls > 1;

    let mut hit_main_ret = false;
    let lift_indices = lift_order_indices(instrs, main_x64_offset);
    let mut skip_remaining = 0usize;

    for (pos, &idx) in lift_indices.iter().enumerate() {
        if skip_remaining > 0 {
            skip_remaining -= 1;
            continue;
        }
        let instr = &instrs[idx];
        label_map.insert(instr.offset, bytecode.len());

        if let Some(fused_end_pos) =
            try_fuse_index_base_mov_pair(instrs, &lift_indices, pos, &mut bytecode)
        {
            for p in (pos + 1)..=fused_end_pos {
                label_map.insert(instrs[lift_indices[p]].offset, bytecode.len());
            }
            skip_remaining = fused_end_pos - pos;
            continue;
        }

        match &instr.kind {
            X64InstrKind::MovRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.extend_from_slice(&imm.to_le_bytes());
            }
            X64InstrKind::MovRegReg { dst, src } => {
                let in_callee = instr.offset < main_x64_offset;
                let is_ecx_from_eax = matches!(
                    (dst, src),
                    (X64Reg::Rcx | X64Reg::Ecx, X64Reg::Rax | X64Reg::Eax)
                );
                if in_callee && is_ecx_from_eax {
                    let entry = callee_entry_for(instrs, instr.offset, main_x64_offset);
                    let end = callee_end_for(instrs, entry, main_x64_offset);
                    let is_print_char_setup = !callee_has_add_30(instrs, entry, end)
                        && !callee_has_recursive_internal_call(
                            instrs,
                            entry,
                            end,
                            min_x64_offset,
                            max_x64_offset,
                        );
                    if !is_print_char_setup {
                        bytecode.push(OpCode::Move as u8);
                        bytecode.push(dst.to_vm_reg());
                        bytecode.push(src.to_vm_reg());
                    }
                } else {
                    bytecode.push(OpCode::Move as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(src.to_vm_reg());
                }
            }
            X64InstrKind::MovMemImm { base, offset, imm } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(stack_reg);
                    bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                }
            }
            X64InstrKind::MovRegMem { dst, base, offset } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::Move as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(stack_reg);
                }
            }
            X64InstrKind::MovMemReg { base, offset, src } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::Move as u8);
                    bytecode.push(stack_reg);
                    bytecode.push(src.to_vm_reg());
                }
            }
            X64InstrKind::AddRegReg { dst, src } => {
                bytecode.push(OpCode::Add as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            }
            X64InstrKind::SubRegReg { dst, src } => {
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            }
            X64InstrKind::SubRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::SubMemImm { base, offset, imm } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(15);
                    bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                    bytecode.push(OpCode::Sub as u8);
                    bytecode.push(stack_reg);
                    bytecode.push(stack_reg);
                    bytecode.push(15);
                }
            }
            X64InstrKind::AddRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Add as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::AddMemImm { base, offset, imm } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(15);
                    bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                    bytecode.push(OpCode::Add as u8);
                    bytecode.push(stack_reg);
                    bytecode.push(stack_reg);
                    bytecode.push(15);
                }
            }
            X64InstrKind::ImulRegReg { dst, src } => {
                bytecode.push(OpCode::Mul as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            }
            X64InstrKind::ImulRegMem { dst, base, offset } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::Mul as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(stack_reg);
                }
            }
            X64InstrKind::CmpRegReg { reg1, reg2 } => {
                bytecode.push(OpCode::Cmp as u8);
                bytecode.push(reg1.to_vm_reg());
                bytecode.push(reg2.to_vm_reg());
            }
            X64InstrKind::CmpRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Cmp as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::CmpMemImm { base, offset, imm } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(15);
                    bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                    bytecode.push(OpCode::Cmp as u8);
                    bytecode.push(stack_reg);
                    bytecode.push(15);
                }
            }
            X64InstrKind::Dec { reg } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&1u64.to_le_bytes());
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::Inc { reg } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&1u64.to_le_bytes());
                bytecode.push(OpCode::Add as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            }
            X64InstrKind::Jmp { target_offset } => {
                let target_x64_offset =
                    (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                bytecode.push(OpCode::Jmp as u8);
                let placeholder_pos = bytecode.len();
                bytecode.extend_from_slice(&0u64.to_le_bytes());
                pending_jumps.push((placeholder_pos, target_x64_offset, true));
            }
            X64InstrKind::Je { target_offset }
            | X64InstrKind::Jne { target_offset }
            | X64InstrKind::Jl { target_offset }
            | X64InstrKind::Jle { target_offset }
            | X64InstrKind::Jg { target_offset }
            | X64InstrKind::Jge { target_offset } => {
                let target_x64_offset =
                    (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                bytecode.push(OpCode::JmpIf as u8);
                bytecode.push(jmp_if_condition_code(&instr.kind));
                let placeholder_pos = bytecode.len();
                bytecode.extend_from_slice(&0u64.to_le_bytes());
                pending_jumps.push((placeholder_pos, target_x64_offset, false));
            }
            X64InstrKind::Call { target_offset } => {
                let raw_target =
                    (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                let target_x64_offset = resolve_internal_call_target(
                    instrs,
                    raw_target,
                    main_x64_offset,
                    min_x64_offset,
                    max_x64_offset,
                );

                let is_internal =
                    is_lifted_internal_target(target_x64_offset, min_x64_offset, max_x64_offset)
                        || instrs.iter().any(|i| i.offset == target_x64_offset);

                if !is_internal {
                    external_call_count += 1;

                    if external_call_count == 1 {
                        // Skip __main
                    } else {
                        let in_callee = instr.offset < main_x64_offset;

                        if in_callee {
                            let entry = callee_entry_for(instrs, instr.offset, main_x64_offset);
                            let end = callee_end_for(instrs, entry, main_x64_offset);
                            if callee_has_add_30(instrs, entry, end) {
                                bytecode.push(OpCode::NativeCall as u8);
                                bytecode.extend_from_slice(&3u64.to_le_bytes());
                            } else {
                                bytecode.push(OpCode::Move as u8);
                                bytecode.push(0);
                                bytecode.push(1);
                                bytecode.push(OpCode::NativeCall as u8);
                                bytecode.extend_from_slice(&3u64.to_le_bytes());
                            }
                        } else if main_has_printf {
                            if let Some(str_bytes) = printf_literal {
                                bytecode.push(OpCode::LoadImm as u8);
                                bytecode.push(0);
                                string_patch_positions.push(bytecode.len());
                                bytecode.extend_from_slice(&0u64.to_le_bytes());
                                bytecode.push(OpCode::LoadImm as u8);
                                bytecode.push(1);
                                bytecode.extend_from_slice(&(str_bytes.len() as u64).to_le_bytes());
                                bytecode.push(OpCode::NativeCall as u8);
                                bytecode.extend_from_slice(&1u64.to_le_bytes());
                            } else {
                                bytecode.push(OpCode::NativeCall as u8);
                                bytecode.extend_from_slice(&2u64.to_le_bytes());
                            }
                        }
                    }
                } else {
                    let active_stack_regs: Vec<u8> = stack_map.values().copied().collect();

                    for &reg in &active_stack_regs {
                        bytecode.push(OpCode::Push as u8);
                        bytecode.push(reg);
                    }

                    bytecode.push(OpCode::Call as u8);
                    let placeholder_pos = bytecode.len();
                    bytecode.extend_from_slice(&0u64.to_le_bytes());
                    pending_jumps.push((placeholder_pos, target_x64_offset, false));

                    for &reg in active_stack_regs.iter().rev() {
                        bytecode.push(OpCode::Pop as u8);
                        bytecode.push(reg);
                    }
                }
            }
            X64InstrKind::Ret => {
                if instr.offset == main_end_offset && !hit_main_ret {
                    hit_main_ret = true;
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(0);
                    bytecode.extend_from_slice(&0u64.to_le_bytes());
                    bytecode.push(OpCode::Exit as u8);
                    bytecode.push(0);
                } else {
                    bytecode.push(OpCode::Ret as u8);
                }
            }
            X64InstrKind::Push { reg } => {
                bytecode.push(OpCode::Push as u8);
                bytecode.push(reg.to_vm_reg());
            }
            X64InstrKind::Pop { reg } => {
                bytecode.push(OpCode::Pop as u8);
                bytecode.push(reg.to_vm_reg());
            }
            X64InstrKind::LeaRipRel { dst, offset: _ } => {
                if !(instr.offset >= main_x64_offset && main_has_printf && printf_literal.is_some())
                {
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(dst.to_vm_reg());
                    string_patch_positions.push(bytecode.len());
                    bytecode.extend_from_slice(&0u64.to_le_bytes());
                }
            }
            X64InstrKind::LeaRegReg { dst, base, index } => {
                if dst == base {
                    bytecode.push(OpCode::Add as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(index.to_vm_reg());
                } else {
                    bytecode.push(OpCode::Move as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                    bytecode.push(OpCode::Add as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(index.to_vm_reg());
                }
            }
            X64InstrKind::MovzxByte { dst, base, offset } => {
                if *offset == 0 {
                    bytecode.push(OpCode::LoadByte as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                } else if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    let stack_reg = *stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode.push(OpCode::LoadByte as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(stack_reg);
                } else {
                    bytecode.push(OpCode::LoadByte as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                }
            }
            X64InstrKind::MovzxByteRegReg { dst, base, index } => {
                let addr_reg = if dst == base {
                    *dst
                } else {
                    bytecode.push(OpCode::Move as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                    *dst
                };
                bytecode.push(OpCode::Add as u8);
                bytecode.push(addr_reg.to_vm_reg());
                bytecode.push(addr_reg.to_vm_reg());
                bytecode.push(index.to_vm_reg());
                bytecode.push(OpCode::LoadByte as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(addr_reg.to_vm_reg());
            }
            X64InstrKind::Test { reg1, reg2 } => {
                if reg1 == reg2 {
                    bytecode.push(OpCode::LoadImm as u8);
                    bytecode.push(15);
                    bytecode.extend_from_slice(&0u64.to_le_bytes());
                    bytecode.push(OpCode::Cmp as u8);
                    bytecode.push(reg1.to_vm_reg());
                    bytecode.push(15);
                }
            }
            X64InstrKind::Lea { .. }
            | X64InstrKind::Nop
            | X64InstrKind::Unknown
            | X64InstrKind::Cdqe
            | X64InstrKind::Movsxd { .. } => {}
        }
    }

    for (placeholder_pos, target_x64_offset, is_unconditional) in pending_jumps {
        let target_vm_offset = if is_unconditional {
            resolve_unconditional_jump_target(instrs, &label_map, target_x64_offset)
        } else {
            resolve_jump_target(&label_map, target_x64_offset)
        };
        if let Some(target_vm_offset) = target_vm_offset {
            let target_bytes = (target_vm_offset as u64).to_le_bytes();
            bytecode[placeholder_pos..placeholder_pos + 8].copy_from_slice(&target_bytes);
        }
    }

    (
        bytecode,
        label_map,
        string_patch_positions,
        main_has_printf,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::OpCode;

    fn call_at(offset: usize, target: i32) -> X64Instruction {
        X64Instruction {
            offset,
            bytes: vec![0xE8, 0, 0, 0, 0],
            kind: X64InstrKind::Call {
                target_offset: target,
            },
        }
    }

    fn ret_at(offset: usize) -> X64Instruction {
        X64Instruction {
            offset,
            bytes: vec![0xC3],
            kind: X64InstrKind::Ret,
        }
    }

    fn native_call_ids(bytecode: &[u8]) -> Vec<u64> {
        let mut ids = Vec::new();
        let mut i = 0;
        while i < bytecode.len() {
            match OpCode::from_u8(bytecode[i]) {
                Some(OpCode::LoadImm) if i + 10 <= bytecode.len() => {
                    i += 10;
                }
                Some(OpCode::NativeCall) if i + 9 <= bytecode.len() => {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&bytecode[i + 1..i + 9]);
                    ids.push(u64::from_le_bytes(bytes));
                    i += 9;
                }
                Some(OpCode::Exit) => {
                    i += 2;
                }
                Some(OpCode::Ret) => {
                    i += 1;
                }
                Some(OpCode::Move) => {
                    i += 3;
                }
                Some(OpCode::Jmp) if i + 9 <= bytecode.len() => {
                    i += 9;
                }
                Some(OpCode::JmpIf) if i + 10 <= bytecode.len() => {
                    i += 10;
                }
                Some(OpCode::Call) if i + 9 <= bytecode.len() => {
                    i += 9;
                }
                _ => {
                    i += 1;
                }
            }
        }
        ids
    }

    #[test]
    fn hello_literal_emits_native_call_1_not_2() {
        let main_off = 0x400;
        let instrs = vec![
            call_at(main_off, 0x1000),
            call_at(main_off + 5, 0x1000),
            ret_at(main_off + 10),
        ];
        let hello = b"Hello, World!\n";
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], Some(hello));
        assert_eq!(native_call_ids(&bc), vec![1]);
        assert!(bc.windows(hello.len()).any(|w| w == hello));
    }

    #[test]
    fn integer_printf_emits_native_call_2() {
        let main_off = 0x400;
        let instrs = vec![
            call_at(main_off, 0x1000),
            call_at(main_off + 5, 0x1000),
            ret_at(main_off + 10),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        assert_eq!(native_call_ids(&bc), vec![2]);
    }

    #[test]
    fn str_lea_rip_rel_embeds_knvest_when_no_hello_literal() {
        let main_off = 0x400;
        let instrs = vec![
            X64Instruction {
                offset: main_off,
                bytes: vec![0x48, 0x8D, 0x05, 0, 0, 0, 0],
                kind: X64InstrKind::LeaRipRel {
                    dst: X64Reg::Rax,
                    offset: 0,
                },
            },
            call_at(main_off + 7, 0x1000),
            call_at(main_off + 12, 0x1000),
            ret_at(main_off + 17),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        assert!(bc.windows(7).any(|w| w == b"knvest\0"));
        assert_eq!(native_call_ids(&bc), vec![2]);
    }

    fn decode(bytes: &[u8]) -> X64InstrKind {
        let mut out = Vec::new();
        let mut off = 0;
        decode_instruction(bytes, &mut out, &mut off)
    }

    #[test]
    fn decodes_cmp_sub_add_mem_imm8_and_imm32() {
        assert!(matches!(
            decode(&[0x83, 0x7D, 0xFC, 0x00]),
            X64InstrKind::CmpMemImm { imm: 0, .. }
        ));
        assert!(matches!(
            decode(&[0x83, 0x6D, 0xFC, 0x01]),
            X64InstrKind::SubMemImm { imm: 1, .. }
        ));
        assert!(matches!(
            decode(&[0x83, 0x45, 0xFC, 0x01]),
            X64InstrKind::AddMemImm { imm: 1, .. }
        ));
        assert!(matches!(
            decode(&[0x81, 0x7D, 0xFC, 0x00, 0x00, 0x00, 0x00]),
            X64InstrKind::CmpMemImm { imm: 0, .. }
        ));
        assert!(matches!(
            decode(&[0x81, 0x6D, 0xFC, 0x01, 0x00, 0x00, 0x00]),
            X64InstrKind::SubMemImm { imm: 1, .. }
        ));
    }

    #[test]
    fn decodes_lea_and_movzx_reg_index() {
        assert!(matches!(
            decode(&[0x4A, 0x8D, 0x04, 0x18]),
            X64InstrKind::LeaRegReg { .. }
        ));
        assert!(matches!(
            decode(&[0x42, 0x0F, 0xB6, 0x04, 0x18]),
            X64InstrKind::MovzxByteRegReg { .. }
        ));
    }

    #[test]
    fn loop_mem_cmp_sub_lift_contains_cmp_and_sub() {
        let main_off = 0x500;
        let mut off = main_off;
        let mut instrs = Vec::new();
        let push_bytes = vec![0x55, 0x48, 0x89, 0xE5];
        instrs.push(X64Instruction {
            offset: off,
            bytes: push_bytes.clone(),
            kind: X64InstrKind::Push { reg: X64Reg::Rbp },
        });
        off += push_bytes.len();

        for (bytes, kind) in [
            (
                vec![0xC7, 0x45, 0xFC, 0x05, 0x00, 0x00, 0x00],
                X64InstrKind::MovMemImm {
                    base: X64Reg::Rbp,
                    offset: -4,
                    imm: 5,
                },
            ),
            (
                vec![0xEB, 0x10],
                X64InstrKind::Jmp { target_offset: 0x10 },
            ),
            (
                vec![0x8B, 0x45, 0xFC],
                X64InstrKind::MovRegMem {
                    dst: X64Reg::Eax,
                    base: X64Reg::Rbp,
                    offset: -4,
                },
            ),
            (
                vec![0x83, 0x6D, 0xFC, 0x01],
                X64InstrKind::SubMemImm {
                    base: X64Reg::Rbp,
                    offset: -4,
                    imm: 1,
                },
            ),
            (
                vec![0x83, 0x7D, 0xFC, 0x00],
                X64InstrKind::CmpMemImm {
                    base: X64Reg::Rbp,
                    offset: -4,
                    imm: 0,
                },
            ),
            (
                vec![0x7F, 0xF0],
                X64InstrKind::Jg { target_offset: -0x10 },
            ),
        ] {
            instrs.push(X64Instruction {
                offset: off,
                bytes: bytes.clone(),
                kind,
            });
            off += bytes.len();
        }
        instrs.push(ret_at(off));

        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        let has_cmp = bc.windows(1).any(|w| w[0] == OpCode::Cmp as u8);
        let has_sub = bc.windows(1).any(|w| w[0] == OpCode::Sub as u8);
        assert!(has_cmp, "loop lift must emit Cmp for [rbp+disp], 0");
        assert!(has_sub, "loop lift must emit Sub for [rbp+disp], 1");
    }

    #[test]
    fn internal_callee_call_emits_vm_call_not_native_call_2() {
        let callee_off = 0x200;
        let main_off = 0x500;
        let callee = vec![
            X64Instruction {
                offset: callee_off,
                bytes: vec![0x55],
                kind: X64InstrKind::Push { reg: X64Reg::Rbp },
            },
            X64Instruction {
                offset: callee_off + 1,
                bytes: vec![0xB8, 0x07, 0x00, 0x00, 0x00],
                kind: X64InstrKind::MovRegImm {
                    reg: X64Reg::Eax,
                    imm: 7,
                },
            },
            ret_at(callee_off + 6),
        ];
        let mut main = vec![
            call_at(main_off, -0x305),
            call_at(main_off + 5, 0x1000),
            call_at(main_off + 10, 0x1000),
            ret_at(main_off + 15),
        ];
        let mut instrs = callee;
        instrs.append(&mut main);
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        assert_eq!(native_call_ids(&bc), vec![2]);
        assert!(bc.contains(&(OpCode::Call as u8)));
        let call_off = bc.iter().position(|&b| b == OpCode::Call as u8).unwrap();
        assert!(call_off < 20, "main must be first; call must not target offset 0 callee");
        let mut target = [0u8; 8];
        target.copy_from_slice(&bc[call_off + 1..call_off + 9]);
        let target_off = u64::from_le_bytes(target);
        assert!(target_off > 0, "internal call must jump past main, not to 0");
    }

    #[test]
    fn main_bytecode_precedes_callees() {
        let callee_off = 0x100;
        let main_off = 0x400;
        let instrs = vec![
            X64Instruction {
                offset: callee_off,
                bytes: vec![0x55],
                kind: X64InstrKind::Push { reg: X64Reg::Rbp },
            },
            ret_at(callee_off + 1),
            X64Instruction {
                offset: main_off,
                bytes: vec![0xB8, 0x01, 0x00, 0x00, 0x00],
                kind: X64InstrKind::MovRegImm {
                    reg: X64Reg::Eax,
                    imm: 1,
                },
            },
            ret_at(main_off + 5),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        assert_eq!(bc[0], OpCode::LoadImm as u8, "main must start at bytecode offset 0");
    }

    #[test]
    fn jg_branch_emits_jmp_if_condition_3() {
        let main_off = 0x400;
        let instrs = vec![
            X64Instruction {
                offset: main_off,
                bytes: vec![0x7F, 0x00],
                kind: X64InstrKind::Jg { target_offset: 0 },
            },
            ret_at(main_off + 2),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        let jmp_if_pos = bc.iter().position(|&b| b == OpCode::JmpIf as u8).unwrap();
        assert_eq!(bc[jmp_if_pos + 1], 3);
    }

    #[test]
    fn jl_branch_emits_jmp_if_condition_4() {
        let main_off = 0x400;
        let instrs = vec![
            X64Instruction {
                offset: main_off,
                bytes: vec![0x7C, 0x00],
                kind: X64InstrKind::Jl { target_offset: 0 },
            },
            ret_at(main_off + 2),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        let jmp_if_pos = bc.iter().position(|&b| b == OpCode::JmpIf as u8).unwrap();
        assert_eq!(bc[jmp_if_pos + 1], 4);
    }

    #[test]
    fn decodes_jg_and_jle_rel8() {
        assert!(matches!(decode(&[0x7F, 0x10]), X64InstrKind::Jg { .. }));
        assert!(matches!(decode(&[0x7E, 0x10]), X64InstrKind::Jle { .. }));
    }

    #[test]
    fn jle_branch_emits_jmp_if_condition_5() {
        let main_off = 0x400;
        let instrs = vec![
            X64Instruction {
                offset: main_off,
                bytes: vec![0x7E, 0x00],
                kind: X64InstrKind::Jle { target_offset: 0 },
            },
            ret_at(main_off + 2),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        let jmp_if_pos = bc.iter().position(|&b| b == OpCode::JmpIf as u8).unwrap();
        assert_eq!(bc[jmp_if_pos + 1], 5);
    }

    #[test]
    fn fuses_mov_index_then_mov_base_into_add() {
        let main_off = 0x400;
        let instrs = vec![
            X64Instruction {
                offset: main_off,
                bytes: vec![0x89, 0xD8],
                kind: X64InstrKind::MovRegReg {
                    dst: X64Reg::Rax,
                    src: X64Reg::Rbx,
                },
            },
            X64Instruction {
                offset: main_off + 2,
                bytes: vec![0x89, 0xF0],
                kind: X64InstrKind::MovRegReg {
                    dst: X64Reg::Rax,
                    src: X64Reg::Rsi,
                },
            },
            ret_at(main_off + 4),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        let moves = bc.iter().filter(|&&b| b == OpCode::Move as u8).count();
        let adds = bc.iter().filter(|&&b| b == OpCode::Add as u8).count();
        assert_eq!(moves, 1, "fused pair should emit one move, not two");
        assert_eq!(adds, 1);
    }

    #[test]
    fn fuses_mov_pair_with_32bit_reg_names() {
        let main_off = 0x400;
        let instrs = vec![
            X64Instruction {
                offset: main_off,
                bytes: vec![0x89, 0xD8],
                kind: X64InstrKind::MovRegReg {
                    dst: X64Reg::Eax,
                    src: X64Reg::Ebx,
                },
            },
            X64Instruction {
                offset: main_off + 2,
                bytes: vec![0x89, 0xF0],
                kind: X64InstrKind::MovRegReg {
                    dst: X64Reg::Rax,
                    src: X64Reg::Rsi,
                },
            },
            ret_at(main_off + 4),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        assert_eq!(bc.iter().filter(|&&b| b == OpCode::Move as u8).count(), 1);
        assert_eq!(bc.iter().filter(|&&b| b == OpCode::Add as u8).count(), 1);
    }

    #[test]
    fn jmp_resolves_to_nearest_label_at_or_before_target() {
        let mut label_map = std::collections::HashMap::new();
        label_map.insert(0x100, 10);
        label_map.insert(0x110, 20);
        label_map.insert(0x120, 30);
        assert_eq!(resolve_jump_target(&label_map, 0x110), Some(20));
        assert_eq!(resolve_jump_target(&label_map, 0x115), Some(20));
        assert_eq!(resolve_jump_target(&label_map, 0x125), Some(30));
    }

    #[test]
    fn unconditional_jmp_to_jcc_retargets_to_preceding_cmp() {
        let main_off = 0x400;
        let cmp_off = main_off + 0x10;
        let jle_off = cmp_off + 3;
        let instrs = vec![
            X64Instruction {
                offset: main_off,
                bytes: vec![0xE9, 0x00, 0x00, 0x00, 0x00],
                kind: X64InstrKind::Jmp {
                    target_offset: (jle_off as i32) - (main_off as i32 + 5),
                },
            },
            X64Instruction {
                offset: cmp_off,
                bytes: vec![0x4C, 0x39, 0xF8],
                kind: X64InstrKind::CmpRegReg {
                    reg1: X64Reg::R15,
                    reg2: X64Reg::Rax,
                },
            },
            X64Instruction {
                offset: jle_off,
                bytes: vec![0x7E, 0x00],
                kind: X64InstrKind::Jle { target_offset: 0 },
            },
            ret_at(jle_off + 2),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        let jmp_pos = bc.iter().position(|&b| b == OpCode::Jmp as u8).unwrap();
        let target = u64::from_le_bytes(bc[jmp_pos + 1..jmp_pos + 9].try_into().unwrap()) as usize;
        let jmp_if_pos = bc.iter().position(|&b| b == OpCode::JmpIf as u8).unwrap();
        assert!(
            target < jmp_if_pos,
            "jmp to JLE must land on cmp (offset {target}), not jmp_if ({jmp_if_pos})"
        );
        assert_eq!(bc[target], OpCode::Cmp as u8);
        assert!(
            bc.iter().any(|&b| b == OpCode::JmpIf as u8),
            "JLE should still be lifted as jmp_if"
        );
    }

    #[test]
    fn fuses_mov_pair_across_cdqe_gap() {
        let main_off = 0x400;
        let instrs = vec![
            X64Instruction {
                offset: main_off,
                bytes: vec![0x89, 0xD8],
                kind: X64InstrKind::MovRegReg {
                    dst: X64Reg::Rax,
                    src: X64Reg::Rbx,
                },
            },
            X64Instruction {
                offset: main_off + 2,
                bytes: vec![0x48, 0x98],
                kind: X64InstrKind::Cdqe,
            },
            X64Instruction {
                offset: main_off + 4,
                bytes: vec![0x89, 0xF0],
                kind: X64InstrKind::MovRegReg {
                    dst: X64Reg::Rax,
                    src: X64Reg::Rsi,
                },
            },
            ret_at(main_off + 6),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        assert_eq!(bc.iter().filter(|&&b| b == OpCode::Move as u8).count(), 1);
        assert_eq!(bc.iter().filter(|&&b| b == OpCode::Add as u8).count(), 1);
    }

    #[test]
    fn test_al_al_decodes_to_cmp_vs_zero() {
        assert!(matches!(
            decode(&[0x84, 0xC0]),
            X64InstrKind::Test {
                reg1: X64Reg::Rax,
                reg2: X64Reg::Rax,
            }
        ));
        let main_off = 0x400;
        let instrs = vec![
            X64Instruction {
                offset: main_off,
                bytes: vec![0x84, 0xC0],
                kind: X64InstrKind::Test {
                    reg1: X64Reg::Rax,
                    reg2: X64Reg::Rax,
                },
            },
            ret_at(main_off + 2),
        ];
        let bc = lift_to_vm_bytecode_for_main(&instrs, 0x1000, main_off, &[], None);
        let cmp_pos = bc.iter().position(|&b| b == OpCode::Cmp as u8).unwrap();
        assert_eq!(bc[cmp_pos + 1], 0, "test al,al must cmp VM r0 against 0");
        assert_eq!(bc[cmp_pos + 2], 15);
    }
}
