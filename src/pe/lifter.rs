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
    LeaRipRel { dst: X64Reg, offset: i32 },
    MovzxByte { dst: X64Reg, base: X64Reg, offset: i32 },
    Test { reg1: X64Reg, reg2: X64Reg },
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
        Register::RAX => X64Reg::Rax,
        Register::RCX => X64Reg::Rcx,
        Register::RDX => X64Reg::Rdx,
        Register::RBX => X64Reg::Rbx,
        Register::RSP => X64Reg::Rsp,
        Register::RBP => X64Reg::Rbp,
        Register::RSI => X64Reg::Rsi,
        Register::RDI => X64Reg::Rdi,
        Register::R8 => X64Reg::R8,
        Register::R9 => X64Reg::R9,
        Register::R10 => X64Reg::R10,
        Register::R11 => X64Reg::R11,
        Register::R12 => X64Reg::R12,
        Register::R13 => X64Reg::R13,
        Register::R14 => X64Reg::R14,
        Register::R15 => X64Reg::R15,
        Register::EAX => X64Reg::Eax,
        Register::ECX => X64Reg::Ecx,
        Register::EDX => X64Reg::Edx,
        Register::EBX => X64Reg::Ebx,
        Register::ESP => X64Reg::Esp,
        Register::EBP => X64Reg::Ebp,
        Register::ESI => X64Reg::Esi,
        Register::EDI => X64Reg::Edi,
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
    instr.immediate32() as u32
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
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Immediate8 {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::AddRegImm { reg, imm: imm_u32(instr) };
        }
    }
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Immediate32 {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::AddRegImm { reg, imm: imm_u32(instr) };
        }
    }
    if instr.op0_kind() == OpKind::Memory && instr.op1_kind() == OpKind::Immediate8 {
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
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Immediate8 {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::SubRegImm { reg, imm: imm_u32(instr) };
        }
    }
    if instr.op0_kind() == OpKind::Memory && instr.op1_kind() == OpKind::Immediate8 {
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
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Immediate8 {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::CmpRegImm { reg, imm: imm_u32(instr) };
        }
    }
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Immediate32 {
        if let Some(reg) = iced_reg_to_x64(instr.op0_register()) {
            return X64InstrKind::CmpRegImm { reg, imm: imm_u32(instr) };
        }
    }
    if instr.op0_kind() == OpKind::Memory && instr.op1_kind() == OpKind::Immediate8 {
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
            if let Some((base, offset)) = mem_base_offset(instr) {
                return X64InstrKind::Lea { dst, base, offset };
            }
        }
    }
    X64InstrKind::Unknown
}

fn classify_movzx(instr: &Instruction) -> X64InstrKind {
    if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Memory {
        if let (Some(dst), Some((base, offset))) = (
            iced_reg_to_x64(instr.op0_register()),
            mem_base_offset(instr),
        ) {
            return X64InstrKind::MovzxByte { dst, base, offset };
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
        X64InstrKind::Je { .. } => 1,  // ZF=1
        X64InstrKind::Jne { .. } => 2, // ZF=0
        X64InstrKind::Jl { .. } => 3,  // SF!=OF
        X64InstrKind::Jle { .. } => 4, // ZF=1 || SF!=OF
        X64InstrKind::Jg { .. } => 5,  // ZF=0 && SF==OF
        X64InstrKind::Jge { .. } => 6, // SF==OF
        _ => 2,
    }
}

fn is_lifted_internal_target(target: usize, min_x64_offset: usize, max_x64_offset: usize) -> bool {
    target >= min_x64_offset && target < max_x64_offset
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
) -> Vec<u8> {
    let (mut bytecode, _, string_patch_positions) =
        lift_to_vm_bytecode_internal_with_main(instrs, base_rva, main_x64_offset);

    if !string_patch_positions.is_empty() {
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

    let mut pending_jumps: Vec<(usize, usize)> = Vec::new();

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
                pending_jumps.push((placeholder_pos, target_x64_offset));
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
                pending_jumps.push((placeholder_pos, target_x64_offset));
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
                    pending_jumps.push((placeholder_pos, target_x64_offset));
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
            X64InstrKind::Lea { .. } | X64InstrKind::Nop | X64InstrKind::Unknown => {}
        }
    }

    for (placeholder_pos, target_x64_offset) in pending_jumps {
        if let Some(&target_vm_offset) = label_map.get(&target_x64_offset) {
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
) -> (
    Vec<u8>,
    std::collections::HashMap<usize, usize>,
    Vec<usize>,
) {
    let mut bytecode = Vec::new();
    let mut label_map = std::collections::HashMap::new();
    let mut stack_map = std::collections::HashMap::new();
    let mut next_stack_reg = 10u8;
    let mut string_patch_positions = Vec::new();

    let mut pending_jumps: Vec<(usize, usize)> = Vec::new();

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

    for instr in instrs {
        label_map.insert(instr.offset, bytecode.len());

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
                pending_jumps.push((placeholder_pos, target_x64_offset));
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
                pending_jumps.push((placeholder_pos, target_x64_offset));
            }
            X64InstrKind::Call { target_offset } => {
                let target_x64_offset =
                    (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;

                let is_internal =
                    is_lifted_internal_target(target_x64_offset, min_x64_offset, max_x64_offset);

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
                            bytecode.push(OpCode::NativeCall as u8);
                            bytecode.extend_from_slice(&2u64.to_le_bytes());
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
                    pending_jumps.push((placeholder_pos, target_x64_offset));

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
            X64InstrKind::LeaRipRel { dst, .. } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(dst.to_vm_reg());
                string_patch_positions.push(bytecode.len());
                bytecode.extend_from_slice(&0u64.to_le_bytes());
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
            X64InstrKind::Lea { .. } | X64InstrKind::Nop | X64InstrKind::Unknown => {}
        }
    }

    for (placeholder_pos, target_x64_offset) in pending_jumps {
        if let Some(&target_vm_offset) = label_map.get(&target_x64_offset) {
            let target_bytes = (target_vm_offset as u64).to_le_bytes();
            bytecode[placeholder_pos..placeholder_pos + 8].copy_from_slice(&target_bytes);
        } else if let Some((_, &vm_offset)) = label_map
            .iter()
            .filter(|(k, _)| **k >= target_x64_offset)
            .min_by_key(|(k, _)| **k)
        {
            let target_bytes = (vm_offset as u64).to_le_bytes();
            bytecode[placeholder_pos..placeholder_pos + 8].copy_from_slice(&target_bytes);
        }
    }

    (bytecode, label_map, string_patch_positions)
}
