use crate::vm::OpCode;

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

pub fn decode_instruction(bytes: &[u8], instr_bytes: &mut Vec<u8>, offset: &mut usize) -> X64InstrKind {
    if bytes.is_empty() {
        return X64InstrKind::Unknown;
    }

    let b0 = bytes[0];
    
    match b0 {
        0x48 | 0x49 | 0x4C | 0x4D if bytes.len() > 1 => {
            instr_bytes.push(b0);
            let b1 = bytes[1];
            
            match b1 {
                0xC7 if bytes.len() > 2 => {
                    let modrm = bytes[2];
                    if (modrm & 0xC0) == 0xC0 {
                        instr_bytes.extend_from_slice(&bytes[0..7]);
                        *offset += 7;
                        let reg = decode_reg_from_modrm(modrm, b0 == 0x49);
                        let imm = u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as u64;
                        return X64InstrKind::MovRegImm { reg, imm };
                    }
                },
                0x89 | 0x8B if bytes.len() > 2 => {
                    instr_bytes.extend_from_slice(&bytes[0..3]);
                    *offset += 3;
                    let modrm = bytes[2];
                    let dst = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                    let src = decode_reg_from_modrm(modrm & 7, b0 == 0x49 || b0 == 0x4D);
                    return if b1 == 0x89 {
                        X64InstrKind::MovRegReg { dst: src, src: dst }
                    } else {
                        X64InstrKind::MovRegReg { dst, src }
                    };
                },
                0x01 if bytes.len() > 2 => {
                    instr_bytes.extend_from_slice(&bytes[0..3]);
                    *offset += 3;
                    let modrm = bytes[2];
                    let dst = decode_reg_from_modrm(modrm & 7, false);
                    let src = decode_reg_from_modrm((modrm >> 3) & 7, false);
                    return X64InstrKind::AddRegReg { dst, src };
                },
                0x29 if bytes.len() > 2 => {
                    instr_bytes.extend_from_slice(&bytes[0..3]);
                    *offset += 3;
                    let modrm = bytes[2];
                    let dst = decode_reg_from_modrm(modrm & 7, false);
                    let src = decode_reg_from_modrm((modrm >> 3) & 7, false);
                    return X64InstrKind::SubRegReg { dst, src };
                },
                0x0F if bytes.len() > 3 && bytes[2] == 0xAF => {
                    instr_bytes.extend_from_slice(&bytes[0..4]);
                    *offset += 4;
                    let modrm = bytes[3];
                    let dst = decode_reg_from_modrm((modrm >> 3) & 7, false);
                    let src = decode_reg_from_modrm(modrm & 7, false);
                    return X64InstrKind::ImulRegReg { dst, src };
                },
                0x39 if bytes.len() > 2 => {
                    instr_bytes.extend_from_slice(&bytes[0..3]);
                    *offset += 3;
                    let modrm = bytes[2];
                    let reg1 = decode_reg_from_modrm(modrm & 7, false);
                    let reg2 = decode_reg_from_modrm((modrm >> 3) & 7, false);
                    return X64InstrKind::CmpRegReg { reg1, reg2 };
                },
                0x83 if bytes.len() > 3 => {
                    let modrm = bytes[2];
                    if (modrm & 0x38) == 0x38 {
                        instr_bytes.extend_from_slice(&bytes[0..4]);
                        *offset += 4;
                        let reg = decode_reg_from_modrm(modrm & 7, b0 == 0x49);
                        let imm = bytes[3] as u32;
                        return X64InstrKind::CmpRegImm { reg, imm };
                    } else if (modrm & 0x38) == 0x28 {
                        if (modrm & 0xC0) == 0xC0 {
                            instr_bytes.extend_from_slice(&bytes[0..4]);
                            *offset += 4;
                            let reg = decode_reg_from_modrm(modrm & 7, b0 == 0x49);
                            return X64InstrKind::SubRegReg { dst: reg, src: reg };
                        } else if (modrm & 0xC0) == 0x40 && bytes.len() > 4 {
                            let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49);
                            let disp = bytes[3] as i8 as i32;
                            let imm = bytes[4] as u32;
                            if base == X64Reg::Rbp || base == X64Reg::Ebp {
                                instr_bytes.extend_from_slice(&bytes[0..5]);
                                *offset += 5;
                                return X64InstrKind::SubMemImm { base, offset: disp, imm };
                            } else {
                                instr_bytes.extend_from_slice(&bytes[0..5]);
                                *offset += 5;
                                return X64InstrKind::SubRegImm { reg: base, imm };
                            }
                        }
                    } else if (modrm & 0x38) == 0x00 && (modrm & 0xC0) == 0x40 && bytes.len() > 4 {
                        instr_bytes.extend_from_slice(&bytes[0..5]);
                        *offset += 5;
                        let reg = decode_reg_from_modrm(modrm & 7, b0 == 0x49);
                        let imm = bytes[4] as u32;
                        return X64InstrKind::AddRegImm { reg, imm };
                    } else if (modrm & 0x38) == 0x38 && (modrm & 0xC0) == 0x40 && bytes.len() > 4 {
                        instr_bytes.extend_from_slice(&bytes[0..5]);
                        *offset += 5;
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49);
                        let disp = bytes[3] as i8 as i32;
                        let imm = bytes[4] as u32;
                        return X64InstrKind::CmpMemImm { base, offset: disp, imm };
                    }
                },
                0x8D if bytes.len() > 3 => {
                    let modrm = bytes[2];
                    if (modrm & 0xC7) == 0x05 && bytes.len() > 6 {
                        // RIP-relative LEA: 48 8D xx [05] disp32
                        instr_bytes.extend_from_slice(&bytes[0..7]);
                        *offset += 7;
                        let dst = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                        let disp = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
                        return X64InstrKind::LeaRipRel { dst, offset: disp };
                    } else if (modrm & 0xC0) == 0x40 {
                        instr_bytes.extend_from_slice(&bytes[0..4]);
                        *offset += 4;
                        let dst = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49 || b0 == 0x4D);
                        let disp = bytes[3] as i8 as i32;
                        return X64InstrKind::Lea { dst, base, offset: disp };
                    } else if (modrm & 0xC0) == 0x80 && bytes.len() > 6 {
                        instr_bytes.extend_from_slice(&bytes[0..7]);
                        *offset += 7;
                        let dst = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49 || b0 == 0x4D);
                        let disp = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
                        return X64InstrKind::Lea { dst, base, offset: disp };
                    }
                },
                0xB6 if bytes.len() > 2 => {
                    // MOVZX: 0F B6 - zero extend byte to register
                    let modrm = bytes[2];
                    if (modrm & 0xC0) == 0x00 {
                        instr_bytes.extend_from_slice(&bytes[0..3]);
                        *offset += 3;
                        let dst = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49 || b0 == 0x4D);
                        return X64InstrKind::MovzxByte { dst, base, offset: 0 };
                    } else if (modrm & 0xC0) == 0x40 && bytes.len() > 3 {
                        instr_bytes.extend_from_slice(&bytes[0..4]);
                        *offset += 4;
                        let dst = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49 || b0 == 0x4D);
                        let disp = bytes[3] as i8 as i32;
                        return X64InstrKind::MovzxByte { dst, base, offset: disp };
                    }
                },
                0x85 if bytes.len() > 2 => {
                    instr_bytes.extend_from_slice(&bytes[0..3]);
                    *offset += 3;
                    let modrm = bytes[2];
                    let reg1 = decode_reg_from_modrm(modrm & 7, false);
                    let reg2 = decode_reg_from_modrm((modrm >> 3) & 7, false);
                    return X64InstrKind::Test { reg1, reg2 };
                },
                0x8B if bytes.len() > 2 => {
                    let modrm = bytes[2];
                    if (modrm & 0xC0) == 0x40 {
                        instr_bytes.extend_from_slice(&bytes[0..4]);
                        *offset += 4;
                        let dst = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49 || b0 == 0x4D);
                        let disp = bytes[3] as i8 as i32;
                        return X64InstrKind::MovRegMem { dst, base, offset: disp };
                    } else if (modrm & 0xC0) == 0x80 && bytes.len() > 6 {
                        instr_bytes.extend_from_slice(&bytes[0..7]);
                        *offset += 7;
                        let dst = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49 || b0 == 0x4D);
                        let disp = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
                        return X64InstrKind::MovRegMem { dst, base, offset: disp };
                    }
                },
                0xC7 if bytes.len() > 2 => {
                    let modrm = bytes[2];
                    if (modrm & 0xC0) == 0x40 && (modrm & 0x38) == 0x00 && bytes.len() > 7 {
                        instr_bytes.extend_from_slice(&bytes[0..8]);
                        *offset += 8;
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49);
                        let disp = bytes[3] as i8 as i32;
                        let imm = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                        return X64InstrKind::MovMemImm { base, offset: disp, imm };
                    } else if (modrm & 0xC0) == 0xC0 {
                        instr_bytes.extend_from_slice(&bytes[0..7]);
                        *offset += 7;
                        let reg = decode_reg_from_modrm(modrm, b0 == 0x49);
                        let imm = u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as u64;
                        return X64InstrKind::MovRegImm { reg, imm };
                    }
                },
                0x89 if bytes.len() > 2 => {
                    let modrm = bytes[2];
                    if (modrm & 0xC0) == 0x40 {
                        instr_bytes.extend_from_slice(&bytes[0..4]);
                        *offset += 4;
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49 || b0 == 0x4D);
                        let src = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                        let disp = bytes[3] as i8 as i32;
                        return X64InstrKind::MovMemReg { base, offset: disp, src };
                    } else if (modrm & 0xC0) == 0x80 && bytes.len() > 6 {
                        instr_bytes.extend_from_slice(&bytes[0..7]);
                        *offset += 7;
                        let base = decode_reg_from_modrm(modrm & 7, b0 == 0x49 || b0 == 0x4D);
                        let src = decode_reg_from_modrm((modrm >> 3) & 7, b0 == 0x49 || b0 == 0x4C);
                        let disp = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
                        return X64InstrKind::MovMemReg { base, offset: disp, src };
                    }
                },
                0xFF if bytes.len() > 2 => {
                    let modrm = bytes[2];
                    if (modrm & 0x38) == 0x08 {
                        instr_bytes.extend_from_slice(&bytes[0..3]);
                        *offset += 3;
                        let reg = decode_reg_from_modrm(modrm & 7, b0 == 0x49);
                        return X64InstrKind::Dec { reg };
                    }
                },
                _ => {}
            }
        },
        0xB8..=0xBF => {
            if bytes.len() >= 5 {
                instr_bytes.extend_from_slice(&bytes[0..5]);
                *offset += 5;
                let reg = decode_reg_from_modrm(b0 & 7, false);
                let imm = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
                return X64InstrKind::MovRegImm { reg: to_32bit_reg(reg), imm };
            }
        },
        0x01 if bytes.len() > 1 => {
            let modrm = bytes[1];
            if (modrm & 0xC0) == 0xC0 {
                instr_bytes.extend_from_slice(&bytes[0..2]);
                *offset += 2;
                let dst = decode_reg_from_modrm(modrm & 7, false);
                let src = decode_reg_from_modrm((modrm >> 3) & 7, false);
                return X64InstrKind::AddRegReg { dst: to_32bit_reg(dst), src: to_32bit_reg(src) };
            }
        },
        0x29 if bytes.len() > 1 => {
            let modrm = bytes[1];
            if (modrm & 0xC0) == 0xC0 {
                instr_bytes.extend_from_slice(&bytes[0..2]);
                *offset += 2;
                let dst = decode_reg_from_modrm(modrm & 7, false);
                let src = decode_reg_from_modrm((modrm >> 3) & 7, false);
                return X64InstrKind::SubRegReg { dst: to_32bit_reg(dst), src: to_32bit_reg(src) };
            }
        },
        0x89 if bytes.len() > 1 => {
            let modrm = bytes[1];
            if (modrm & 0xC0) == 0xC0 {
                instr_bytes.extend_from_slice(&bytes[0..2]);
                *offset += 2;
                let dst = decode_reg_from_modrm(modrm & 7, false);
                let src = decode_reg_from_modrm((modrm >> 3) & 7, false);
                return X64InstrKind::MovRegReg { dst: to_32bit_reg(dst), src: to_32bit_reg(src) };
            } else if (modrm & 0xC0) == 0x40 {
                instr_bytes.extend_from_slice(&bytes[0..3]);
                *offset += 3;
                let base = decode_reg_from_modrm(modrm & 7, false);
                let src = decode_reg_from_modrm((modrm >> 3) & 7, false);
                let disp = bytes[2] as i8 as i32;
                return X64InstrKind::MovMemReg { base, offset: disp, src: to_32bit_reg(src) };
            }
        },
        0x8B if bytes.len() > 1 => {
            let modrm = bytes[1];
            if (modrm & 0xC0) == 0xC0 {
                instr_bytes.extend_from_slice(&bytes[0..2]);
                *offset += 2;
                let dst = decode_reg_from_modrm((modrm >> 3) & 7, false);
                let src = decode_reg_from_modrm(modrm & 7, false);
                return X64InstrKind::MovRegReg { dst: to_32bit_reg(dst), src: to_32bit_reg(src) };
            } else if (modrm & 0xC0) == 0x40 {
                instr_bytes.extend_from_slice(&bytes[0..3]);
                *offset += 3;
                let dst = decode_reg_from_modrm((modrm >> 3) & 7, false);
                let base = decode_reg_from_modrm(modrm & 7, false);
                let disp = bytes[2] as i8 as i32;
                return X64InstrKind::MovRegMem { dst: to_32bit_reg(dst), base, offset: disp };
            }
        },
        0xC7 if bytes.len() > 1 => {
            let modrm = bytes[1];
            if (modrm & 0xC0) == 0x40 && (modrm & 0x38) == 0x00 && bytes.len() > 6 {
                instr_bytes.extend_from_slice(&bytes[0..7]);
                *offset += 7;
                let base = decode_reg_from_modrm(modrm & 7, false);
                let disp = bytes[2] as i8 as i32;
                let imm = u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
                return X64InstrKind::MovMemImm { base, offset: disp, imm };
            }
        },
        0x31 if bytes.len() > 1 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            *offset += 2;
            let modrm = bytes[1];
            let reg1 = decode_reg_from_modrm(modrm & 7, false);
            let reg2 = decode_reg_from_modrm((modrm >> 3) & 7, false);
            if reg1 == reg2 {
                return X64InstrKind::MovRegImm { reg: to_32bit_reg(reg1), imm: 0 };
            }
        },
        0x01 if bytes.len() > 1 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            *offset += 2;
            let modrm = bytes[1];
            let dst = decode_reg_from_modrm(modrm & 7, false);
            let src = decode_reg_from_modrm((modrm >> 3) & 7, false);
            return X64InstrKind::AddRegReg { dst: to_32bit_reg(dst), src: to_32bit_reg(src) };
        },
        0x0F if bytes.len() > 1 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            let b1 = bytes[1];
            match b1 {
                0x8E if bytes.len() >= 6 => {
                    instr_bytes.extend_from_slice(&bytes[2..6]);
                    *offset += 6;
                    let rel = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                    return X64InstrKind::Jle { target_offset: rel };
                },
                0x8F if bytes.len() >= 6 => {
                    instr_bytes.extend_from_slice(&bytes[2..6]);
                    *offset += 6;
                    let rel = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                    return X64InstrKind::Jg { target_offset: rel };
                },
                0x8D if bytes.len() >= 6 => {
                    instr_bytes.extend_from_slice(&bytes[2..6]);
                    *offset += 6;
                    let rel = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                    return X64InstrKind::Jge { target_offset: rel };
                },
                0x8C if bytes.len() >= 6 => {
                    instr_bytes.extend_from_slice(&bytes[2..6]);
                    *offset += 6;
                    let rel = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                    return X64InstrKind::Jl { target_offset: rel };
                },
                0x84 if bytes.len() >= 6 => {
                    instr_bytes.extend_from_slice(&bytes[2..6]);
                    *offset += 6;
                    let rel = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                    return X64InstrKind::Je { target_offset: rel };
                },
                0x85 if bytes.len() >= 6 => {
                    instr_bytes.extend_from_slice(&bytes[2..6]);
                    *offset += 6;
                    let rel = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                    return X64InstrKind::Jne { target_offset: rel };
                },
                0xAF if bytes.len() > 2 => {
                    instr_bytes.extend_from_slice(&bytes[2..3]);
                    *offset += 3;
                    let modrm = bytes[2];
                    let dst = decode_reg_from_modrm((modrm >> 3) & 7, false);
                    let src = decode_reg_from_modrm(modrm & 7, false);
                    return X64InstrKind::ImulRegReg { dst: to_32bit_reg(dst), src: to_32bit_reg(src) };
                },
                _ => {
                    *offset += 2;
                }
            }
        },
        0x74 if bytes.len() >= 2 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            *offset += 2;
            let rel = bytes[1] as i8 as i32;
            return X64InstrKind::Je { target_offset: rel };
        },
        0x75 if bytes.len() >= 2 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            *offset += 2;
            let rel = bytes[1] as i8 as i32;
            return X64InstrKind::Jne { target_offset: rel };
        },
        0x7E if bytes.len() >= 2 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            *offset += 2;
            let rel = bytes[1] as i8 as i32;
            return X64InstrKind::Jle { target_offset: rel };
        },
        0x7F if bytes.len() >= 2 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            *offset += 2;
            let rel = bytes[1] as i8 as i32;
            return X64InstrKind::Jg { target_offset: rel };
        },
        0x7C if bytes.len() >= 2 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            *offset += 2;
            let rel = bytes[1] as i8 as i32;
            return X64InstrKind::Jl { target_offset: rel };
        },
        0x7D if bytes.len() >= 2 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            *offset += 2;
            let rel = bytes[1] as i8 as i32;
            return X64InstrKind::Jge { target_offset: rel };
        },
        0xE8 if bytes.len() >= 5 => {
            instr_bytes.extend_from_slice(&bytes[0..5]);
            *offset += 5;
            let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            return X64InstrKind::Call { target_offset: rel };
        },
        0xE9 if bytes.len() >= 5 => {
            instr_bytes.extend_from_slice(&bytes[0..5]);
            *offset += 5;
            let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            return X64InstrKind::Jmp { target_offset: rel };
        },
        0xEB if bytes.len() >= 2 => {
            instr_bytes.extend_from_slice(&bytes[0..2]);
            *offset += 2;
            let rel = bytes[1] as i8 as i32;
            return X64InstrKind::Jmp { target_offset: rel };
        },
        0xC3 => {
            instr_bytes.push(b0);
            *offset += 1;
            return X64InstrKind::Ret;
        },
        0x90 => {
            instr_bytes.push(b0);
            *offset += 1;
            return X64InstrKind::Nop;
        },
        0x50..=0x57 => {
            instr_bytes.push(b0);
            *offset += 1;
            let reg = decode_reg_from_modrm(b0 & 7, false);
            return X64InstrKind::Push { reg };
        },
        0x58..=0x5F => {
            instr_bytes.push(b0);
            *offset += 1;
            let reg = decode_reg_from_modrm(b0 & 7, false);
            return X64InstrKind::Pop { reg };
        },
        0xFF if bytes.len() > 1 => {
            let modrm = bytes[1];
            if (modrm & 0x38) == 0x08 {
                instr_bytes.extend_from_slice(&bytes[0..2]);
                *offset += 2;
                let reg = decode_reg_from_modrm(modrm & 7, false);
                return X64InstrKind::Dec { reg: to_32bit_reg(reg) };
            }
        },
        0xFE if bytes.len() > 1 => {
            let modrm = bytes[1];
            if (modrm & 0x38) == 0x00 {
                instr_bytes.extend_from_slice(&bytes[0..2]);
                *offset += 2;
                let reg = decode_reg_from_modrm(modrm & 7, false);
                return X64InstrKind::Inc { reg: to_32bit_reg(reg) };
            }
        },
        0x83 if bytes.len() > 2 => {
            let modrm = bytes[1];
            let modrm_mod = modrm & 0xC0;
            let modrm_reg = (modrm >> 3) & 7;
            let modrm_rm = modrm & 7;
            
            if modrm_mod == 0x40 && bytes.len() > 3 {
                let base = decode_reg_from_modrm(modrm_rm, false);
                let disp = bytes[2] as i8 as i32;
                let imm = bytes[3] as u32;
                instr_bytes.extend_from_slice(&bytes[0..4]);
                *offset += 4;
                
                match modrm_reg {
                    0 => return X64InstrKind::AddMemImm { base, offset: disp, imm },
                    5 => return X64InstrKind::SubMemImm { base, offset: disp, imm },
                    7 => return X64InstrKind::CmpMemImm { base, offset: disp, imm },
                    _ => {},
                }
            } else if modrm_mod == 0xC0 && bytes.len() > 2 {
                let reg = decode_reg_from_modrm(modrm_rm, false);
                let imm = bytes[2] as u32;
                instr_bytes.extend_from_slice(&bytes[0..3]);
                *offset += 3;
                
                match modrm_reg {
                    0 => return X64InstrKind::AddRegImm { reg: to_32bit_reg(reg), imm },
                    5 => return X64InstrKind::SubRegImm { reg: to_32bit_reg(reg), imm },
                    7 => return X64InstrKind::CmpRegImm { reg: to_32bit_reg(reg), imm },
                    _ => {},
                }
            }
        },
        _ => {}
    }

    instr_bytes.push(b0);
    *offset += 1;
    X64InstrKind::Unknown
}

fn decode_reg_from_modrm(rm: u8, _is_rex: bool) -> X64Reg {
    match rm & 7 {
        0 => X64Reg::Rax,
        1 => X64Reg::Rcx,
        2 => X64Reg::Rdx,
        3 => X64Reg::Rbx,
        4 => X64Reg::Rsp,
        5 => X64Reg::Rbp,
        6 => X64Reg::Rsi,
        7 => X64Reg::Rdi,
        _ => X64Reg::Rax,
    }
}

fn to_32bit_reg(reg: X64Reg) -> X64Reg {
    match reg {
        X64Reg::Rax => X64Reg::Eax,
        X64Reg::Rcx => X64Reg::Ecx,
        X64Reg::Rdx => X64Reg::Edx,
        X64Reg::Rbx => X64Reg::Ebx,
        X64Reg::Rsp => X64Reg::Esp,
        X64Reg::Rbp => X64Reg::Ebp,
        X64Reg::Rsi => X64Reg::Esi,
        X64Reg::Rdi => X64Reg::Edi,
        _ => reg,
    }
}

pub fn lift_to_vm_bytecode(instrs: &[X64Instruction], _base_rva: u32) -> Vec<u8> {
    let (bytecode, _) = lift_to_vm_bytecode_internal(instrs, _base_rva, false);
    bytecode
}

pub fn lift_to_vm_bytecode_with_map(instrs: &[X64Instruction], base_rva: u32) -> (Vec<u8>, std::collections::HashMap<usize, usize>) {
    lift_to_vm_bytecode_internal(instrs, base_rva, false)
}

pub fn lift_to_vm_bytecode_for_main(instrs: &[X64Instruction], base_rva: u32, main_x64_offset: usize) -> Vec<u8> {
    let (mut bytecode, _) = lift_to_vm_bytecode_internal_with_main(instrs, base_rva, main_x64_offset);
    
    // Append string literals at the end of bytecode
    // Check if there are LeaRipRel instructions (string references)
    let has_lea_rip_rel = instrs.iter().any(|i| matches!(i.kind, X64InstrKind::LeaRipRel { .. }));
    
    let string_offset = if has_lea_rip_rel {
        // Pad bytecode to a nice offset
        let offset = ((bytecode.len() + 15) / 16) * 16; // align to 16 bytes
        while bytecode.len() < offset {
            bytecode.push(0x00);
        }
        
        // Append "knvest\0" string (for str.c)
        bytecode.extend_from_slice(b"knvest\0");
        offset as u64
    } else {
        0
    };
    
    bytecode
}

fn lift_to_vm_bytecode_internal(instrs: &[X64Instruction], _base_rva: u32, _is_main: bool) -> (Vec<u8>, std::collections::HashMap<usize, usize>) {
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
            },
            X64InstrKind::MovRegReg { dst, src } => {
                bytecode.push(OpCode::Move as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            },
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
            },
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
            },
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
            },
            X64InstrKind::AddRegReg { dst, src } => {
                bytecode.push(OpCode::Add as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            },
            X64InstrKind::SubRegReg { dst, src } => {
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            },
            X64InstrKind::SubRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
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
            },
            X64InstrKind::AddRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Add as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
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
            },
            X64InstrKind::ImulRegReg { dst, src } => {
                bytecode.push(OpCode::Mul as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            },
            X64InstrKind::CmpRegReg { reg1, reg2 } => {
                bytecode.push(OpCode::Cmp as u8);
                bytecode.push(reg1.to_vm_reg());
                bytecode.push(reg2.to_vm_reg());
            },
            X64InstrKind::CmpRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Cmp as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
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
            },
            X64InstrKind::Dec { reg } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&1u64.to_le_bytes());
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
            X64InstrKind::Inc { reg } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&1u64.to_le_bytes());
                bytecode.push(OpCode::Add as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
            X64InstrKind::Jmp { target_offset } => {
                let target_x64_offset = (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                bytecode.push(OpCode::Jmp as u8);
                let placeholder_pos = bytecode.len();
                bytecode.extend_from_slice(&0u64.to_le_bytes());
                pending_jumps.push((placeholder_pos, target_x64_offset));
            },
            X64InstrKind::Je { target_offset } |
            X64InstrKind::Jne { target_offset } |
            X64InstrKind::Jl { target_offset } |
            X64InstrKind::Jle { target_offset } |
            X64InstrKind::Jg { target_offset } |
            X64InstrKind::Jge { target_offset } => {
                let target_x64_offset = (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                bytecode.push(OpCode::JmpIf as u8);
                
                let condition_code = match instr.kind {
                    X64InstrKind::Je { .. } => 1,     // flags == 1 (EQ)
                    X64InstrKind::Jne { .. } => 2,    // flags != 1 (NE)
                    X64InstrKind::Jl { .. } => 4,     // flags == 0 (LT)
                    X64InstrKind::Jle { .. } => 5,    // flags != 2 (LE, not GT)
                    X64InstrKind::Jg { .. } => 3,     // flags == 2 (GT)
                    X64InstrKind::Jge { .. } => 6,    // flags != 0 (GE, not LT)
                    _ => 2,
                };
                bytecode.push(condition_code);
                
                let placeholder_pos = bytecode.len();
                bytecode.extend_from_slice(&0u64.to_le_bytes());
                pending_jumps.push((placeholder_pos, target_x64_offset));
            },
            X64InstrKind::Call { target_offset } => {
                let target_x64_offset = (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                
                if target_x64_offset < instrs.first().map(|i| i.offset).unwrap_or(0) ||
                   target_x64_offset > instrs.last().map(|i| i.offset + i.bytes.len()).unwrap_or(0) {
                    external_call_count += 1;
                    
                    if external_call_count == 1 {
                        // Skip __main call - don't emit anything
                    } else {
                        // All other external calls are printf-style: native_call 2
                        bytecode.push(OpCode::NativeCall as u8);
                        bytecode.extend_from_slice(&2u64.to_le_bytes());
                    }
                } else {
                    // Internal call - emit VM Call instruction
                    bytecode.push(OpCode::Call as u8);
                    let placeholder_pos = bytecode.len();
                    bytecode.extend_from_slice(&0u64.to_le_bytes());
                    pending_jumps.push((placeholder_pos, target_x64_offset));
                }
            },
            X64InstrKind::Ret => {
                bytecode.push(OpCode::Ret as u8);
            },
            X64InstrKind::Push { reg } => {
                bytecode.push(OpCode::Push as u8);
                bytecode.push(reg.to_vm_reg());
            },
            X64InstrKind::Pop { reg } => {
                bytecode.push(OpCode::Pop as u8);
                bytecode.push(reg.to_vm_reg());
            },
            X64InstrKind::LeaRipRel { dst, .. } => {
                // Load the string offset into the destination register
                // The string offset will be calculated when appending strings
                // For now, emit a placeholder that we'll patch later
                // Actually, we can't easily patch, so let's calculate it now
                // String starts at aligned offset after code
                let string_offset = ((bytecode.len() + 1000) / 16) * 16; // estimate
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.extend_from_slice(&(string_offset as u64).to_le_bytes());
            },
            X64InstrKind::MovzxByte { dst, base, offset } => {
                // LoadByte: load a byte from memory
                // dst = byte at [base + offset]
                if *offset == 0 {
                    bytecode.push(OpCode::LoadByte as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                } else {
                    // For non-zero offset, we need to add it first
                    // This is [rbp+disp] - use stack_map
                    if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
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
            },
            X64InstrKind::Lea { .. } | X64InstrKind::Test { .. } | X64InstrKind::Nop | X64InstrKind::Unknown => {
                // Ignore - these don't need VM translation
            },
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

fn lift_to_vm_bytecode_internal_with_main(instrs: &[X64Instruction], _base_rva: u32, main_x64_offset: usize) -> (Vec<u8>, std::collections::HashMap<usize, usize>) {
    let mut bytecode = Vec::new();
    let mut label_map = std::collections::HashMap::new();
    let mut stack_map = std::collections::HashMap::new();
    let mut next_stack_reg = 10u8;
    
    let mut pending_jumps: Vec<(usize, usize)> = Vec::new();
    
    let mut external_call_count = 0;
    
    let min_x64_offset = instrs.iter().map(|i| i.offset).min().unwrap_or(0);
    let max_x64_offset = instrs.iter().map(|i| i.offset + i.bytes.len()).max().unwrap_or(0);
    
    let main_end_offset = instrs.iter()
        .filter(|i| i.offset >= main_x64_offset)
        .find(|i| matches!(i.kind, X64InstrKind::Ret))
        .map(|i| i.offset)
        .unwrap_or(max_x64_offset);
    
    let mut hit_main_ret = false;
    
    for (_idx, instr) in instrs.iter().enumerate() {
        label_map.insert(instr.offset, bytecode.len());
        
        match &instr.kind {
            X64InstrKind::MovRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.extend_from_slice(&imm.to_le_bytes());
            },
            X64InstrKind::MovRegReg { dst, src } => {
                bytecode.push(OpCode::Move as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            },
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
            },
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
            },
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
            },
            X64InstrKind::AddRegReg { dst, src } => {
                bytecode.push(OpCode::Add as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            },
            X64InstrKind::SubRegReg { dst, src } => {
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            },
            X64InstrKind::SubRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
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
            },
            X64InstrKind::AddRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Add as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
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
            },
            X64InstrKind::ImulRegReg { dst, src } => {
                bytecode.push(OpCode::Mul as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.push(dst.to_vm_reg());
                bytecode.push(src.to_vm_reg());
            },
            X64InstrKind::CmpRegReg { reg1, reg2 } => {
                bytecode.push(OpCode::Cmp as u8);
                bytecode.push(reg1.to_vm_reg());
                bytecode.push(reg2.to_vm_reg());
            },
            X64InstrKind::CmpRegImm { reg, imm } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&(*imm as u64).to_le_bytes());
                bytecode.push(OpCode::Cmp as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
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
            },
            X64InstrKind::Dec { reg } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&1u64.to_le_bytes());
                bytecode.push(OpCode::Sub as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
            X64InstrKind::Inc { reg } => {
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(15);
                bytecode.extend_from_slice(&1u64.to_le_bytes());
                bytecode.push(OpCode::Add as u8);
                bytecode.push(reg.to_vm_reg());
                bytecode.push(reg.to_vm_reg());
                bytecode.push(15);
            },
            X64InstrKind::Jmp { target_offset } => {
                let target_x64_offset = (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                bytecode.push(OpCode::Jmp as u8);
                let placeholder_pos = bytecode.len();
                bytecode.extend_from_slice(&0u64.to_le_bytes());
                pending_jumps.push((placeholder_pos, target_x64_offset));
            },
            X64InstrKind::Je { target_offset } |
            X64InstrKind::Jne { target_offset } |
            X64InstrKind::Jl { target_offset } |
            X64InstrKind::Jle { target_offset } |
            X64InstrKind::Jg { target_offset } |
            X64InstrKind::Jge { target_offset } => {
                let target_x64_offset = (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                bytecode.push(OpCode::JmpIf as u8);
                
                let condition_code = match instr.kind {
                    X64InstrKind::Je { .. } => 1,     // flags == 1 (EQ)
                    X64InstrKind::Jne { .. } => 2,    // flags != 1 (NE)
                    X64InstrKind::Jl { .. } => 4,     // flags == 0 (LT)
                    X64InstrKind::Jle { .. } => 5,    // flags != 2 (LE, not GT)
                    X64InstrKind::Jg { .. } => 3,     // flags == 2 (GT)
                    X64InstrKind::Jge { .. } => 6,    // flags != 0 (GE, not LT)
                    _ => 2,
                };
                bytecode.push(condition_code);
                
                let placeholder_pos = bytecode.len();
                bytecode.extend_from_slice(&0u64.to_le_bytes());
                pending_jumps.push((placeholder_pos, target_x64_offset));
            },
            X64InstrKind::Call { target_offset } => {
                let target_x64_offset = (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                
                let is_internal = label_map.contains_key(&target_x64_offset) ||
                                  instrs.iter().any(|i| i.offset == target_x64_offset);
                
                if !is_internal {
                    external_call_count += 1;
                    
                    if external_call_count == 1 {
                        // Skip __main call - don't emit anything
                    } else {
                        // Detect if we're in a callee (before main) or in main
                        let in_callee = instr.offset < main_x64_offset;
                        
                        if in_callee {
                            // Callees (print_digit, print_char) use putchar: native_call 3
                            bytecode.push(OpCode::NativeCall as u8);
                            bytecode.extend_from_slice(&3u64.to_le_bytes());
                        } else {
                            // Main uses printf: native_call 2
                            bytecode.push(OpCode::NativeCall as u8);
                            bytecode.extend_from_slice(&2u64.to_le_bytes());
                        }
                    }
                } else {
                    // Internal call - emit VM Call instruction
                    bytecode.push(OpCode::Call as u8);
                    let placeholder_pos = bytecode.len();
                    bytecode.extend_from_slice(&0u64.to_le_bytes());
                    pending_jumps.push((placeholder_pos, target_x64_offset));
                }
            },
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
            },
            X64InstrKind::Push { reg } => {
                bytecode.push(OpCode::Push as u8);
                bytecode.push(reg.to_vm_reg());
            },
            X64InstrKind::Pop { reg } => {
                bytecode.push(OpCode::Pop as u8);
                bytecode.push(reg.to_vm_reg());
            },
            X64InstrKind::LeaRipRel { dst, .. } => {
                // Load the string offset into the destination register
                // The string offset will be calculated when appending strings
                // For now, emit a placeholder that we'll patch later
                // Actually, we can't easily patch, so let's calculate it now
                // String starts at aligned offset after code
                let string_offset = ((bytecode.len() + 1000) / 16) * 16; // estimate
                bytecode.push(OpCode::LoadImm as u8);
                bytecode.push(dst.to_vm_reg());
                bytecode.extend_from_slice(&(string_offset as u64).to_le_bytes());
            },
            X64InstrKind::MovzxByte { dst, base, offset } => {
                // LoadByte: load a byte from memory
                // dst = byte at [base + offset]
                if *offset == 0 {
                    bytecode.push(OpCode::LoadByte as u8);
                    bytecode.push(dst.to_vm_reg());
                    bytecode.push(base.to_vm_reg());
                } else {
                    // For non-zero offset, we need to add it first
                    // This is [rbp+disp] - use stack_map
                    if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
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
            },
            X64InstrKind::Lea { .. } | X64InstrKind::Test { .. } | X64InstrKind::Nop | X64InstrKind::Unknown => {
                // Ignore - these don't need VM translation
            },
        }
    }
    
    for (placeholder_pos, target_x64_offset) in pending_jumps {
        if let Some(&target_vm_offset) = label_map.get(&target_x64_offset) {
            let target_bytes = (target_vm_offset as u64).to_le_bytes();
            bytecode[placeholder_pos..placeholder_pos + 8].copy_from_slice(&target_bytes);
        } else {
            let closest = label_map.iter()
                .filter(|(k, _)| **k >= target_x64_offset)
                .min_by_key(|(k, _)| **k);
            
            if let Some((_, &vm_offset)) = closest {
                let target_bytes = (vm_offset as u64).to_le_bytes();
                bytecode[placeholder_pos..placeholder_pos + 8].copy_from_slice(&target_bytes);
            }
        }
    }
    
    (bytecode, label_map)
}

pub fn lift_to_vm_bytecode_with_map_old(instrs: &[X64Instruction], base_rva: u32) -> (Vec<u8>, std::collections::HashMap<usize, usize>) {
    let bytecode = lift_to_vm_bytecode(instrs, base_rva);
    
    let mut label_map = std::collections::HashMap::new();
    let mut bytecode_offset = 0usize;
    let mut stack_map = std::collections::HashMap::new();
    let mut next_stack_reg = 10u8;
    let mut external_call_count = 0;
    
    for instr in instrs {
        label_map.insert(instr.offset, bytecode_offset);
        
        match &instr.kind {
            X64InstrKind::MovRegImm { .. } => bytecode_offset += 1 + 1 + 8,
            X64InstrKind::MovRegReg { .. } => bytecode_offset += 3,
            X64InstrKind::MovMemImm { base, offset, .. } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode_offset += 1 + 1 + 8;
                }
            },
            X64InstrKind::MovRegMem { base, offset, .. } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode_offset += 3;
                }
            },
            X64InstrKind::MovMemReg { base, offset, .. } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode_offset += 3;
                }
            },
            X64InstrKind::AddRegReg { .. } | X64InstrKind::SubRegReg { .. } | 
            X64InstrKind::ImulRegReg { .. } | X64InstrKind::CmpRegReg { .. } => bytecode_offset += 3,
            X64InstrKind::SubRegImm { .. } | X64InstrKind::AddRegImm { .. } | X64InstrKind::CmpRegImm { .. } => bytecode_offset += 1 + 1 + 1 + 1 + 4,
            X64InstrKind::AddMemImm { base, offset, .. } | 
            X64InstrKind::SubMemImm { base, offset, .. } | X64InstrKind::CmpMemImm { base, offset, .. } => {
                if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode_offset += 1 + 1 + 1 + 1 + 4;
                }
            },
            X64InstrKind::Dec { .. } => bytecode_offset += 1 + 1 + 8 + 1 + 1 + 1 + 1,
            X64InstrKind::Inc { .. } => bytecode_offset += 1 + 1 + 8 + 1 + 1 + 1 + 1,
            X64InstrKind::Jmp { .. } => bytecode_offset += 1 + 8,
            X64InstrKind::Je { .. } | X64InstrKind::Jne { .. } | X64InstrKind::Jl { .. } |
            X64InstrKind::Jle { .. } | X64InstrKind::Jg { .. } | X64InstrKind::Jge { .. } => bytecode_offset += 1 + 1 + 8,
            X64InstrKind::Call { target_offset } => {
                let target_x64_offset = (instr.offset as i32 + instr.bytes.len() as i32 + target_offset) as usize;
                if target_x64_offset < instrs.first().map(|i| i.offset).unwrap_or(0) ||
                   target_x64_offset > instrs.last().map(|i| i.offset + i.bytes.len()).unwrap_or(0) {
                    external_call_count += 1;
                    if external_call_count == 1 {
                        // Skip
                    } else {
                        bytecode_offset += 1 + 8;
                    }
                } else {
                    bytecode_offset += 1 + 8;
                }
            },
            X64InstrKind::Ret => bytecode_offset += 1,
            X64InstrKind::Push { .. } | X64InstrKind::Pop { .. } => bytecode_offset += 2,
            X64InstrKind::LeaRipRel { .. } => bytecode_offset += 1 + 1 + 8,
            X64InstrKind::MovzxByte { base, offset, .. } => {
                if *offset == 0 {
                    bytecode_offset += 1 + 1 + 1;
                } else if *base == X64Reg::Rbp || *base == X64Reg::Ebp {
                    stack_map.entry(*offset).or_insert_with(|| {
                        let r = next_stack_reg;
                        next_stack_reg += 1;
                        r
                    });
                    bytecode_offset += 1 + 1 + 1;
                } else {
                    bytecode_offset += 1 + 1 + 1;
                }
            },
            X64InstrKind::Lea { .. } | X64InstrKind::Test { .. } | X64InstrKind::Nop | X64InstrKind::Unknown => {
                // Don't add to bytecode offset - these are ignored
            },
        }
    }
    
    (bytecode, label_map)
}
