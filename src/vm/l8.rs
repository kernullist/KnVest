//! L8 micro-operations: position-keyed rolling wire mask, indirect jumps, and XMM scalars.
//!
//! Canonical opcode count stays 21. Indirect jumps and XMM ops ride on `NativeCall`
//! immediates so existing wire maps, handlers, and trailers remain compatible.

use super::opcode::OpCode;

pub const ROLLING_WIRE_GOLDEN: u32 = 0x9E3779B9;
const ROLLING_WIRE_SALT: u64 = 0x524F_4C4C_4349_5048; // "ROLLCIPH"

/// `NativeCall` immediate tag for XMM/SSE scalar micro-ops.
/// Layout: `0x2_0000_0000 | (subop << 16) | (dst << 8) | src`.
pub const NATIVE_CALL_XMM_BASE: u64 = 0x2_0000_0000;
/// `NativeCall` immediate tag for a dynamic VM-offset indirect jump.
/// Layout: `0x3_0000_0000 | vm_reg`.
pub const NATIVE_CALL_JMP_REG_BASE: u64 = 0x3_0000_0000;
/// `NativeCall` immediate tag for a direct call to another packed function RVA.
/// Layout: `0x4_0000_0000 | rva`.
pub const NATIVE_CALL_DIRECT_BASE: u64 = 0x4_0000_0000;
/// `NativeCall` immediate for x86 `div`/`idiv`.
/// Layout: `0x5_0000_0000 | (kind << 8) | divisor_reg`.
/// Dividend is `rdx:rax` (r2:r0). Quotient is written to r0 and remainder to r2.
pub const NATIVE_CALL_DIV_BASE: u64 = 0x5_0000_0000;
/// `NativeCall` immediate for a pointer load/store through a VM register.
/// Layout: `0x6_0000_0000 | (op << 16) | (data_reg << 8) | addr_reg`.
pub const NATIVE_CALL_MEM_BASE: u64 = 0x6_0000_0000;
const NATIVE_CALL_MEM_END: u64 = 0x7_0000_0000;

pub const DIV_IDIV64: u8 = 0;
pub const DIV_IDIV32: u8 = 1;
pub const DIV_DIV64: u8 = 2;
pub const DIV_DIV32: u8 = 3;
/// `cdq`: `edx = sext_fill(eax)`, `rax` unchanged, flags unchanged.
pub const DIV_CDQ: u8 = 4;
/// `cqo`: `rdx = sext_fill(rax)`, `rax` unchanged, flags unchanged.
pub const DIV_CQO: u8 = 5;
/// 8-bit `idiv`: quotient in `al`, remainder in `ah`. Bits `[63:16]` of `rax` stay.
pub const DIV_IDIV8: u8 = 6;
/// 16-bit `idiv`: quotient in `ax`, remainder in `dx`. Bits `[63:16]` stay.
pub const DIV_IDIV16: u8 = 7;
/// 8-bit `div`. Same register merge as `DIV_IDIV8`.
pub const DIV_DIV8: u8 = 8;
/// 16-bit `div`. Same register merge as `DIV_IDIV16`.
pub const DIV_DIV16: u8 = 9;

pub const MEM_LOAD64: u8 = 0;
pub const MEM_STORE64: u8 = 1;
pub const MEM_LOAD32: u8 = 2;
pub const MEM_STORE32: u8 = 3;
/// Merge a byte into bits `[7:0]`. Upper bits of the data register stay.
pub const MEM_LOAD8: u8 = 4;
pub const MEM_STORE8: u8 = 5;
/// Merge a word into bits `[15:0]`. Bits `[63:16]` stay.
pub const MEM_LOAD16: u8 = 6;
pub const MEM_STORE16: u8 = 7;
/// Merge a byte into `ah` (bits `[15:8]`).
pub const MEM_LOAD8_HI: u8 = 8;
pub const MEM_STORE8_HI: u8 = 9;

pub const XMM_MOVSS_XX: u8 = 0;
pub const XMM_MOVSD_XX: u8 = 1;
pub const XMM_MOVAPS_XX: u8 = 2;
pub const XMM_MOVUPS_XX: u8 = 3;
pub const XMM_ADDSS: u8 = 4;
pub const XMM_ADDSD: u8 = 5;
pub const XMM_SUBSS: u8 = 6;
pub const XMM_SUBSD: u8 = 7;
pub const XMM_MULSS: u8 = 8;
pub const XMM_MULSD: u8 = 9;
pub const XMM_DIVSS: u8 = 10;
pub const XMM_DIVSD: u8 = 11;
pub const XMM_UCOMISS: u8 = 12;
pub const XMM_UCOMISD: u8 = 13;
pub const XMM_CVTSI2SD: u8 = 14;
pub const XMM_CVTTSD2SI: u8 = 15;
pub const XMM_XORPS: u8 = 16;
pub const XMM_XORPD: u8 = 17;
/// xmm dst, gp src (memory-style load: upper bits cleared).
pub const XMM_MOVSS_XM: u8 = 18;
pub const XMM_MOVSS_MX: u8 = 19;
pub const XMM_MOVSD_XM: u8 = 20;
pub const XMM_MOVSD_MX: u8 = 21;
pub const XMM_MOVAPS_XM: u8 = 22;
pub const XMM_MOVAPS_MX: u8 = 23;
pub const XMM_MOVUPS_XM: u8 = 24;
pub const XMM_MOVUPS_MX: u8 = 25;
pub const XMM_MOVQ_XX: u8 = 26;
pub const XMM_MOVD_XX: u8 = 27;
pub const XMM_COMISS: u8 = 28;
pub const XMM_COMISD: u8 = 29;
pub const XMM_CVTSI2SS: u8 = 30;
pub const XMM_CVTTSS2SI: u8 = 31;
pub const XMM_CVTSS2SD: u8 = 32;
pub const XMM_CVTSD2SS: u8 = 33;
pub const XMM_MOVQ_XM: u8 = 34;
pub const XMM_MOVQ_MX: u8 = 35;
pub const XMM_MOVD_XM: u8 = 36;
pub const XMM_MOVD_MX: u8 = 37;

pub const XMM_SLOT_COUNT: usize = 16;

fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// 32-bit rolling key derived from the pack seed.
pub fn rolling_wire_key32(seed: u64) -> u32 {
    splitmix64(seed ^ ROLLING_WIRE_SALT) as u32
}

/// Idempotent position-based wire mask.
/// `mask = (((offset * 0x9E3779B9) ^ key32) ^ (mixed >> 16)) as u8`.
pub fn rolling_wire_mask(seed: u64, offset: usize) -> u8 {
    let key32 = rolling_wire_key32(seed);
    let mixed = (offset as u32).wrapping_mul(ROLLING_WIRE_GOLDEN) ^ key32;
    (mixed ^ (mixed >> 16)) as u8
}

/// XOR the wire byte at each instruction start. Applying twice restores the plaintext.
pub fn apply_rolling_wire_mask(bytecode: &mut [u8], seed: u64, starts: &[usize]) {
    for &off in starts {
        if off < bytecode.len() {
            bytecode[off] ^= rolling_wire_mask(seed, off);
        }
    }
}

pub fn encode_xmm(subop: u8, dst: u8, src: u8) -> u64 {
    NATIVE_CALL_XMM_BASE | ((subop as u64) << 16) | ((dst as u64) << 8) | (src as u64)
}

pub fn encode_jmp_reg(reg: u8) -> u64 {
    NATIVE_CALL_JMP_REG_BASE | (reg as u64)
}

pub fn encode_direct_call(rva: u32) -> u64 {
    NATIVE_CALL_DIRECT_BASE | (rva as u64)
}

pub fn decode_xmm(func_id: u64) -> Option<(u8, u8, u8)> {
    if func_id < NATIVE_CALL_XMM_BASE || func_id >= NATIVE_CALL_JMP_REG_BASE {
        return None;
    }
    let subop = ((func_id >> 16) & 0xFF) as u8;
    let dst = ((func_id >> 8) & 0xFF) as u8;
    let src = (func_id & 0xFF) as u8;
    Some((subop, dst, src))
}

pub fn decode_jmp_reg(func_id: u64) -> Option<u8> {
    if func_id < NATIVE_CALL_JMP_REG_BASE || func_id >= NATIVE_CALL_DIRECT_BASE {
        return None;
    }
    Some((func_id & 0xFF) as u8)
}

pub fn decode_direct_call(func_id: u64) -> Option<u32> {
    if func_id < NATIVE_CALL_DIRECT_BASE || func_id >= NATIVE_CALL_DIV_BASE {
        return None;
    }
    Some(func_id as u32)
}

pub fn encode_div(kind: u8, divisor_reg: u8) -> u64 {
    NATIVE_CALL_DIV_BASE | ((kind as u64) << 8) | (divisor_reg as u64)
}

pub fn decode_div(func_id: u64) -> Option<(u8, u8)> {
    if !(NATIVE_CALL_DIV_BASE..NATIVE_CALL_MEM_BASE).contains(&func_id) {
        return None;
    }
    let kind = ((func_id >> 8) & 0xFF) as u8;
    let reg = (func_id & 0xFF) as u8;
    Some((kind, reg))
}

pub fn encode_mem(op: u8, data_reg: u8, addr_reg: u8) -> u64 {
    NATIVE_CALL_MEM_BASE | ((op as u64) << 16) | ((data_reg as u64) << 8) | (addr_reg as u64)
}

pub fn decode_mem(func_id: u64) -> Option<(u8, u8, u8)> {
    if !(NATIVE_CALL_MEM_BASE..NATIVE_CALL_MEM_END).contains(&func_id) {
        return None;
    }
    let op = ((func_id >> 16) & 0xFF) as u8;
    let data = ((func_id >> 8) & 0xFF) as u8;
    let addr = (func_id & 0xFF) as u8;
    Some((op, data, addr))
}

/// x86 `div`/`idiv`. `dividend_hi:dividend_lo` is `rdx:rax`.
/// 32-bit forms use only the low half of each register and zero-extend the results.
/// Returns `(quotient, remainder)` or `Err` on divide-by-zero or a quotient that does not fit.
pub fn exec_div(
    kind: u8,
    dividend_lo: u64,
    dividend_hi: u64,
    divisor: u64,
) -> Result<(u64, u64), ()> {
    match kind {
        DIV_IDIV64 => {
            let d = divisor as i64;
            let n = ((dividend_hi as i64 as i128) << 64) | (dividend_lo as u64 as i128);
            let q = n.checked_div(d as i128).ok_or(())?;
            let r = n.checked_rem(d as i128).ok_or(())?;
            if q > i64::MAX as i128 || q < i64::MIN as i128 {
                return Err(());
            }
            Ok((q as i64 as u64, r as i64 as u64))
        }
        DIV_IDIV32 => {
            let d = divisor as i32;
            let n = ((dividend_hi as i32 as i64) << 32) | (dividend_lo as u32 as i64);
            let q = n.checked_div(d as i64).ok_or(())?;
            let r = n.checked_rem(d as i64).ok_or(())?;
            if q > i32::MAX as i64 || q < i32::MIN as i64 {
                return Err(());
            }
            Ok((q as u32 as u64, r as u32 as u64))
        }
        DIV_DIV64 => {
            let n = ((dividend_hi as u128) << 64) | (dividend_lo as u128);
            let q = n.checked_div(divisor as u128).ok_or(())?;
            let r = n.checked_rem(divisor as u128).ok_or(())?;
            if q > u64::MAX as u128 {
                return Err(());
            }
            Ok((q as u64, r as u64))
        }
        DIV_DIV32 => {
            let d = divisor as u32;
            let n = ((dividend_hi as u32 as u64) << 32) | (dividend_lo as u32 as u64);
            let q = n.checked_div(d as u64).ok_or(())?;
            let r = n.checked_rem(d as u64).ok_or(())?;
            if q > u32::MAX as u64 {
                return Err(());
            }
            Ok((q, r))
        }
        DIV_CDQ => {
            let edx = if (dividend_lo as i32) < 0 {
                0xFFFF_FFFFu64
            } else {
                0
            };
            Ok((dividend_lo, edx))
        }
        DIV_CQO => {
            let rdx = if (dividend_lo as i64) < 0 {
                u64::MAX
            } else {
                0
            };
            Ok((dividend_lo, rdx))
        }
        _ => Err(()),
    }
}

/// Where a `div`/`idiv` result is written. 8-bit forms keep the remainder in `ah`.
pub enum DivWrite {
    /// Quotient to `rax`, remainder to `rdx`.
    Both(u64, u64),
    /// Updated `rax` only (`rdx` is unchanged).
    Rax(u64),
}

fn merge_low(old: u64, value: u64, bits: u32) -> u64 {
    let mask = (1u64 << bits) - 1;
    (old & !mask) | (value & mask)
}

fn div8(signed: bool, rax: u64, divisor: u64) -> Result<u64, ()> {
    let ax = rax as u16;
    let (quot, rem) = if signed {
        let d = divisor as i8;
        let n = ax as i16;
        let q = n.checked_div(d as i16).ok_or(())?;
        let r = n.checked_rem(d as i16).ok_or(())?;
        if q > i8::MAX as i16 || q < i8::MIN as i16 {
            return Err(());
        }
        (q as u8 as u16, r as u8 as u16)
    } else {
        let d = divisor as u8;
        if d == 0 {
            return Err(());
        }
        let q = ax / d as u16;
        let r = ax % d as u16;
        if q > u8::MAX as u16 {
            return Err(());
        }
        (q, r)
    };
    Ok(merge_low(rax, u64::from((rem << 8) | quot), 16))
}

fn div16(signed: bool, rax: u64, rdx: u64, divisor: u64) -> Result<(u64, u64), ()> {
    let ax = rax as u16;
    let dx = rdx as u16;
    if signed {
        let n = ((dx as i16 as i32) << 16) | (ax as u16 as i32);
        let d = divisor as i16;
        let q = n.checked_div(d as i32).ok_or(())?;
        let r = n.checked_rem(d as i32).ok_or(())?;
        if q > i16::MAX as i32 || q < i16::MIN as i32 {
            return Err(());
        }
        Ok((
            merge_low(rax, q as u16 as u64, 16),
            merge_low(rdx, r as u16 as u64, 16),
        ))
    } else {
        let d = divisor as u16 as u32;
        if d == 0 {
            return Err(());
        }
        let n = ((dx as u32) << 16) | (ax as u32);
        let q = n / d;
        let r = n % d;
        if q > u16::MAX as u32 {
            return Err(());
        }
        Ok((merge_low(rax, q as u64, 16), merge_low(rdx, r as u64, 16)))
    }
}

/// Apply `div`/`idiv`/`cdq`/`cqo`, including 8- and 16-bit partial-register merges.
pub fn exec_div_effect(kind: u8, lo: u64, hi: u64, divisor: u64) -> Result<DivWrite, ()> {
    match kind {
        DIV_IDIV8 => Ok(DivWrite::Rax(div8(true, lo, divisor)?)),
        DIV_DIV8 => Ok(DivWrite::Rax(div8(false, lo, divisor)?)),
        DIV_IDIV16 => {
            let (rax, rdx) = div16(true, lo, hi, divisor)?;
            Ok(DivWrite::Both(rax, rdx))
        }
        DIV_DIV16 => {
            let (rax, rdx) = div16(false, lo, hi, divisor)?;
            Ok(DivWrite::Both(rax, rdx))
        }
        _ => {
            let (q, r) = exec_div(kind, lo, hi, divisor)?;
            Ok(DivWrite::Both(q, r))
        }
    }
}

pub fn xmm_mnemonic(subop: u8) -> &'static str {
    match subop {
        XMM_MOVSS_XX | XMM_MOVSS_XM | XMM_MOVSS_MX => "xmm_movss",
        XMM_MOVSD_XX | XMM_MOVSD_XM | XMM_MOVSD_MX => "xmm_movsd",
        XMM_MOVAPS_XX | XMM_MOVAPS_XM | XMM_MOVAPS_MX => "xmm_movaps",
        XMM_MOVUPS_XX | XMM_MOVUPS_XM | XMM_MOVUPS_MX => "xmm_movups",
        XMM_ADDSS => "xmm_addss",
        XMM_ADDSD => "xmm_addsd",
        XMM_SUBSS => "xmm_subss",
        XMM_SUBSD => "xmm_subsd",
        XMM_MULSS => "xmm_mulss",
        XMM_MULSD => "xmm_mulsd",
        XMM_DIVSS => "xmm_divss",
        XMM_DIVSD => "xmm_divsd",
        XMM_UCOMISS => "xmm_ucomiss",
        XMM_UCOMISD => "xmm_ucomisd",
        XMM_CVTSI2SD => "xmm_cvtsi2sd",
        XMM_CVTTSD2SI => "xmm_cvttsd2si",
        XMM_XORPS => "xmm_xorps",
        XMM_XORPD => "xmm_xorpd",
        XMM_MOVQ_XX | XMM_MOVQ_XM | XMM_MOVQ_MX => "xmm_movq",
        XMM_MOVD_XX | XMM_MOVD_XM | XMM_MOVD_MX => "xmm_movd",
        XMM_COMISS => "xmm_comiss",
        XMM_COMISD => "xmm_comisd",
        XMM_CVTSI2SS => "xmm_cvtsi2ss",
        XMM_CVTTSS2SI => "xmm_cvttss2si",
        XMM_CVTSS2SD => "xmm_cvtss2sd",
        XMM_CVTSD2SS => "xmm_cvtsd2ss",
        _ => "xmm_op",
    }
}

fn operand_name(subop: u8, idx: u8, is_dst: bool) -> String {
    let gp = match subop {
        XMM_MOVSS_XM | XMM_MOVSD_XM | XMM_MOVAPS_XM | XMM_MOVUPS_XM | XMM_MOVQ_XM | XMM_MOVD_XM
        | XMM_CVTSI2SD | XMM_CVTSI2SS => !is_dst,
        XMM_MOVSS_MX | XMM_MOVSD_MX | XMM_MOVAPS_MX | XMM_MOVUPS_MX | XMM_MOVQ_MX | XMM_MOVD_MX
        | XMM_CVTTSD2SI | XMM_CVTTSS2SI => is_dst,
        _ => false,
    };
    if gp {
        format!("r{idx}")
    } else {
        format!("xmm{idx}")
    }
}

/// Pretty operand text for an L8 `native_call` immediate, if it is one.
pub fn format_native_micro(func_id: u64) -> Option<String> {
    if let Some((subop, dst, src)) = decode_xmm(func_id) {
        return Some(format!(
            "{} {}, {}",
            xmm_mnemonic(subop),
            operand_name(subop, dst, true),
            operand_name(subop, src, false)
        ));
    }
    if let Some(reg) = decode_jmp_reg(func_id) {
        return Some(format!("jmp_reg r{reg}"));
    }
    if let Some(rva) = decode_direct_call(func_id) {
        return Some(format!("direct_call {rva:#x}"));
    }
    if let Some((kind, reg)) = decode_div(func_id) {
        let name = match kind {
            DIV_IDIV64 => "idiv64",
            DIV_IDIV32 => "idiv32",
            DIV_DIV64 => "div64",
            DIV_DIV32 => "div32",
            DIV_CDQ => return Some("cdq".to_string()),
            DIV_CQO => return Some("cqo".to_string()),
            DIV_IDIV8 => "idiv8",
            DIV_IDIV16 => "idiv16",
            DIV_DIV8 => "div8",
            DIV_DIV16 => "div16",
            _ => "div?",
        };
        return Some(format!("{name} r{reg}"));
    }
    if let Some((op, data, addr)) = decode_mem(func_id) {
        let name = match op {
            MEM_LOAD64 => "load64",
            MEM_STORE64 => "store64",
            MEM_LOAD32 => "load32",
            MEM_STORE32 => "store32",
            MEM_LOAD8 => "load8",
            MEM_STORE8 => "store8",
            MEM_LOAD16 => "load16",
            MEM_STORE16 => "store16",
            MEM_LOAD8_HI => "load8hi",
            MEM_STORE8_HI => "store8hi",
            _ => "mem?",
        };
        return Some(format!("{name} r{data}, [r{addr}]"));
    }
    None
}

fn f32_binop(dst: u64, src: u64, op: fn(f32, f32) -> f32) -> u64 {
    let a = f32::from_bits(dst as u32);
    let b = f32::from_bits(src as u32);
    let r = op(a, b).to_bits() as u64;
    (dst & !0xFFFF_FFFF) | r
}

fn f64_binop(dst: u64, src: u64, op: fn(f64, f64) -> f64) -> u64 {
    let a = f64::from_bits(dst);
    let b = f64::from_bits(src);
    op(a, b).to_bits()
}

/// Flags matching `ucomiss`/`ucomisd`: ZF bit 6, CF bit 0. SF and OF stay clear.
pub fn ucomi_flags(dest_nan_or_less: bool, equal: bool, unordered: bool) -> u64 {
    if unordered {
        return 0x40 | 0x01;
    }
    if equal {
        return 0x40;
    }
    if dest_nan_or_less {
        return 0x01;
    }
    0
}

pub fn compare_f64_flags(dest: f64, src: f64) -> u64 {
    if dest.is_nan() || src.is_nan() {
        ucomi_flags(true, false, true)
    } else if dest == src {
        ucomi_flags(false, true, false)
    } else if dest < src {
        ucomi_flags(true, false, false)
    } else {
        ucomi_flags(false, false, false)
    }
}

pub fn compare_f32_flags(dest: f32, src: f32) -> u64 {
    if dest.is_nan() || src.is_nan() {
        ucomi_flags(true, false, true)
    } else if dest == src {
        ucomi_flags(false, true, false)
    } else if dest < src {
        ucomi_flags(true, false, false)
    } else {
        ucomi_flags(false, false, false)
    }
}

pub fn cvttss2si_bits(bits: u32) -> u64 {
    cvttsd2si_bits((f32::from_bits(bits) as f64).to_bits())
}

pub fn cvttsd2si_bits(bits: u64) -> u64 {
    let f = f64::from_bits(bits);
    if !f.is_finite() || f >= (i64::MAX as f64) || f < (i64::MIN as f64) {
        return 0x8000_0000_0000_0000;
    }
    (f as i64) as u64
}

fn gp_read(gp: &[u64], reg: u8) -> Result<u64, ()> {
    gp.get(reg as usize).copied().ok_or(())
}

fn gp_write(gp: &mut [u64], reg: u8, value: u64) -> Result<(), ()> {
    if (reg as usize) < gp.len() {
        gp[reg as usize] = value;
        Ok(())
    } else {
        Err(())
    }
}

/// Execute one XMM micro-op against the XMM file and GP registers.
/// Returns `Some(flags)` when the op is a compare, otherwise `None`.
pub fn exec_xmm(
    subop: u8,
    dst: u8,
    src: u8,
    xmm: &mut [u64; XMM_SLOT_COUNT],
    gp: &mut [u64],
) -> Result<Option<u64>, ()> {
    let di = dst as usize;
    let si = src as usize;
    if di >= XMM_SLOT_COUNT || si >= XMM_SLOT_COUNT {
        return Err(());
    }
    match subop {
        XMM_MOVSS_XX => {
            xmm[di] = (xmm[di] & !0xFFFF_FFFF) | (xmm[si] & 0xFFFF_FFFF);
        }
        XMM_MOVSD_XX | XMM_MOVAPS_XX | XMM_MOVUPS_XX | XMM_MOVAPS_XM | XMM_MOVUPS_XM => {
            let value = if subop == XMM_MOVAPS_XM || subop == XMM_MOVUPS_XM {
                gp_read(gp, src)?
            } else {
                xmm[si]
            };
            if subop == XMM_MOVAPS_XM || subop == XMM_MOVUPS_XM {
                xmm[di] = value;
            } else {
                xmm[di] = xmm[si];
            }
        }
        XMM_MOVSS_XM | XMM_MOVD_XM => {
            let bits = gp_read(gp, src)?;
            xmm[di] = bits & 0xFFFF_FFFF;
        }
        XMM_MOVSD_XM | XMM_MOVQ_XM => {
            xmm[di] = gp_read(gp, src)?;
        }
        XMM_MOVSS_MX | XMM_MOVD_MX => {
            gp_write(gp, dst, xmm[si] & 0xFFFF_FFFF)?;
        }
        XMM_MOVSD_MX | XMM_MOVAPS_MX | XMM_MOVUPS_MX | XMM_MOVQ_MX => {
            gp_write(gp, dst, xmm[si])?;
        }
        XMM_MOVQ_XX => xmm[di] = xmm[si],
        XMM_MOVD_XX => xmm[di] = xmm[si] & 0xFFFF_FFFF,
        XMM_ADDSS => xmm[di] = f32_binop(xmm[di], xmm[si], |a, b| a + b),
        XMM_SUBSS => xmm[di] = f32_binop(xmm[di], xmm[si], |a, b| a - b),
        XMM_MULSS => xmm[di] = f32_binop(xmm[di], xmm[si], |a, b| a * b),
        XMM_DIVSS => xmm[di] = f32_binop(xmm[di], xmm[si], |a, b| a / b),
        XMM_ADDSD => xmm[di] = f64_binop(xmm[di], xmm[si], |a, b| a + b),
        XMM_SUBSD => xmm[di] = f64_binop(xmm[di], xmm[si], |a, b| a - b),
        XMM_MULSD => xmm[di] = f64_binop(xmm[di], xmm[si], |a, b| a * b),
        XMM_DIVSD => xmm[di] = f64_binop(xmm[di], xmm[si], |a, b| a / b),
        XMM_XORPS | XMM_XORPD => xmm[di] ^= xmm[si],
        XMM_UCOMISS | XMM_COMISS => {
            let flags = compare_f32_flags(
                f32::from_bits(xmm[di] as u32),
                f32::from_bits(xmm[si] as u32),
            );
            return Ok(Some(flags));
        }
        XMM_UCOMISD | XMM_COMISD => {
            let flags = compare_f64_flags(f64::from_bits(xmm[di]), f64::from_bits(xmm[si]));
            return Ok(Some(flags));
        }
        XMM_CVTSI2SD => {
            let bits = gp_read(gp, src)? as i64 as f64;
            xmm[di] = bits.to_bits();
        }
        XMM_CVTSI2SS => {
            let low = (gp_read(gp, src)? as i64 as f32).to_bits() as u64;
            xmm[di] = (xmm[di] & !0xFFFF_FFFF) | low;
        }
        XMM_CVTTSD2SI => {
            gp_write(gp, dst, cvttsd2si_bits(xmm[si]))?;
        }
        XMM_CVTTSS2SI => {
            gp_write(gp, dst, cvttss2si_bits(xmm[si] as u32))?;
        }
        XMM_CVTSS2SD => {
            xmm[di] = (f32::from_bits(xmm[si] as u32) as f64).to_bits();
        }
        XMM_CVTSD2SS => {
            let low = (f64::from_bits(xmm[si]) as f32).to_bits() as u64;
            xmm[di] = (xmm[di] & !0xFFFF_FFFF) | low;
        }
        _ => return Err(()),
    }
    Ok(None)
}

/// True when `func_id` is an L8 micro-op that the reference VM handles itself.
pub fn is_l8_native(func_id: u64) -> bool {
    decode_xmm(func_id).is_some()
        || decode_jmp_reg(func_id).is_some()
        || decode_direct_call(func_id).is_some()
}

pub fn native_call_opcode() -> OpCode {
    OpCode::NativeCall
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_mask_is_idempotent_and_position_dependent() {
        let seed = 0x0BAD_F00D_u64;
        let mut buf = vec![0xABu8; 16];
        let starts = [0usize, 3, 10];
        let plain = buf.clone();
        apply_rolling_wire_mask(&mut buf, seed, &starts);
        assert_ne!(buf[0], plain[0]);
        assert_eq!(buf[1], plain[1], "only instruction-start wires are masked");
        assert_ne!(rolling_wire_mask(seed, 0), rolling_wire_mask(seed, 3));
        apply_rolling_wire_mask(&mut buf, seed, &starts);
        assert_eq!(buf, plain);
    }

    #[test]
    fn xmm_addsd_and_cvtsi2sd_roundtrip() {
        let mut xmm = [0u64; XMM_SLOT_COUNT];
        xmm[0] = 1.5f64.to_bits();
        xmm[1] = 2.5f64.to_bits();
        let mut gp = [0u64; 16];
        gp[2] = 7;
        exec_xmm(XMM_ADDSD, 0, 1, &mut xmm, &mut gp).unwrap();
        assert_eq!(f64::from_bits(xmm[0]), 4.0);
        exec_xmm(XMM_CVTSI2SD, 3, 2, &mut xmm, &mut gp).unwrap();
        assert_eq!(f64::from_bits(xmm[3]), 7.0);
        xmm[4] = 9.9f64.to_bits();
        exec_xmm(XMM_CVTTSD2SI, 0, 4, &mut xmm, &mut gp).unwrap();
        assert_eq!(gp[0], 9);
    }

    #[test]
    fn ucomisd_sets_cf_and_zf() {
        let mut xmm = [0u64; XMM_SLOT_COUNT];
        xmm[0] = 1.0f64.to_bits();
        xmm[1] = 2.0f64.to_bits();
        let mut gp = [0u64; 4];
        let flags = exec_xmm(XMM_UCOMISD, 0, 1, &mut xmm, &mut gp)
            .unwrap()
            .unwrap();
        assert_eq!(flags & 0x01, 0x01, "CF set when dest < src");
        assert_eq!(flags & 0x40, 0);
        xmm[1] = 1.0f64.to_bits();
        let flags = exec_xmm(XMM_UCOMISD, 0, 1, &mut xmm, &mut gp)
            .unwrap()
            .unwrap();
        assert_eq!(flags & 0x40, 0x40);
    }

    #[test]
    fn remaining_xmm_moves_compares_and_converts() {
        let mut xmm = [0u64; XMM_SLOT_COUNT];
        let mut gp = [0u64; 8];
        xmm[1] = 0xAAAA_AAAA_FFFF_FFFFu64;
        exec_xmm(XMM_MOVD_XX, 0, 1, &mut xmm, &mut gp).unwrap();
        assert_eq!(xmm[0], 0xFFFF_FFFF);
        exec_xmm(XMM_MOVQ_XX, 2, 1, &mut xmm, &mut gp).unwrap();
        assert_eq!(xmm[2], xmm[1]);

        gp[3] = 0x1122_3344_5566_7788;
        exec_xmm(XMM_MOVD_XM, 4, 3, &mut xmm, &mut gp).unwrap();
        assert_eq!(xmm[4], 0x5566_7788);
        exec_xmm(XMM_MOVQ_XM, 5, 3, &mut xmm, &mut gp).unwrap();
        assert_eq!(xmm[5], gp[3]);
        exec_xmm(XMM_MOVD_MX, 6, 4, &mut xmm, &mut gp).unwrap();
        assert_eq!(gp[6], 0x5566_7788);

        xmm[0] = 1.0f32.to_bits() as u64;
        xmm[1] = 2.0f32.to_bits() as u64;
        let flags = exec_xmm(XMM_COMISS, 0, 1, &mut xmm, &mut gp)
            .unwrap()
            .unwrap();
        assert_eq!(flags & 0x41, 0x01);
        xmm[0] = f32::NAN.to_bits() as u64;
        let flags = exec_xmm(XMM_COMISS, 0, 1, &mut xmm, &mut gp)
            .unwrap()
            .unwrap();
        assert_eq!(flags & 0x41, 0x41);
        xmm[0] = 1.25f64.to_bits();
        xmm[1] = 1.25f64.to_bits();
        let flags = exec_xmm(XMM_COMISD, 0, 1, &mut xmm, &mut gp)
            .unwrap()
            .unwrap();
        assert_eq!(flags & 0x40, 0x40);

        gp[2] = 7;
        xmm[3] = 0x1111_1111_0000_0000;
        exec_xmm(XMM_CVTSI2SS, 3, 2, &mut xmm, &mut gp).unwrap();
        assert_eq!(f32::from_bits(xmm[3] as u32), 7.0);
        assert_eq!(xmm[3] >> 32, 0x1111_1111);
        xmm[4] = 9.75f32.to_bits() as u64;
        exec_xmm(XMM_CVTTSS2SI, 1, 4, &mut xmm, &mut gp).unwrap();
        assert_eq!(gp[1], 9);
        exec_xmm(XMM_CVTSS2SD, 5, 4, &mut xmm, &mut gp).unwrap();
        assert_eq!(f64::from_bits(xmm[5]), 9.75);
        xmm[6] = 0x2222_2222_0000_0000;
        xmm[7] = 3.5f64.to_bits();
        exec_xmm(XMM_CVTSD2SS, 6, 7, &mut xmm, &mut gp).unwrap();
        assert_eq!(f32::from_bits(xmm[6] as u32), 3.5);
        assert_eq!(xmm[6] >> 32, 0x2222_2222);
        assert!(format_native_micro(encode_xmm(XMM_COMISS, 0, 1))
            .unwrap()
            .contains("xmm_comiss xmm0, xmm1"));
        assert!(format_native_micro(encode_xmm(XMM_CVTSI2SS, 0, 2))
            .unwrap()
            .contains("xmm_cvtsi2ss xmm0, r2"));
        assert!(format_native_micro(encode_xmm(XMM_CVTTSS2SI, 1, 4))
            .unwrap()
            .contains("xmm_cvttss2si r1, xmm4"));
    }

    #[test]
    fn micro_immediate_ranges_do_not_alias_iat() {
        let xmm = encode_xmm(XMM_ADDSD, 1, 2);
        let jmp = encode_jmp_reg(0);
        let direct = encode_direct_call(0x1400);
        assert!(xmm < NATIVE_CALL_JMP_REG_BASE);
        assert!(jmp < NATIVE_CALL_DIRECT_BASE);
        assert!(direct >= NATIVE_CALL_DIRECT_BASE);
        assert!(format_native_micro(xmm).unwrap().contains("xmm_addsd"));
        assert!(format_native_micro(jmp).unwrap().contains("jmp_reg"));
        assert!(format_native_micro(direct).unwrap().contains("direct_call"));
        let div = encode_div(DIV_IDIV32, 1);
        let mem = encode_mem(MEM_LOAD64, 0, 2);
        assert!(div >= NATIVE_CALL_DIV_BASE && div < NATIVE_CALL_MEM_BASE);
        assert!(mem >= NATIVE_CALL_MEM_BASE);
        assert!(decode_direct_call(div).is_none());
        assert!(decode_div(mem).is_none());
        assert_eq!(exec_div(DIV_IDIV32, 30, 0, 5).unwrap(), (6, 0));
        // edx:eax = -20, idiv 3 → quot -6, rem -2 (remainder sign follows dividend)
        assert_eq!(
            exec_div(DIV_IDIV32, (-20i32) as u32 as u64, 0xFFFF_FFFF, 3).unwrap(),
            ((-6i32) as u32 as u64, (-2i32) as u32 as u64)
        );
        assert!(exec_div(DIV_IDIV64, 1, 0, 0).is_err());
        // i128::MIN / -1 is #DE, not a panic and not a wrapped quotient.
        assert!(exec_div(DIV_IDIV64, 0, 0x8000_0000_0000_0000, u64::MAX).is_err());
        assert_eq!(
            exec_div(DIV_CDQ, 0x1_8000_0000, 0xDEAD, 0).unwrap(),
            (0x1_8000_0000, 0xFFFF_FFFF)
        );
        assert_eq!(
            exec_div(DIV_CQO, u64::MAX, 0, 0).unwrap(),
            (u64::MAX, u64::MAX)
        );
        assert_eq!(
            format_native_micro(encode_div(DIV_CDQ, 0)).as_deref(),
            Some("cdq")
        );
        assert_eq!(
            format_native_micro(encode_div(DIV_CQO, 0)).as_deref(),
            Some("cqo")
        );
        // ax = 100, idiv cl=7 → al=14, ah=2. High rax bits stay.
        match exec_div_effect(DIV_IDIV8, 0x1111_0000_0064, 0, 7).unwrap() {
            DivWrite::Rax(rax) => assert_eq!(rax, 0x1111_0000_020E),
            DivWrite::Both(_, _) => panic!("idiv r8 writes ah:al inside rax"),
        }
        // dx:ax = 1:0, div cx=10 → quot 0x1999, rem 6. High halves stay.
        match exec_div_effect(DIV_DIV16, 0x2222_0000_0000, 0x3333_0000_0001, 10).unwrap() {
            DivWrite::Both(rax, rdx) => {
                assert_eq!(rax, 0x2222_0000_1999);
                assert_eq!(rdx, 0x3333_0000_0006);
            }
            DivWrite::Rax(_) => panic!("div r16 writes ax and dx"),
        }
    }
}
