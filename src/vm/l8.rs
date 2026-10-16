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
    if func_id < NATIVE_CALL_DIRECT_BASE || func_id >= 0x5_0000_0000 {
        return None;
    }
    Some(func_id as u32)
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
        _ => "xmm_op",
    }
}

fn operand_name(subop: u8, idx: u8, is_dst: bool) -> String {
    let gp = match subop {
        XMM_MOVSS_XM | XMM_MOVSD_XM | XMM_MOVAPS_XM | XMM_MOVUPS_XM | XMM_CVTSI2SD => !is_dst,
        XMM_MOVSS_MX | XMM_MOVSD_MX | XMM_MOVAPS_MX | XMM_MOVUPS_MX | XMM_CVTTSD2SI => is_dst,
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
        XMM_MOVSS_XM => {
            let bits = gp_read(gp, src)?;
            xmm[di] = bits & 0xFFFF_FFFF;
        }
        XMM_MOVSD_XM => {
            xmm[di] = gp_read(gp, src)?;
        }
        XMM_MOVSS_MX => {
            gp_write(gp, dst, xmm[si] & 0xFFFF_FFFF)?;
        }
        XMM_MOVSD_MX | XMM_MOVAPS_MX | XMM_MOVUPS_MX => {
            gp_write(gp, dst, xmm[si])?;
        }
        XMM_ADDSS => xmm[di] = f32_binop(xmm[di], xmm[si], |a, b| a + b),
        XMM_SUBSS => xmm[di] = f32_binop(xmm[di], xmm[si], |a, b| a - b),
        XMM_MULSS => xmm[di] = f32_binop(xmm[di], xmm[si], |a, b| a * b),
        XMM_DIVSS => xmm[di] = f32_binop(xmm[di], xmm[si], |a, b| a / b),
        XMM_ADDSD => xmm[di] = f64_binop(xmm[di], xmm[si], |a, b| a + b),
        XMM_SUBSD => xmm[di] = f64_binop(xmm[di], xmm[si], |a, b| a - b),
        XMM_MULSD => xmm[di] = f64_binop(xmm[di], xmm[si], |a, b| a * b),
        XMM_DIVSD => xmm[di] = f64_binop(xmm[di], xmm[si], |a, b| a / b),
        XMM_XORPS | XMM_XORPD => xmm[di] ^= xmm[si],
        XMM_UCOMISS => {
            let flags = compare_f32_flags(f32::from_bits(xmm[di] as u32), f32::from_bits(xmm[si] as u32));
            return Ok(Some(flags));
        }
        XMM_UCOMISD => {
            let flags = compare_f64_flags(f64::from_bits(xmm[di]), f64::from_bits(xmm[si]));
            return Ok(Some(flags));
        }
        XMM_CVTSI2SD => {
            let bits = gp_read(gp, src)? as i64 as f64;
            xmm[di] = bits.to_bits();
        }
        XMM_CVTTSD2SI => {
            gp_write(gp, dst, cvttsd2si_bits(xmm[si]))?;
        }
        _ => return Err(()),
    }
    Ok(None)
}

/// True when `func_id` is an L8 micro-op that the reference VM handles itself.
pub fn is_l8_native(func_id: u64) -> bool {
    decode_xmm(func_id).is_some() || decode_jmp_reg(func_id).is_some() || decode_direct_call(func_id).is_some()
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
    }
}
