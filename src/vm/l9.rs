//! L9 virtualization passes.
//!
//! Two techniques that sit on top of the existing 21-opcode ISA:
//!
//! * **Register-file encoding.** Each virtual register slot is stored as
//!   `plaintext XOR key[slot]`, with the key fixed at pack time. Handlers
//!   decode a slot only for the instruction that uses it. This matches the
//!   per-slot register encoding used by current virtualization obfuscators
//!   (xollvm `regEncrypt`; the handler-level encryption surveyed in
//!   IEEE S&P 2025, "Inspecting Virtual Machine Diversification").
//! * **Superoperators.** A straight-line `mul` followed by `add` collapses
//!   into one `native_call` (`dst = a * b + c`). Tigress and xollvm `superOps`
//!   use the same idea: one dispatch does the work of two, and the product
//!   never appears as its own handler result.
//!
//! Canonical opcode count stays 21. The fused multiply-add rides on
//! `NativeCall`, same as the L8 micro-ops.

use super::block_map::{BlockMapPlan, META_OPERAND_LEN};
use super::layout::{enumerate_raw_instructions, RawInsnKind};
use super::opcode::OpCode;
use super::opcode_map::OpcodeMap;
use super::DispatchMode;
use super::IsaMode;
use std::collections::{HashMap, HashSet};

/// `NativeCall` tag for `dst = a * b + c`.
/// Layout: `0x7_0000_0000 | (dst << 24) | (a << 16) | (b << 8) | c`.
pub const NATIVE_CALL_MADD_BASE: u64 = 0x7_0000_0000;
const NATIVE_CALL_MADD_END: u64 = 0x8_0000_0000;

const REG_KEY_SALT: u64 = 0x5245_474B_4559_4C39; // "REGKEYL9"

fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Pack-time XOR key for virtual register `slot` (`0..32`).
pub fn reg_slot_key(seed: u64, slot: u8) -> u64 {
    splitmix64(
        seed ^ REG_KEY_SALT ^ (slot as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
    )
}

pub fn encode_madd(dst: u8, a: u8, b: u8, c: u8) -> u64 {
    NATIVE_CALL_MADD_BASE
        | ((dst as u64) << 24)
        | ((a as u64) << 16)
        | ((b as u64) << 8)
        | (c as u64)
}

pub fn decode_madd(func_id: u64) -> Option<(u8, u8, u8, u8)> {
    if !(NATIVE_CALL_MADD_BASE..NATIVE_CALL_MADD_END).contains(&func_id) {
        return None;
    }
    let dst = ((func_id >> 24) & 0xFF) as u8;
    let a = ((func_id >> 16) & 0xFF) as u8;
    let b = ((func_id >> 8) & 0xFF) as u8;
    let c = (func_id & 0xFF) as u8;
    if dst > 31 || a > 31 || b > 31 || c > 31 {
        return None;
    }
    Some((dst, a, b, c))
}

pub fn format_madd(func_id: u64) -> Option<String> {
    let (dst, a, b, c) = decode_madd(func_id)?;
    Some(format!("madd r{dst}, r{a}, r{b}, r{c}"))
}

/// `dst = a.wrapping_mul(b).wrapping_add(c)`.
pub fn exec_madd(a: u64, b: u64, c: u64) -> u64 {
    a.wrapping_mul(b).wrapping_add(c)
}

/// Fuse adjacent register-ISA `mul t, a, b` + `add d, …t…` into one madd.
///
/// The product register `t` must be the add's destination, or it must be
/// dead before the next branch, call, or native micro-op. A branch that
/// lands on the `add` blocks the fuse so the target stays a real instruction.
/// Stack ISA bytecode is returned unchanged. Branch immediates and string-pool
/// offsets are relocated; other immediates are not.
pub fn fuse_madd(
    bytecode: &[u8],
    base_map: &OpcodeMap,
    block_plan: &BlockMapPlan,
    isa_mode: IsaMode,
) -> Vec<u8> {
    if isa_mode.is_stack() || bytecode.is_empty() {
        return bytecode.to_vec();
    }
    let insns = enumerate_raw_instructions(
        bytecode,
        base_map,
        block_plan,
        &super::layout::BytecodeLayout::identity(),
        DispatchMode::Table,
        isa_mode,
    );
    if insns.is_empty() {
        return bytecode.to_vec();
    }
    let code_end = insns.last().map(|i| i.start + i.raw_len).unwrap_or(0);
    let targets = branch_targets(bytecode, &insns);
    let mut active = base_map.clone();
    let mut maps = Vec::with_capacity(insns.len());
    for insn in &insns {
        maps.push(active.clone());
        if let RawInsnKind::SetBlockMap = insn.kind {
            if insn.start + 1 + META_OPERAND_LEN <= bytecode.len() {
                let tx = u16::from_le_bytes([
                    bytecode[insn.start + 1],
                    bytecode[insn.start + 2],
                ]);
                if let Some(next) = block_plan.map_for_tx_or_legacy(tx, base_map) {
                    active = next;
                }
            }
        }
    }

    let mut fuse_at = vec![false; insns.len()];
    let mut skip_add = vec![false; insns.len()];
    let mut i = 0;
    while i + 1 < insns.len() {
        if let Some((dst, a, b, c)) = madd_pair(bytecode, &insns, &targets, i) {
            let _ = (dst, a, b, c);
            fuse_at[i] = true;
            skip_add[i + 1] = true;
            i += 2;
        } else {
            i += 1;
        }
    }

    let mut new_of: HashMap<usize, usize> = HashMap::new();
    let mut cursor = 0usize;
    for (idx, insn) in insns.iter().enumerate() {
        if skip_add[idx] {
            continue;
        }
        new_of.insert(insn.start, cursor);
        if fuse_at[idx] {
            cursor += 1 + 8;
        } else {
            cursor += insn.raw_len;
        }
    }
    let growth = cursor as isize - code_end as isize;

    let reloc = |old: usize| -> usize {
        if let Some(&neu) = new_of.get(&old) {
            neu
        } else if old >= code_end {
            (old as isize + growth) as usize
        } else {
            old
        }
    };

    let mut out = Vec::with_capacity(bytecode.len().saturating_add(growth.max(0) as usize));
    for (idx, insn) in insns.iter().enumerate() {
        if skip_add[idx] {
            continue;
        }
        if fuse_at[idx] {
            let (dst, a, b, c) = madd_pair(bytecode, &insns, &targets, idx).expect("fuse pair");
            let wire = maps[idx].encode(OpCode::NativeCall);
            let imm = encode_madd(dst, a, b, c);
            out.push(wire);
            out.extend_from_slice(&imm.to_le_bytes());
            continue;
        }
        let mut body = bytecode[insn.start..insn.start + insn.raw_len].to_vec();
        if let RawInsnKind::Semantic(op) = insn.kind {
            patch_relocated_immediate(&mut body, op, code_end, &reloc);
        }
        out.extend_from_slice(&body);
    }
    if code_end < bytecode.len() {
        out.extend_from_slice(&bytecode[code_end..]);
    }
    out
}

fn madd_pair(
    bytecode: &[u8],
    insns: &[super::layout::RawInsn],
    targets: &HashSet<usize>,
    mul_idx: usize,
) -> Option<(u8, u8, u8, u8)> {
    let mul = &insns[mul_idx];
    let add = insns.get(mul_idx + 1)?;
    let RawInsnKind::Semantic(OpCode::Mul) = mul.kind else {
        return None;
    };
    let RawInsnKind::Semantic(OpCode::Add) = add.kind else {
        return None;
    };
    if mul.raw_len != 4 || add.raw_len != 4 {
        return None;
    }
    if targets.contains(&add.start) {
        return None;
    }
    let mul_dst = bytecode[mul.start + 1];
    let a = bytecode[mul.start + 2];
    let b = bytecode[mul.start + 3];
    let add_dst = bytecode[add.start + 1];
    let s1 = bytecode[add.start + 2];
    let s2 = bytecode[add.start + 3];
    if mul_dst > 31 || a > 31 || b > 31 || add_dst > 31 || s1 > 31 || s2 > 31 {
        return None;
    }
    let c = if s1 == mul_dst && s2 != mul_dst {
        s2
    } else if s2 == mul_dst && s1 != mul_dst {
        s1
    } else {
        return None;
    };
    if mul_dst != add_dst && !temp_dead(bytecode, insns, mul_dst, mul_idx + 2) {
        return None;
    }
    Some((add_dst, a, b, c))
}

fn temp_dead(
    bytecode: &[u8],
    insns: &[super::layout::RawInsn],
    temp: u8,
    from: usize,
) -> bool {
    for insn in insns.iter().skip(from) {
        match insn.kind {
            RawInsnKind::SetBlockMap => return false,
            RawInsnKind::Semantic(op) => {
                if is_barrier(op) {
                    return false;
                }
                let ops = &bytecode[insn.start + 1..insn.start + insn.raw_len];
                if reads_reg(op, ops, temp) {
                    return false;
                }
                if writes_reg(op, ops, temp) {
                    return true;
                }
            }
        }
    }
    true
}

fn is_barrier(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::Jmp
            | OpCode::JmpIf
            | OpCode::Call
            | OpCode::Ret
            | OpCode::NativeCall
            | OpCode::RunNative
            | OpCode::BailNative
    )
}

fn reads_reg(op: OpCode, ops: &[u8], reg: u8) -> bool {
    match op {
        OpCode::Move | OpCode::LoadByte | OpCode::LoadMem => ops.get(1) == Some(&reg),
        OpCode::StoreMem => ops.first() == Some(&reg) || ops.get(1) == Some(&reg),
        OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Xor | OpCode::And => {
            ops.get(1) == Some(&reg) || ops.get(2) == Some(&reg)
        }
        OpCode::Cmp | OpCode::Cmp32 => ops.first() == Some(&reg) || ops.get(1) == Some(&reg),
        OpCode::Push | OpCode::Exit => ops.first() == Some(&reg),
        _ => false,
    }
}

fn writes_reg(op: OpCode, ops: &[u8], reg: u8) -> bool {
    match op {
        OpCode::LoadImm
        | OpCode::LoadStr
        | OpCode::Move
        | OpCode::LoadByte
        | OpCode::LoadMem
        | OpCode::Add
        | OpCode::Sub
        | OpCode::Mul
        | OpCode::Xor
        | OpCode::And
        | OpCode::Pop => ops.first() == Some(&reg),
        _ => false,
    }
}

fn branch_targets(bytecode: &[u8], insns: &[super::layout::RawInsn]) -> HashSet<usize> {
    let mut targets = HashSet::new();
    for insn in insns {
        let RawInsnKind::Semantic(op) = insn.kind else {
            continue;
        };
        let ops = &bytecode[insn.start + 1..insn.start + insn.raw_len];
        match op {
            OpCode::Jmp | OpCode::Call if ops.len() >= 8 => {
                targets.insert(u64::from_le_bytes(ops[0..8].try_into().unwrap()) as usize);
            }
            OpCode::JmpIf if ops.len() >= 9 => {
                targets.insert(u64::from_le_bytes(ops[1..9].try_into().unwrap()) as usize);
            }
            _ => {}
        }
    }
    targets
}

fn patch_relocated_immediate(body: &mut [u8], op: OpCode, code_end: usize, reloc: &dyn Fn(usize) -> usize) {
    let patch = |slot: &mut [u8], code_end: usize| {
        let old = u64::from_le_bytes(slot.try_into().unwrap()) as usize;
        let new = if old >= code_end || reloc(old) != old {
            reloc(old)
        } else {
            old
        };
        // Relocate instruction starts and pool offsets. Leave immediates that
        // are not instruction starts and sit inside the code image alone.
        if old >= code_end || reloc(old) != old {
            slot.copy_from_slice(&(new as u64).to_le_bytes());
        }
    };
    match op {
        OpCode::Jmp | OpCode::Call if body.len() >= 9 => patch(&mut body[1..9], code_end),
        OpCode::JmpIf if body.len() >= 10 => patch(&mut body[2..10], code_end),
        OpCode::LoadImm | OpCode::LoadStr if body.len() >= 10 => {
            let old = u64::from_le_bytes(body[2..10].try_into().unwrap()) as usize;
            if old >= code_end {
                body[2..10].copy_from_slice(&(reloc(old) as u64).to_le_bytes());
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::machine::VirtualMachine;

    fn push_alu(bc: &mut Vec<u8>, map: &OpcodeMap, op: OpCode, dst: u8, s1: u8, s2: u8) {
        bc.push(map.encode(op));
        bc.push(dst);
        bc.push(s1);
        bc.push(s2);
    }

    fn push_load(bc: &mut Vec<u8>, map: &OpcodeMap, reg: u8, imm: u64) {
        bc.push(map.encode(OpCode::LoadImm));
        bc.push(reg);
        bc.extend_from_slice(&imm.to_le_bytes());
    }

    fn push_exit(bc: &mut Vec<u8>, map: &OpcodeMap, reg: u8) {
        bc.push(map.encode(OpCode::Exit));
        bc.push(reg);
    }

    #[test]
    fn slot_keys_are_per_register_and_involutive() {
        let seed = 0x4C39_u64;
        let k0 = reg_slot_key(seed, 0);
        let k1 = reg_slot_key(seed, 1);
        assert_ne!(k0, k1);
        assert_ne!(k0, 0);
        assert_eq!(0x1234_u64 ^ k0 ^ k0, 0x1234);
    }

    #[test]
    fn madd_encoding_roundtrip_and_wrap() {
        let id = encode_madd(5, 1, 2, 3);
        assert_eq!(decode_madd(id), Some((5, 1, 2, 3)));
        assert_eq!(format_madd(id).as_deref(), Some("madd r5, r1, r2, r3"));
        assert_eq!(exec_madd(u64::MAX, 2, 5), 3);
        assert!(decode_madd(0x6_0000_0000).is_none());
        assert!(decode_madd(encode_madd(32, 0, 0, 0)).is_none());
    }

    #[test]
    fn reg_encrypt_matches_plaintext_vm() {
        let map = OpcodeMap::from_seed(0x1111);
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 1, 3);
        push_load(&mut bc, &map, 2, 4);
        push_load(&mut bc, &map, 3, 5);
        push_alu(&mut bc, &map, OpCode::Mul, 4, 1, 2);
        push_alu(&mut bc, &map, OpCode::Add, 5, 4, 3);
        push_exit(&mut bc, &map, 5);

        let mut plain = VirtualMachine::with_opcode_map(bc.clone(), map.clone());
        plain.run().unwrap();
        let mut enc = VirtualMachine::with_opcode_map(bc, map).with_reg_encrypt(0x1111);
        enc.run().unwrap();
        assert_eq!(plain.exit_code, Some(17));
        assert_eq!(enc.exit_code, Some(17));
        assert_eq!(enc.get_register(5).unwrap(), 17);
        assert_ne!(enc.raw_register(5).unwrap(), 17);
        assert_eq!(enc.raw_register(1).unwrap() ^ reg_slot_key(0x1111, 1), 3);
    }

    #[test]
    fn fuse_madd_preserves_result_and_skips_live_temp() {
        let map = OpcodeMap::from_seed(0xA11);
        let plan = BlockMapPlan::default();
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 1, 3);
        push_load(&mut bc, &map, 2, 4);
        push_load(&mut bc, &map, 3, 5);
        push_alu(&mut bc, &map, OpCode::Mul, 4, 1, 2);
        push_alu(&mut bc, &map, OpCode::Add, 5, 4, 3);
        push_exit(&mut bc, &map, 5);
        let fused = fuse_madd(&bc, &map, &plan, IsaMode::Reg);
        assert!(fused.windows(9).any(|w| {
            w[0] == map.encode(OpCode::NativeCall)
                && decode_madd(u64::from_le_bytes(w[1..9].try_into().unwrap()))
                    == Some((5, 1, 2, 3))
        }));
        let fused_ops = enumerate_raw_instructions(
            &fused,
            &map,
            &plan,
            &crate::vm::BytecodeLayout::identity(),
            DispatchMode::Table,
            IsaMode::Reg,
        );
        assert!(fused_ops.iter().any(|insn| {
            matches!(insn.kind, RawInsnKind::Semantic(OpCode::NativeCall))
        }));
        assert!(!fused_ops
            .iter()
            .any(|insn| matches!(insn.kind, RawInsnKind::Semantic(OpCode::Mul))));
        let mut vm = VirtualMachine::with_opcode_map(fused, map.clone());
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(17));

        let mut live = Vec::new();
        push_load(&mut live, &map, 1, 3);
        push_load(&mut live, &map, 2, 4);
        push_alu(&mut live, &map, OpCode::Mul, 4, 1, 2);
        push_alu(&mut live, &map, OpCode::Add, 5, 4, 1);
        push_exit(&mut live, &map, 4);
        let kept = fuse_madd(&live, &map, &plan, IsaMode::Reg);
        assert_eq!(kept, live);
    }

    #[test]
    fn fuse_madd_relocates_forward_branch_and_refuses_add_target() {
        let map = OpcodeMap::from_seed(0xBEE);
        let plan = BlockMapPlan::default();
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 0, 1);
        push_load(&mut bc, &map, 1, 2);
        let jmp_at = bc.len();
        bc.push(map.encode(OpCode::Jmp));
        let jmp_imm = bc.len();
        bc.extend_from_slice(&0u64.to_le_bytes());
        let mul_at = bc.len();
        push_alu(&mut bc, &map, OpCode::Mul, 2, 0, 1);
        push_alu(&mut bc, &map, OpCode::Add, 3, 2, 0);
        let skip = bc.len();
        push_load(&mut bc, &map, 3, 7);
        push_exit(&mut bc, &map, 3);
        bc[jmp_imm..jmp_imm + 8].copy_from_slice(&(skip as u64).to_le_bytes());

        let fused = fuse_madd(&bc, &map, &plan, IsaMode::Reg);
        assert!(
            fused.windows(9).any(|w| w[0] == map.encode(OpCode::NativeCall)),
            "straight-line mul/add should fuse"
        );
        let mut vm = VirtualMachine::with_opcode_map(fused, map.clone());
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(7));

        let add_at = mul_at + 4;
        let mut targeted = bc;
        targeted[jmp_imm..jmp_imm + 8].copy_from_slice(&(add_at as u64).to_le_bytes());
        let refused = fuse_madd(&targeted, &map, &plan, IsaMode::Reg);
        assert_eq!(refused, targeted);
        let _ = jmp_at;
    }
}
