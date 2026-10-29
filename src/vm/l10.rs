//! L10 immediate cipher.
//!
//! L8 masks only the opcode wire byte. The qword operands that follow it —
//! `load_imm` constants, `jmp` / `jmp_if` / `call` targets, `native_call`
//! ids, and native-sled offsets — stay in the clear. xVMP encrypts each
//! virtual block, and VMSpec (arXiv:2610.29566) treats encrypted operands as
//! part of the bytecode decoding context. This pass XORs those 8-byte
//! immediates with a position key and leaves the image ciphertext. Handlers
//! recover the value in a register. They do not write it back.
//!
//! Canonical opcode count stays 21. The `jmp_if` condition byte stays plaintext.
//! Register-index bytes are covered by L11.

use super::block_map::BlockMapPlan;
use super::layout::{enumerate_raw_instructions, enumerate_raw_instructions_masked, BytecodeLayout, RawInsnKind};
use super::opcode::OpCode;
use super::opcode_map::OpcodeMap;
use super::DispatchMode;
use super::IsaMode;

const IMM_CIPHER_SALT: u64 = 0x494D_4D4B_4559_4C31; // "IMMKEYL1"
/// Zero-extended multiplier. Matches `mov r10d, 0x9E3779B9` in the stub.
pub const IMM_CIPHER_GOLDEN: u64 = 0x9E37_79B9;

fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Pack-time key mixed into every immediate mask.
pub fn imm_cipher_key64(seed: u64) -> u64 {
    splitmix64(seed ^ IMM_CIPHER_SALT)
}

/// Idempotent mask for the qword whose first byte sits at `offset`.
pub fn imm_cipher_mask(seed: u64, offset: usize) -> u64 {
    let mixed = (offset as u64).wrapping_mul(IMM_CIPHER_GOLDEN) ^ imm_cipher_key64(seed);
    mixed ^ (mixed >> 32)
}

/// Operand-relative offsets of each 8-byte immediate. A leading 1 skips a
/// register or `jmp_if` condition byte.
const IMM_AFTER_BYTE: [usize; 1] = [1];
const IMM_AT_OPERAND: [usize; 1] = [0];
const IMM_PAIR: [usize; 2] = [0, 8];

fn sites_for(op: OpCode) -> &'static [usize] {
    match op {
        OpCode::LoadImm | OpCode::LoadStr | OpCode::JmpIf => &IMM_AFTER_BYTE,
        OpCode::Jmp | OpCode::Call | OpCode::NativeCall => &IMM_AT_OPERAND,
        OpCode::RunNative | OpCode::BailNative => &IMM_PAIR,
        _ => &[],
    }
}

/// XOR every qword immediate. Applying the function twice restores the image.
pub fn apply_imm_cipher(
    bytecode: &mut [u8],
    seed: u64,
    opcode_map: &OpcodeMap,
    block_plan: &BlockMapPlan,
    layout: &BytecodeLayout,
    dispatch: DispatchMode,
    isa: IsaMode,
    rolling: bool,
) {
    let insns = if rolling {
        enumerate_raw_instructions_masked(
            bytecode,
            opcode_map,
            block_plan,
            layout,
            dispatch,
            isa,
            Some(seed),
        )
    } else {
        enumerate_raw_instructions(bytecode, opcode_map, block_plan, layout, dispatch, isa)
    };
    for insn in insns {
        let RawInsnKind::Semantic(op) = insn.kind else {
            continue;
        };
        let op_off = insn.start + layout.operands_offset_dispatch(op, false, dispatch);
        for rel in sites_for(op) {
            let site = op_off + rel;
            if site + 8 > bytecode.len() || site + 8 > insn.start + insn.raw_len {
                continue;
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytecode[site..site + 8]);
            let masked = u64::from_le_bytes(raw) ^ imm_cipher_mask(seed, site);
            bytecode[site..site + 8].copy_from_slice(&masked.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::machine::VirtualMachine;
    use crate::vm::IsaMode;

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
    fn imm_mask_is_involutive_and_position_dependent() {
        let seed = 0x4C31_u64;
        let a = imm_cipher_mask(seed, 3);
        let b = imm_cipher_mask(seed, 4);
        assert_ne!(a, b);
        assert_ne!(a, 0);
        assert_eq!(0x1111_u64 ^ a ^ a, 0x1111);
    }

    #[test]
    fn imm_cipher_hides_constant_and_keeps_exit() {
        let map = OpcodeMap::from_seed(0x4C31);
        let plan = BlockMapPlan::default();
        let layout = BytecodeLayout::identity();
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 1, 42);
        push_exit(&mut bc, &map, 1);
        let plain = bc.clone();
        apply_imm_cipher(
            &mut bc,
            0x4C31,
            &map,
            &plan,
            &layout,
            DispatchMode::Table,
            IsaMode::Reg,
            false,
        );
        assert_ne!(bc, plain);
        let mut vm = VirtualMachine::with_opcode_map(bc, map).with_imm_cipher(0x4C31);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(42));
        assert_eq!(vm.get_register(1).unwrap(), 42);
    }

    #[test]
    fn imm_cipher_keeps_forward_jump_target() {
        let map = OpcodeMap::from_seed(0x4C31);
        let plan = BlockMapPlan::default();
        let layout = BytecodeLayout::identity();
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 0, 1);
        bc.push(map.encode(OpCode::Jmp));
        let imm_at = bc.len();
        bc.extend_from_slice(&0u64.to_le_bytes());
        push_load(&mut bc, &map, 0, 99);
        let land = bc.len();
        push_exit(&mut bc, &map, 0);
        bc[imm_at..imm_at + 8].copy_from_slice(&(land as u64).to_le_bytes());
        apply_imm_cipher(
            &mut bc,
            0x4C31,
            &map,
            &plan,
            &layout,
            DispatchMode::Table,
            IsaMode::Reg,
            false,
        );
        let stored = u64::from_le_bytes(bc[imm_at..imm_at + 8].try_into().unwrap());
        assert_ne!(stored, land as u64);
        let mut vm = VirtualMachine::with_opcode_map(bc, map).with_imm_cipher(0x4C31);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(1));
    }

    #[test]
    fn imm_cipher_roundtrips_madd_and_stacks_with_rolling() {
        let seed = 0x4C31_u64;
        let map = OpcodeMap::from_seed(seed);
        let plan = BlockMapPlan::default();
        let layout = BytecodeLayout::identity();
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 0, 7);
        push_load(&mut bc, &map, 1, 4);
        push_load(&mut bc, &map, 2, 5);
        bc.push(map.encode(OpCode::NativeCall));
        bc.extend_from_slice(&crate::vm::l9::encode_madd(3, 0, 1, 2).to_le_bytes());
        push_exit(&mut bc, &map, 3);
        let plain = bc.clone();
        // load_imm is 10 bytes, native_call is 9, exit is 2.
        let starts = [0usize, 10, 20, 30, 39];
        crate::vm::l8::apply_rolling_wire_mask(&mut bc, seed, &starts);
        apply_imm_cipher(
            &mut bc,
            seed,
            &map,
            &plan,
            &layout,
            DispatchMode::Table,
            IsaMode::Reg,
            true,
        );
        assert_ne!(&bc[30 + 1..30 + 9], &plain[30 + 1..30 + 9]);
        let mut vm = VirtualMachine::with_opcode_map(bc, map)
            .with_rolling_cipher(seed)
            .with_imm_cipher(seed);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(7 * 4 + 5));
    }
}
