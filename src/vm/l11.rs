//! L11 register-index mask.
//!
//! xollvm's `obfRegIdx` XORs every register-index byte with one salt. The
//! same slot then has the same ciphertext everywhere. This pass uses the
//! byte's bytecode offset, the same 32-bit mix as the L8 wire mask, and a
//! different salt. `jmp_if` conditions, qword immediates, threaded targets,
//! and layout padding stay as they are.

use super::block_map::BlockMapPlan;
use super::layout::{
    enumerate_raw_instructions, enumerate_raw_instructions_masked, BytecodeLayout, RawInsnKind,
};
use super::opcode::OpCode;
use super::opcode_map::OpcodeMap;
use super::DispatchMode;
use super::IsaMode;

const REG_INDEX_SALT: u64 = 0x5245_4749_4458_4C31; // "REGIDXL1"

const ONE: [usize; 1] = [0];
const TWO: [usize; 2] = [0, 1];
const THREE: [usize; 3] = [0, 1, 2];

fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

pub fn reg_index_key32(seed: u64) -> u32 {
    splitmix64(seed ^ REG_INDEX_SALT) as u32
}

/// Idempotent mask for the register-index byte at `offset`.
pub fn reg_index_mask(seed: u64, offset: usize) -> u8 {
    let mixed = (offset as u32).wrapping_mul(super::l8::ROLLING_WIRE_GOLDEN) ^ reg_index_key32(seed);
    (mixed ^ (mixed >> 16)) as u8
}

/// Operand-relative offsets of register-index bytes. Stack ALU keeps only the destination.
pub fn reg_index_slots(op: OpCode, isa: IsaMode) -> &'static [usize] {
    match op {
        OpCode::LoadImm | OpCode::LoadStr | OpCode::Push | OpCode::Pop | OpCode::Exit => &ONE,
        OpCode::Move | OpCode::LoadByte | OpCode::LoadMem | OpCode::StoreMem => &TWO,
        OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Xor | OpCode::And => {
            if isa.is_stack() {
                &ONE
            } else {
                &THREE
            }
        }
        OpCode::Cmp | OpCode::Cmp32 => {
            if isa.is_stack() {
                &[]
            } else {
                &TWO
            }
        }
        _ => &[],
    }
}

/// XOR every register-index byte. Applying the function twice restores the image.
pub fn apply_reg_index_mask(
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
        for rel in reg_index_slots(op, isa) {
            let site = op_off + rel;
            if site >= bytecode.len() || site >= insn.start + insn.raw_len {
                continue;
            }
            bytecode[site] ^= reg_index_mask(seed, site);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::machine::VirtualMachine;

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
    fn reg_index_mask_is_involutive_and_position_dependent() {
        let seed = 0x4C31_u64;
        let a = reg_index_mask(seed, 1);
        let b = reg_index_mask(seed, 2);
        assert_ne!(a, b);
        assert_eq!(0x11u8 ^ a ^ a, 0x11);
    }

    #[test]
    fn reg_index_hides_slot_and_keeps_exit() {
        let seed = 0x4C31_u64;
        let map = OpcodeMap::from_seed(seed);
        let plan = BlockMapPlan::default();
        let layout = BytecodeLayout::identity();
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 1, 42);
        push_exit(&mut bc, &map, 1);
        let plain = bc.clone();
        apply_reg_index_mask(
            &mut bc,
            seed,
            &map,
            &plan,
            &layout,
            DispatchMode::Table,
            IsaMode::Reg,
            false,
        );
        assert_ne!(bc[1], plain[1]);
        assert_eq!(bc[1], 1 ^ reg_index_mask(seed, 1));
        assert_eq!(&bc[2..10], &plain[2..10]);
        let mut vm = VirtualMachine::with_opcode_map(bc, map).with_reg_index(seed);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(42));
    }

    #[test]
    fn reg_index_move_and_stack_add_match_plaintext() {
        let seed = 0x4C31_u64;
        let map = OpcodeMap::from_seed(seed);
        let plan = BlockMapPlan::default();
        let layout = BytecodeLayout::identity();
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 2, 7);
        bc.push(map.encode(OpCode::Move));
        bc.push(0);
        bc.push(2);
        push_exit(&mut bc, &map, 0);
        apply_reg_index_mask(
            &mut bc,
            seed,
            &map,
            &plan,
            &layout,
            DispatchMode::Table,
            IsaMode::Reg,
            false,
        );
        let mut vm = VirtualMachine::with_opcode_map(bc, map.clone()).with_reg_index(seed);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(7));

        let mut stack = Vec::new();
        push_load(&mut stack, &map, 1, 3);
        push_load(&mut stack, &map, 2, 4);
        stack.push(map.encode(OpCode::Push));
        stack.push(1);
        stack.push(map.encode(OpCode::Push));
        stack.push(2);
        stack.push(map.encode(OpCode::Add));
        stack.push(0);
        push_exit(&mut stack, &map, 0);
        apply_reg_index_mask(
            &mut stack,
            seed,
            &map,
            &plan,
            &layout,
            DispatchMode::Table,
            IsaMode::Stack,
            false,
        );
        let mut vm = VirtualMachine::with_opcode_map(stack, map)
            .with_isa_mode(IsaMode::Stack)
            .with_reg_index(seed);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(7));
    }

    #[test]
    fn jmp_if_condition_stays_plaintext() {
        let seed = 0x4C31_u64;
        let map = OpcodeMap::from_seed(seed);
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 0, 1);
        bc.push(map.encode(OpCode::JmpIf));
        let cond_at = bc.len();
        bc.push(1);
        bc.extend_from_slice(&0u64.to_le_bytes());
        let plain_cond = bc[cond_at];
        apply_reg_index_mask(
            &mut bc,
            seed,
            &map,
            &BlockMapPlan::default(),
            &BytecodeLayout::identity(),
            DispatchMode::Table,
            IsaMode::Reg,
            false,
        );
        assert_eq!(bc[cond_at], plain_cond);
        assert_ne!(bc[1], 0);
    }
}
