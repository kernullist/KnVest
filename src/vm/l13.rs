//! L13 data-stack slot encryption.
//!
//! Stack-ISA `push` and the stub's data stack store a guest qword at
//! `[rbp+depth*8-0x380]`. This pass XORs that qword with a per-depth key.
//! `pop` and stack ALU reverse it. Call-stack return records stay on the L12
//! mask. Register-ISA `push`/`pop` in the reference VM use the call stack and
//! stay plaintext.

const DATA_STACK_SALT: u64 = 0x4441_5441_5354_4B31; // "DATASTK1"
/// Zero-extended multiplier. Matches `mov r11d, 0x9E3779B9` in the stub.
pub const DATA_SLOT_GOLDEN: u64 = 0x9E37_79B9;

fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

pub fn data_slot_key64(seed: u64) -> u64 {
    splitmix64(seed ^ DATA_STACK_SALT)
}

/// Idempotent mask for the data-stack qword written at `depth`.
pub fn data_slot_mask(seed: u64, depth: u64) -> u64 {
    let mixed = depth.wrapping_mul(DATA_SLOT_GOLDEN) ^ data_slot_key64(seed);
    mixed ^ (mixed >> 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::machine::VirtualMachine;
    use crate::vm::opcode_map::OpcodeMap;
    use crate::vm::{IsaMode, OpCode};

    fn push_load(bc: &mut Vec<u8>, map: &OpcodeMap, reg: u8, imm: u64) {
        bc.push(map.encode(OpCode::LoadImm));
        bc.push(reg);
        bc.extend_from_slice(&imm.to_le_bytes());
    }

    fn push_op(bc: &mut Vec<u8>, map: &OpcodeMap, op: OpCode, reg: u8) {
        bc.push(map.encode(op));
        bc.push(reg);
    }

    #[test]
    fn data_slot_mask_depends_on_depth() {
        let seed = 0x4C31_u64;
        let a = data_slot_mask(seed, 0);
        let b = data_slot_mask(seed, 1);
        assert_ne!(a, b);
        assert_ne!(a, call_mask_sample());
        assert_eq!(0x2222_u64 ^ a ^ a, 0x2222);
    }

    fn call_mask_sample() -> u64 {
        crate::vm::l12::call_slot_mask(0x4C31, 0)
    }

    #[test]
    fn stack_encrypt_hides_data_slot_and_alu_roundtrips() {
        let seed = 0x4C31_u64;
        let map = OpcodeMap::from_seed(seed);
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 0, 42);
        push_op(&mut bc, &map, OpCode::Push, 0);
        push_load(&mut bc, &map, 1, 7);
        push_op(&mut bc, &map, OpCode::Exit, 1);
        let mut vm = VirtualMachine::with_opcode_map(bc, map)
            .with_isa_mode(IsaMode::Stack)
            .with_stack_encrypt(seed);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(7));
        let raw = vm.data_stack_word(0).unwrap();
        assert_ne!(raw, 42);
        assert_eq!(raw ^ data_slot_mask(seed, 0), 42);

        let map = OpcodeMap::from_seed(seed);
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 0, 3);
        push_op(&mut bc, &map, OpCode::Push, 0);
        push_load(&mut bc, &map, 0, 4);
        push_op(&mut bc, &map, OpCode::Push, 0);
        push_op(&mut bc, &map, OpCode::Add, 1);
        push_op(&mut bc, &map, OpCode::Exit, 1);
        let mut vm = VirtualMachine::with_opcode_map(bc, map)
            .with_isa_mode(IsaMode::Stack)
            .with_stack_encrypt(seed);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(7));
        assert_eq!(vm.data_stack_word(0).unwrap() ^ data_slot_mask(seed, 0), 3);
        assert_eq!(vm.data_stack_word(1).unwrap() ^ data_slot_mask(seed, 1), 4);

        let map = OpcodeMap::from_seed(seed);
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 0, 5);
        push_op(&mut bc, &map, OpCode::Push, 0);
        push_load(&mut bc, &map, 1, 9);
        push_op(&mut bc, &map, OpCode::Exit, 1);
        let mut vm = VirtualMachine::with_opcode_map(bc, map).with_stack_encrypt(seed);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(9));
        assert_eq!(vm.call_stack_word(0), Some(5));
        assert_eq!(vm.data_stack_word(0), None);
    }
}
