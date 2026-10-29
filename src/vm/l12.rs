//! L12 call-stack return encryption.
//!
//! A `call` stores the return bytecode index (and, with a block map, the
//! caller block id) in the VM call stack. That qword is a direct map of the
//! virtual program counter. This pass XORs the record with a per-depth key
//! before the store. `ret` reverses it. Register `push`/`pop` and the stack
//! ISA data stack stay plaintext; they do not share this slot.

const RET_STACK_SALT: u64 = 0x5245_5453_544B_4C31; // "RETSTKL1"
/// Zero-extended multiplier. Matches `mov ecx, 0x9E3779B9` in the stub.
pub const CALL_SLOT_GOLDEN: u64 = 0x9E37_79B9;

fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

pub fn call_slot_key64(seed: u64) -> u64 {
    splitmix64(seed ^ RET_STACK_SALT)
}

/// Idempotent mask for the call-stack record written at `depth`.
pub fn call_slot_mask(seed: u64, depth: u64) -> u64 {
    let mixed = depth.wrapping_mul(CALL_SLOT_GOLDEN) ^ call_slot_key64(seed);
    mixed ^ (mixed >> 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::machine::VirtualMachine;
    use crate::vm::opcode_map::OpcodeMap;
    use crate::vm::OpCode;

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
    fn call_slot_mask_depends_on_depth() {
        let seed = 0x4C31_u64;
        let a = call_slot_mask(seed, 0);
        let b = call_slot_mask(seed, 1);
        assert_ne!(a, b);
        assert_eq!(0x1111_u64 ^ a ^ a, 0x1111);
    }

    #[test]
    fn ret_encrypt_hides_return_index_and_nested_call_returns() {
        let seed = 0x4C31_u64;
        let map = OpcodeMap::from_seed(seed);
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 0, 1);
        bc.push(map.encode(OpCode::Call));
        let call_imm = bc.len();
        bc.extend_from_slice(&0u64.to_le_bytes());
        let landing = bc.len();
        push_exit(&mut bc, &map, 0);
        let callee = bc.len();
        bc[call_imm..call_imm + 8].copy_from_slice(&(callee as u64).to_le_bytes());
        push_exit(&mut bc, &map, 0);
        let mut vm = VirtualMachine::with_opcode_map(bc, map).with_ret_encrypt(seed);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(1));
        let raw = vm.call_stack_word(0).unwrap();
        assert_ne!(raw, landing as u64);
        assert_eq!(raw ^ call_slot_mask(seed, 0), landing as u64);

        let map = OpcodeMap::from_seed(seed);
        let mut bc = Vec::new();
        push_load(&mut bc, &map, 0, 1);
        bc.push(map.encode(OpCode::Call));
        let outer_imm = bc.len();
        bc.extend_from_slice(&0u64.to_le_bytes());
        push_exit(&mut bc, &map, 0);
        let func_a = bc.len();
        bc[outer_imm..outer_imm + 8].copy_from_slice(&(func_a as u64).to_le_bytes());
        push_load(&mut bc, &map, 0, 3);
        bc.push(map.encode(OpCode::Call));
        let inner_imm = bc.len();
        bc.extend_from_slice(&0u64.to_le_bytes());
        bc.push(map.encode(OpCode::Ret));
        let func_b = bc.len();
        bc[inner_imm..inner_imm + 8].copy_from_slice(&(func_b as u64).to_le_bytes());
        push_load(&mut bc, &map, 0, 9);
        bc.push(map.encode(OpCode::Ret));
        let mut vm = VirtualMachine::with_opcode_map(bc, map).with_ret_encrypt(seed);
        vm.run().unwrap();
        assert_eq!(vm.exit_code, Some(9));
    }
}
