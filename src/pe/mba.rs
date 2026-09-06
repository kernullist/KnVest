use crate::vm::{active_encode, OpCode};

/// Scratch registers for MBA expansion (same convention as immediate holder r15 elsewhere).
pub const MBA_TEMP_ZERO: u8 = 14;
pub const MBA_TEMP_NEG: u8 = 15;

std::thread_local! {
    static MBA_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn set_mba_enabled(enabled: bool) {
    MBA_ENABLED.with(|c| c.set(enabled));
}

pub fn mba_enabled() -> bool {
    MBA_ENABLED.with(|c| c.get())
}

pub fn clear_mba_enabled() {
    MBA_ENABLED.with(|c| c.set(false));
}

/// Emit `dst = src1 + src2`, optionally as `src1 - (0 - src2)` (equivalent integer add).
pub fn emit_add_three(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    if mba_enabled() {
        bytecode.push(active_encode(OpCode::LoadImm));
        bytecode.push(MBA_TEMP_ZERO);
        bytecode.extend_from_slice(&0u64.to_le_bytes());
        bytecode.push(active_encode(OpCode::Sub));
        bytecode.push(MBA_TEMP_NEG);
        bytecode.push(MBA_TEMP_ZERO);
        bytecode.push(src2);
        bytecode.push(active_encode(OpCode::Sub));
        bytecode.push(dst);
        bytecode.push(src1);
        bytecode.push(MBA_TEMP_NEG);
    } else {
        bytecode.push(active_encode(OpCode::Add));
        bytecode.push(dst);
        bytecode.push(src1);
        bytecode.push(src2);
    }
}

pub fn emit_add_reg_reg(bytecode: &mut Vec<u8>, dst: u8, src: u8) {
    emit_add_three(bytecode, dst, dst, src);
}

pub fn emit_add_reg_imm(bytecode: &mut Vec<u8>, dst: u8, imm: u64) {
    bytecode.push(active_encode(OpCode::LoadImm));
    bytecode.push(MBA_TEMP_NEG);
    bytecode.extend_from_slice(&imm.to_le_bytes());
    emit_add_three(bytecode, dst, dst, MBA_TEMP_NEG);
}

pub fn format_ir_header(enabled: bool) -> String {
    if !enabled {
        return String::new();
    }
    format!(
        "L4f MBA substitution | enabled=yes | rule: a+b -> a-(0-b)  (algebraic add via negation)\n\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::OpcodeMap;

    #[test]
    fn mba_add_expands_to_sub_chain() {
        let map = OpcodeMap::from_seed(0x4D4241);
        crate::vm::set_active_map(&map);
        set_mba_enabled(true);
        let mut bc = Vec::new();
        emit_add_reg_reg(&mut bc, 0, 1);
        clear_mba_enabled();
        crate::vm::clear_active_map();

        let sub_w = map.encode(OpCode::Sub);
        assert!(bc.contains(&map.encode(OpCode::LoadImm)));
        assert_eq!(bc.iter().filter(|&&b| b == sub_w).count(), 2);
        assert!(!bc.contains(&map.encode(OpCode::Add)));
    }

    #[test]
    fn mba_off_emits_single_add() {
        let map = OpcodeMap::from_seed(1);
        crate::vm::set_active_map(&map);
        set_mba_enabled(false);
        let mut bc = Vec::new();
        emit_add_reg_reg(&mut bc, 2, 3);
        crate::vm::clear_active_map();

        assert_eq!(bc.len(), 4);
        assert_eq!(bc[0], map.encode(OpCode::Add));
    }
}
