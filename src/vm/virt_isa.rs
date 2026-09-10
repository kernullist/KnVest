use super::opcode_map::handler_variant_count;
use super::opcode::OpCode;
use super::OpcodeMap;
use super::{active_encode, current_isa_mode, DispatchMode, IsaMode};
use crate::pe::mba;

/// Scratch register for L5a lift-time sub split (not used by MBA temps r14/r15).
pub const VIRT_ISA_SPLIT_TEMP: u8 = 13;

const SUB_SPLIT_SALT: u64 = 0x53504954; // "SPIT" — split lift encoding salt

/// When true, `sub dst, dst, src` lifts as `move temp,dst; sub dst,temp,src`.
pub fn sub_lift_split_enabled(seed: u64) -> bool {
    splitmix64(seed ^ SUB_SPLIT_SALT) % 2 == 1
}

pub fn emit_sub_three(bytecode: &mut Vec<u8>, dst: u8, lhs: u8, rhs: u8, seed: u64) {
    if mba::mba_level().is_enabled() {
        if sub_lift_split_enabled(seed) && lhs == dst {
            bytecode.push(active_encode(OpCode::Move));
            bytecode.push(VIRT_ISA_SPLIT_TEMP);
            bytecode.push(lhs);
            mba::emit_sub_three(bytecode, dst, VIRT_ISA_SPLIT_TEMP, rhs);
        } else {
            mba::emit_sub_three(bytecode, dst, lhs, rhs);
        }
        return;
    }
    if current_isa_mode() == IsaMode::Stack {
        if sub_lift_split_enabled(seed) && lhs == dst {
            bytecode.push(active_encode(OpCode::Move));
            bytecode.push(VIRT_ISA_SPLIT_TEMP);
            bytecode.push(lhs);
            bytecode.push(active_encode(OpCode::Push));
            bytecode.push(VIRT_ISA_SPLIT_TEMP);
            bytecode.push(active_encode(OpCode::Push));
            bytecode.push(rhs);
            bytecode.push(active_encode(OpCode::Sub));
            bytecode.push(dst);
        } else {
            bytecode.push(active_encode(OpCode::Push));
            bytecode.push(lhs);
            bytecode.push(active_encode(OpCode::Push));
            bytecode.push(rhs);
            bytecode.push(active_encode(OpCode::Sub));
            bytecode.push(dst);
        }
        return;
    }
    if sub_lift_split_enabled(seed) {
        bytecode.push(active_encode(OpCode::Move));
        bytecode.push(VIRT_ISA_SPLIT_TEMP);
        bytecode.push(lhs);
        bytecode.push(active_encode(OpCode::Sub));
        bytecode.push(dst);
        bytecode.push(VIRT_ISA_SPLIT_TEMP);
        bytecode.push(rhs);
    } else {
        bytecode.push(active_encode(OpCode::Sub));
        bytecode.push(dst);
        bytecode.push(lhs);
        bytecode.push(rhs);
    }
}

pub fn emit_sub_reg_reg(bytecode: &mut Vec<u8>, dst: u8, src: u8, seed: u64) {
    emit_sub_three(bytecode, dst, dst, src, seed);
}

pub fn format_ir_header(map: &OpcodeMap, dispatch_mode: DispatchMode) -> String {
    let seed = map.seed();
    let mut out = String::new();
    out.push_str(&format!(
        "L5a virtual ISA | seed={:#x} | dispatch={} | sub_lift={}\n",
        seed,
        dispatch_mode,
        if sub_lift_split_enabled(seed) {
            "split"
        } else {
            "direct"
        }
    ));
    out.push_str("ALU handler variants (stub bodies, seed-derived):\n");
    for &op in &[OpCode::Add, OpCode::Sub, OpCode::Xor, OpCode::And] {
        let count = handler_variant_count(op);
        let variant = map.handler_variant(op);
        let wire = map.encode(op);
        out.push_str(&format!(
            "  {:<4} wire={:#04x} variant={}/{} ({} native bodies)\n",
            op.name(),
            wire,
            variant,
            count.saturating_sub(1),
            count
        ));
    }
    out.push_str("Lift-time patterns:\n");
    out.push_str("  merge | x86 xor/test r,r → load_imm r,0 (+ cmp r,0 for test)\n");
    out.push_str("  split | x86 sub r,d → move r13,r ; sub r,r13,d (when sub_lift=split)\n");
    out.push('\n');
    out
}

pub fn seed_for_handler_variant(op: OpCode, target: u8) -> u64 {
    for seed in 0..2048u64 {
        if OpcodeMap::from_seed(seed).handler_variant(op) == target {
            return seed;
        }
    }
    panic!("no seed yields {} handler variant {target}", op.name());
}

pub fn seed_for_sub_split(enabled: bool) -> u64 {
    for seed in 0..2048u64 {
        if sub_lift_split_enabled(seed) == enabled {
            return seed;
        }
    }
    panic!("no seed yields sub_lift_split={enabled}");
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_split_encoding_varies_by_seed() {
        let direct = seed_for_sub_split(false);
        let split = seed_for_sub_split(true);
        assert_ne!(direct, split);
        assert!(!sub_lift_split_enabled(direct));
        assert!(sub_lift_split_enabled(split));
    }

    #[test]
    fn alu_handler_variants_cover_multiple_indices() {
        for &op in &[OpCode::Sub, OpCode::Xor, OpCode::And] {
            let count = handler_variant_count(op) as usize;
            assert!(count >= 2, "{} needs >=2 variants", op.name());
            let mut seen = vec![false; count];
            for seed in 0..128u64 {
                let v = OpcodeMap::from_seed(seed).handler_variant(op) as usize;
                seen[v] = true;
            }
            assert!(
                seen.iter().filter(|&&v| v).count() >= 2,
                "{} variants not covered in seeds 0..128",
                op.name()
            );
        }
    }

    #[test]
    fn ir_header_lists_wire_and_variant() {
        let map = OpcodeMap::from_seed(0x15A_2026);
        let hdr = format_ir_header(&map, DispatchMode::Table);
        assert!(hdr.contains("L5a virtual ISA"));
        assert!(hdr.contains("wire="));
        assert!(hdr.contains("sub_lift="));
        assert!(hdr.contains(&format!("variant={}/", map.handler_variant(OpCode::Add))));
    }
}
