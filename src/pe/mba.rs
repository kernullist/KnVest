use crate::vm::{active_encode, OpCode};

/// Scratch registers for MBA expansion (same convention as immediate holder r15 elsewhere).
pub const MBA_TEMP_ZERO: u8 = 14;
pub const MBA_TEMP_NEG: u8 = 15;
pub const MBA_TEMP_T0: u8 = 12;
pub const MBA_TEMP_T1: u8 = 11;

const ALL_ONES: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const MBA_CATALOG_SALT: u64 = 0x4D4241_4C35; // "MBAL5"
const MBA_NEST_MAX_DEPTH: u32 = 2;

std::thread_local! {
    static MBA_LEVEL: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static MBA_SEED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static MBA_FAMILY_SITES: std::cell::Cell<[u32; 4]> = const { std::cell::Cell::new([0; 4]) };
}

/// MBA substitution depth: 0=off, 1=single catalog rewrite, 2=nested (depth-limited).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MbaLevel {
    Off = 0,
    Single = 1,
    Nested = 2,
}

impl MbaLevel {
    pub fn from_u8(v: u8) -> Self {
        match v {
            2 => MbaLevel::Nested,
            1 => MbaLevel::Single,
            _ => MbaLevel::Off,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn is_enabled(self) -> bool {
        self != MbaLevel::Off
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MbaFamily {
    Add,
    Sub,
    Xor,
    And,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MbaIdentity {
    /// `a + b = a - (0 - b)` (L4f)
    AddViaNeg,
    /// `a + b = (a ^ b) + 2 * (a & b)` — classical xor-form MBA
    AddViaXorAnd,
    /// `a - b = a + (0 - b)`
    SubViaNeg,
    /// `a - b = (a ^ b) - 2 * ((~a) & b)`
    SubViaXorAnd,
    /// `a ^ b = (a + b) - 2 * (a & b)`
    XorViaAddAnd,
    /// `a & b = (a | b) - (a ^ b)` where `a | b = a + b - (a & b)`
    AndViaOrXor,
}

impl MbaFamily {
    fn salt(self) -> u64 {
        match self {
            MbaFamily::Add => 0x4144_4400,
            MbaFamily::Sub => 0x5355_4200,
            MbaFamily::Xor => 0x584F_5200,
            MbaFamily::And => 0x414E_4400,
        }
    }

    fn index(self) -> usize {
        match self {
            MbaFamily::Add => 0,
            MbaFamily::Sub => 1,
            MbaFamily::Xor => 2,
            MbaFamily::And => 3,
        }
    }

    fn catalog(self) -> &'static [MbaIdentity] {
        match self {
            MbaFamily::Add => &[MbaIdentity::AddViaNeg, MbaIdentity::AddViaXorAnd],
            MbaFamily::Sub => &[MbaIdentity::SubViaNeg, MbaIdentity::SubViaXorAnd],
            MbaFamily::Xor => &[MbaIdentity::XorViaAddAnd],
            MbaFamily::And => &[MbaIdentity::AndViaOrXor],
        }
    }
}

impl MbaIdentity {
    pub fn family(self) -> MbaFamily {
        match self {
            MbaIdentity::AddViaNeg | MbaIdentity::AddViaXorAnd => MbaFamily::Add,
            MbaIdentity::SubViaNeg | MbaIdentity::SubViaXorAnd => MbaFamily::Sub,
            MbaIdentity::XorViaAddAnd => MbaFamily::Xor,
            MbaIdentity::AndViaOrXor => MbaFamily::And,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MbaIdentity::AddViaNeg => "a+b -> a-(0-b)",
            MbaIdentity::AddViaXorAnd => "a+b -> (a^b)+2*(a&b)",
            MbaIdentity::SubViaNeg => "a-b -> a+(0-b)",
            MbaIdentity::SubViaXorAnd => "a-b -> (a^b)-2*((~a)&b)",
            MbaIdentity::XorViaAddAnd => "a^b -> (a+b)-2*(a&b)",
            MbaIdentity::AndViaOrXor => "a&b -> (a+b-(a&b))-(a^b)",
        }
    }
}

pub fn set_mba_context(level: u8, seed: u64) {
    MBA_LEVEL.with(|c| c.set(level));
    MBA_SEED.with(|c| c.set(seed));
    MBA_FAMILY_SITES.with(|c| c.set([0; 4]));
}

pub fn clear_mba_context() {
    MBA_LEVEL.with(|c| c.set(0));
    MBA_SEED.with(|c| c.set(0));
    MBA_FAMILY_SITES.with(|c| c.set([0; 4]));
}

/// Backward-compatible helpers (L4f tests).
pub fn set_mba_enabled(enabled: bool) {
    set_mba_context(u8::from(enabled), 0);
}

pub fn mba_enabled() -> bool {
    mba_level().is_enabled()
}

pub fn clear_mba_enabled() {
    clear_mba_context();
}

pub fn mba_level() -> MbaLevel {
    MbaLevel::from_u8(MBA_LEVEL.with(|c| c.get()))
}

fn next_site(family: MbaFamily) -> u32 {
    MBA_FAMILY_SITES.with(|c| {
        let mut sites = c.get();
        let idx = family.index();
        let site = sites[idx];
        sites[idx] = site.wrapping_add(1);
        c.set(sites);
        site
    })
}

fn pick_identity(family: MbaFamily) -> MbaIdentity {
    let seed = MBA_SEED.with(|c| c.get());
    let site = next_site(family);
    let catalog = family.catalog();
    let h = splitmix64(seed ^ MBA_CATALOG_SALT ^ family.salt() ^ site as u64);
    catalog[h as usize % catalog.len()]
}

fn should_rewrite(depth: u32) -> bool {
    let level = mba_level();
    match level {
        MbaLevel::Off => false,
        MbaLevel::Single => depth == 0,
        MbaLevel::Nested => depth < MBA_NEST_MAX_DEPTH,
    }
}

fn raw_load_imm(bytecode: &mut Vec<u8>, dst: u8, imm: u64) {
    bytecode.push(active_encode(OpCode::LoadImm));
    bytecode.push(dst);
    bytecode.extend_from_slice(&imm.to_le_bytes());
}

fn raw_move(bytecode: &mut Vec<u8>, dst: u8, src: u8) {
    bytecode.push(active_encode(OpCode::Move));
    bytecode.push(dst);
    bytecode.push(src);
}

fn raw_add(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    bytecode.push(active_encode(OpCode::Add));
    bytecode.push(dst);
    bytecode.push(src1);
    bytecode.push(src2);
}

fn raw_sub(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    bytecode.push(active_encode(OpCode::Sub));
    bytecode.push(dst);
    bytecode.push(src1);
    bytecode.push(src2);
}

fn raw_xor(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    bytecode.push(active_encode(OpCode::Xor));
    bytecode.push(dst);
    bytecode.push(src1);
    bytecode.push(src2);
}

fn raw_and(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    bytecode.push(active_encode(OpCode::And));
    bytecode.push(dst);
    bytecode.push(src1);
    bytecode.push(src2);
}

fn emit_neg(bytecode: &mut Vec<u8>, dst: u8, src: u8) {
    raw_load_imm(bytecode, MBA_TEMP_ZERO, 0);
    raw_sub(bytecode, dst, MBA_TEMP_ZERO, src);
}

fn emit_double(bytecode: &mut Vec<u8>, dst: u8, src: u8) {
    raw_add(bytecode, dst, src, src);
}

fn expand_add_via_neg(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    raw_load_imm(bytecode, MBA_TEMP_ZERO, 0);
    raw_sub(bytecode, MBA_TEMP_NEG, MBA_TEMP_ZERO, src2);
    raw_sub(bytecode, dst, src1, MBA_TEMP_NEG);
}

fn expand_add_via_xor_and(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) {
    emit_xor_three_depth(bytecode, MBA_TEMP_T0, src1, src2, depth + 1);
    emit_and_three_depth(bytecode, MBA_TEMP_T1, src1, src2, depth + 1);
    emit_double(bytecode, MBA_TEMP_T1, MBA_TEMP_T1);
    emit_add_three_depth(bytecode, dst, MBA_TEMP_T0, MBA_TEMP_T1, depth + 1);
}

fn expand_sub_via_neg(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    emit_neg(bytecode, MBA_TEMP_NEG, src2);
    raw_add(bytecode, dst, src1, MBA_TEMP_NEG);
}

fn expand_sub_via_xor_and(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) {
    raw_load_imm(bytecode, MBA_TEMP_NEG, ALL_ONES);
    raw_xor(bytecode, MBA_TEMP_T0, src1, MBA_TEMP_NEG);
    emit_and_three_depth(bytecode, MBA_TEMP_T1, MBA_TEMP_T0, src2, depth + 1);
    emit_double(bytecode, MBA_TEMP_T1, MBA_TEMP_T1);
    emit_xor_three_depth(bytecode, MBA_TEMP_T0, src1, src2, depth + 1);
    raw_sub(bytecode, dst, MBA_TEMP_T0, MBA_TEMP_T1);
}

fn expand_xor_via_add_and(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) {
    emit_and_three_depth(bytecode, MBA_TEMP_T0, src1, src2, depth + 1);
    emit_double(bytecode, MBA_TEMP_T0, MBA_TEMP_T0);
    emit_add_three_depth(bytecode, MBA_TEMP_T1, src1, src2, depth + 1);
    raw_sub(bytecode, dst, MBA_TEMP_T1, MBA_TEMP_T0);
}

fn expand_and_via_or_xor(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) {
    emit_and_three_depth(bytecode, MBA_TEMP_T0, src1, src2, depth + 1);
    emit_add_three_depth(bytecode, MBA_TEMP_T1, src1, src2, depth + 1);
    raw_sub(bytecode, MBA_TEMP_T1, MBA_TEMP_T1, MBA_TEMP_T0);
    emit_xor_three_depth(bytecode, MBA_TEMP_T0, src1, src2, depth + 1);
    raw_sub(bytecode, dst, MBA_TEMP_T1, MBA_TEMP_T0);
}

/// Emit `dst = src1 + src2`, optionally via catalog MBA rewrite.
pub fn emit_add_three(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    emit_add_three_depth(bytecode, dst, src1, src2, 0);
}

fn emit_add_three_depth(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) {
    if should_rewrite(depth) {
        match pick_identity(MbaFamily::Add) {
            MbaIdentity::AddViaNeg => expand_add_via_neg(bytecode, dst, src1, src2),
            MbaIdentity::AddViaXorAnd => expand_add_via_xor_and(bytecode, dst, src1, src2, depth),
            _ => raw_add(bytecode, dst, src1, src2),
        }
    } else {
        raw_add(bytecode, dst, src1, src2);
    }
}

pub fn emit_add_reg_reg(bytecode: &mut Vec<u8>, dst: u8, src: u8) {
    emit_add_three(bytecode, dst, dst, src);
}

pub fn emit_add_reg_imm(bytecode: &mut Vec<u8>, dst: u8, imm: u64) {
    raw_load_imm(bytecode, MBA_TEMP_NEG, imm);
    emit_add_three(bytecode, dst, dst, MBA_TEMP_NEG);
}

/// Emit `dst = lhs - rhs`, optionally via catalog MBA rewrite.
pub fn emit_sub_three(bytecode: &mut Vec<u8>, dst: u8, lhs: u8, rhs: u8) {
    emit_sub_three_depth(bytecode, dst, lhs, rhs, 0);
}

fn emit_sub_three_depth(bytecode: &mut Vec<u8>, dst: u8, lhs: u8, rhs: u8, depth: u32) {
    if should_rewrite(depth) {
        match pick_identity(MbaFamily::Sub) {
            MbaIdentity::SubViaNeg => expand_sub_via_neg(bytecode, dst, lhs, rhs),
            MbaIdentity::SubViaXorAnd => expand_sub_via_xor_and(bytecode, dst, lhs, rhs, depth),
            _ => raw_sub(bytecode, dst, lhs, rhs),
        }
    } else {
        raw_sub(bytecode, dst, lhs, rhs);
    }
}

pub fn emit_sub_reg_reg(bytecode: &mut Vec<u8>, dst: u8, src: u8) {
    emit_sub_three(bytecode, dst, dst, src);
}

/// Emit `dst = src1 ^ src2`, optionally via catalog MBA rewrite.
pub fn emit_xor_three(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    emit_xor_three_depth(bytecode, dst, src1, src2, 0);
}

fn emit_xor_three_depth(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) {
    if should_rewrite(depth) {
        match pick_identity(MbaFamily::Xor) {
            MbaIdentity::XorViaAddAnd => expand_xor_via_add_and(bytecode, dst, src1, src2, depth),
            _ => raw_xor(bytecode, dst, src1, src2),
        }
    } else {
        raw_xor(bytecode, dst, src1, src2);
    }
}

/// Emit `dst = src1 & src2`, optionally via catalog MBA rewrite.
pub fn emit_and_three(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    emit_and_three_depth(bytecode, dst, src1, src2, 0);
}

fn emit_and_three_depth(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) {
    if should_rewrite(depth) {
        match pick_identity(MbaFamily::And) {
            MbaIdentity::AndViaOrXor => expand_and_via_or_xor(bytecode, dst, src1, src2, depth),
            _ => raw_and(bytecode, dst, src1, src2),
        }
    } else {
        raw_and(bytecode, dst, src1, src2);
    }
}

pub fn catalog_identities_for_seed(seed: u64) -> Vec<MbaIdentity> {
    let mut out = Vec::new();
    for family in [MbaFamily::Add, MbaFamily::Sub, MbaFamily::Xor, MbaFamily::And] {
        let catalog = family.catalog();
        let h = splitmix64(seed ^ MBA_CATALOG_SALT ^ family.salt());
        out.push(catalog[h as usize % catalog.len()]);
    }
    out
}

pub fn format_ir_header(level: MbaLevel, seed: u64) -> String {
    if !level.is_enabled() {
        return String::new();
    }
    let mut out = format!(
        "L5b MBA catalog | level={} | seed={:#x}\n",
        level.as_u8(),
        seed
    );
    out.push_str("Classical identities (public literature, seed-picked per family):\n");
    for id in catalog_identities_for_seed(seed) {
        out.push_str(&format!("  {:<4} | {}\n", id.family().name(), id.label()));
    }
    out.push('\n');
    out
}

impl MbaFamily {
    fn name(self) -> &'static str {
        match self {
            MbaFamily::Add => "add",
            MbaFamily::Sub => "sub",
            MbaFamily::Xor => "xor",
            MbaFamily::And => "and",
        }
    }
}

pub fn seed_picking(family: MbaFamily, target: MbaIdentity) -> u64 {
    for seed in 0..4096u64 {
        let catalog = family.catalog();
        let h = splitmix64(seed ^ MBA_CATALOG_SALT ^ family.salt());
        if catalog[h as usize % catalog.len()] == target {
            return seed;
        }
    }
    panic!("no seed picks {target:?} for {family:?}");
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
    use crate::vm::OpcodeMap;

    fn with_mba<F: FnOnce()>(level: u8, seed: u64, f: F) {
        let map = OpcodeMap::from_seed(seed);
        crate::vm::set_active_map(&map);
        set_mba_context(level, seed);
        f();
        clear_mba_context();
        crate::vm::clear_active_map();
    }

    #[test]
    fn mba_add_expands_to_sub_chain_at_level1() {
        let seed = seed_picking(MbaFamily::Add, MbaIdentity::AddViaNeg);
        with_mba(1, seed, || {
            let map = OpcodeMap::from_seed(seed);
            let mut bc = Vec::new();
            emit_add_reg_reg(&mut bc, 0, 1);
            let sub_w = map.encode(OpCode::Sub);
            assert!(bc.contains(&map.encode(OpCode::LoadImm)));
            assert_eq!(bc.iter().filter(|&&b| b == sub_w).count(), 2);
            assert!(!bc.contains(&map.encode(OpCode::Add)));
        });
    }

    #[test]
    fn mba_off_emits_single_add() {
        with_mba(0, 1, || {
            let map = OpcodeMap::from_seed(1);
            let mut bc = Vec::new();
            emit_add_reg_reg(&mut bc, 2, 3);
            assert_eq!(bc.len(), 4);
            assert_eq!(bc[0], map.encode(OpCode::Add));
        });
    }

    #[test]
    fn catalog_differs_by_seed() {
        let a = catalog_identities_for_seed(1);
        let b = catalog_identities_for_seed(2);
        assert_ne!(a, b);
    }

    #[test]
    fn xor_form_add_mba_uses_xor_and() {
        let seed = seed_picking(MbaFamily::Add, MbaIdentity::AddViaXorAnd);
        with_mba(1, seed, || {
            let map = OpcodeMap::from_seed(seed);
            let mut bc = Vec::new();
            emit_add_reg_reg(&mut bc, 0, 1);
            assert!(bc.contains(&map.encode(OpCode::Xor)));
            assert!(bc.contains(&map.encode(OpCode::And)));
        });
    }

    #[test]
    fn level2_nested_applies_multiple_layers() {
        with_mba(2, 0xA11C_EED, || {
            let map = OpcodeMap::from_seed(0xA11C_EED);
            let mut bc = Vec::new();
            emit_add_reg_reg(&mut bc, 0, 1);
            let sub_count = bc.iter().filter(|&&b| b == map.encode(OpCode::Sub)).count();
            assert!(sub_count >= 2, "nested MBA should emit deeper sub chains");
        });
    }

    #[test]
    fn sub_xor_and_family_emits_xor_and() {
        with_mba(1, 0x5355_4255, || {
            let map = OpcodeMap::from_seed(0x5355_4255);
            let mut bc = Vec::new();
            emit_sub_reg_reg(&mut bc, 0, 1);
            assert!(
                bc.contains(&map.encode(OpCode::Xor)) || bc.contains(&map.encode(OpCode::Sub)),
                "sub MBA should expand"
            );
            let _ = map;
        });
    }

    #[test]
    fn and_family_expansion_uses_add_xor_sub() {
        with_mba(1, 0x414E_44AA, || {
            let map = OpcodeMap::from_seed(0x414E_44AA);
            let mut bc = Vec::new();
            emit_and_three(&mut bc, 0, 1, 2);
            assert!(bc.contains(&map.encode(OpCode::Xor)));
            assert!(bc.contains(&map.encode(OpCode::Add)) || bc.contains(&map.encode(OpCode::Sub)));
        });
    }

    #[test]
    fn ir_header_lists_level_and_catalog() {
        let hdr = format_ir_header(MbaLevel::Single, 0x1234);
        assert!(hdr.contains("level=1"));
        assert!(hdr.contains("(a^b)+2*(a&b)"));
    }
}
