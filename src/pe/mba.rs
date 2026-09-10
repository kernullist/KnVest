use crate::vm::{active_encode, current_isa_mode, IsaMode, OpCode};

/// Legacy IR annotation anchors (L4f); runtime temps are allocated dynamically.
pub const MBA_TEMP_ZERO: u8 = 14;
pub const MBA_TEMP_NEG: u8 = 15;
pub const MBA_TEMP_T0: u8 = 12;
pub const MBA_TEMP_T1: u8 = 11;

const ALL_ONES: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const MBA_CATALOG_SALT: u64 = 0x4D4241_4C35; // "MBAL5"
const MBA_NEST_MAX_DEPTH: u32 = 2;
const MBA_POOL: [u8; 3] = [8, 9, 14];

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
    if dst == src {
        return;
    }
    bytecode.push(active_encode(OpCode::Move));
    bytecode.push(dst);
    bytecode.push(src);
}

fn emit_stack_push(bytecode: &mut Vec<u8>, reg: u8) {
    bytecode.push(active_encode(OpCode::Push));
    bytecode.push(reg);
}

fn raw_add(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    if current_isa_mode() == IsaMode::Stack {
        emit_stack_push(bytecode, src1);
        emit_stack_push(bytecode, src2);
        bytecode.push(active_encode(OpCode::Add));
        bytecode.push(dst);
        return;
    }
    bytecode.push(active_encode(OpCode::Add));
    bytecode.push(dst);
    bytecode.push(src1);
    bytecode.push(src2);
}

fn raw_sub(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    if current_isa_mode() == IsaMode::Stack {
        emit_stack_push(bytecode, src1);
        emit_stack_push(bytecode, src2);
        bytecode.push(active_encode(OpCode::Sub));
        bytecode.push(dst);
        return;
    }
    bytecode.push(active_encode(OpCode::Sub));
    bytecode.push(dst);
    bytecode.push(src1);
    bytecode.push(src2);
}

fn raw_mul(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    if current_isa_mode() == IsaMode::Stack {
        emit_stack_push(bytecode, src1);
        emit_stack_push(bytecode, src2);
        bytecode.push(active_encode(OpCode::Mul));
        bytecode.push(dst);
        return;
    }
    bytecode.push(active_encode(OpCode::Mul));
    bytecode.push(dst);
    bytecode.push(src1);
    bytecode.push(src2);
}

fn raw_xor(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    if current_isa_mode() == IsaMode::Stack {
        emit_stack_push(bytecode, src1);
        emit_stack_push(bytecode, src2);
        bytecode.push(active_encode(OpCode::Xor));
        bytecode.push(dst);
        return;
    }
    bytecode.push(active_encode(OpCode::Xor));
    bytecode.push(dst);
    bytecode.push(src1);
    bytecode.push(src2);
}

fn raw_and(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    if current_isa_mode() == IsaMode::Stack {
        emit_stack_push(bytecode, src1);
        emit_stack_push(bytecode, src2);
        bytecode.push(active_encode(OpCode::And));
        bytecode.push(dst);
        return;
    }
    bytecode.push(active_encode(OpCode::And));
    bytecode.push(dst);
    bytecode.push(src1);
    bytecode.push(src2);
}

/// Emit compare of two VM registers (Cmp or Cmp32).
pub fn emit_cmp_regs(bytecode: &mut Vec<u8>, op: OpCode, src1: u8, src2: u8) {
    if current_isa_mode() == IsaMode::Stack {
        emit_stack_push(bytecode, src1);
        emit_stack_push(bytecode, src2);
        bytecode.push(active_encode(op));
        return;
    }
    bytecode.push(active_encode(op));
    bytecode.push(src1);
    bytecode.push(src2);
}

/// Emit `dst = src1 * src2` (lift helper for imul).
pub fn emit_mul_three(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    raw_mul(bytecode, dst, src1, src2);
}

fn temps_excluding(count: usize, exclude: &[u8]) -> Vec<u8> {
    MBA_POOL
        .iter()
        .copied()
        .filter(|r| !exclude.contains(r))
        .take(count)
        .collect()
}

/// Copy operands into scratch that does not overlap `dst` or each other.
/// Uses only dedicated MBA temps (r8/r9/r14), never lifter spill slots r10–r15.
fn materialize_pair(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) -> Option<(u8, u8)> {
    let exclude = [dst, src1, src2];
    let t = temps_excluding(2, &exclude);
    if t.len() < 2 {
        return None;
    }
    raw_move(bytecode, t[0], src1);
    raw_move(bytecode, t[1], src2);
    Some((t[0], t[1]))
}

fn emit_neg_into(bytecode: &mut Vec<u8>, dst: u8, src: u8, exclude: &[u8]) -> bool {
    let t = temps_excluding(2, exclude);
    if t.len() < 2 {
        return false;
    }
    raw_load_imm(bytecode, t[0], 0);
    raw_sub(bytecode, t[1], t[0], src);
    if dst != t[1] {
        raw_move(bytecode, dst, t[1]);
    }
    true
}

fn expand_add_via_neg(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) -> bool {
    let exclude = [dst, src1, src2];
    let t = temps_excluding(2, &exclude);
    if t.len() < 2 {
        return false;
    }
    raw_load_imm(bytecode, t[0], 0);
    raw_sub(bytecode, t[1], t[0], src2);
    raw_sub(bytecode, dst, src1, t[1]);
    true
}

fn expand_add_via_xor_and(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) -> bool {
    let Some((ta, tb)) = materialize_pair(bytecode, dst, src1, src2) else {
        return false;
    };
    let exclude = [dst, ta, tb];
    let t = temps_excluding(1, &exclude);
    if t.is_empty() {
        return false;
    }
    let xor_sum = t[0];
    raw_xor(bytecode, xor_sum, ta, tb);
    raw_and(bytecode, ta, ta, tb);
    raw_add(bytecode, ta, ta, ta);
    if should_rewrite(depth + 1) {
        emit_add_three_depth(bytecode, dst, xor_sum, ta, depth + 1);
    } else {
        raw_add(bytecode, dst, xor_sum, ta);
    }
    true
}

fn expand_sub_via_neg(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) -> bool {
    let exclude = [dst, src1, src2];
    let t = temps_excluding(1, &exclude);
    if t.is_empty() {
        return false;
    }
    let neg = t[0];
    if !emit_neg_into(bytecode, neg, src2, &exclude) {
        return false;
    }
    raw_add(bytecode, dst, src1, neg);
    true
}

fn expand_sub_via_xor_and(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) -> bool {
    let Some((ta, tb)) = materialize_pair(bytecode, dst, src1, src2) else {
        return false;
    };
    let exclude = [dst, ta, tb];
    let t = temps_excluding(3, &exclude);
    if t.len() < 3 {
        return false;
    }
    raw_load_imm(bytecode, t[0], ALL_ONES);
    raw_xor(bytecode, t[1], ta, t[0]);
    if should_rewrite(depth + 1) {
        emit_and_three_depth(bytecode, t[2], t[1], tb, depth + 1);
    } else {
        raw_and(bytecode, t[2], t[1], tb);
    }
    raw_add(bytecode, t[2], t[2], t[2]);
    if should_rewrite(depth + 1) {
        emit_xor_three_depth(bytecode, t[1], ta, tb, depth + 1);
    } else {
        raw_xor(bytecode, t[1], ta, tb);
    }
    raw_sub(bytecode, dst, t[1], t[2]);
    true
}

fn expand_xor_via_add_and(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) -> bool {
    let Some((ta, tb)) = materialize_pair(bytecode, dst, src1, src2) else {
        return false;
    };
    let exclude = [dst, ta, tb];
    let t = temps_excluding(2, &exclude);
    if t.len() < 2 {
        return false;
    }
    if should_rewrite(depth + 1) {
        emit_and_three_depth(bytecode, t[0], ta, tb, depth + 1);
    } else {
        raw_and(bytecode, t[0], ta, tb);
    }
    raw_add(bytecode, t[0], t[0], t[0]);
    if should_rewrite(depth + 1) {
        emit_add_three_depth(bytecode, t[1], ta, tb, depth + 1);
    } else {
        raw_add(bytecode, t[1], ta, tb);
    }
    raw_sub(bytecode, dst, t[1], t[0]);
    true
}

fn expand_and_via_or_xor(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) -> bool {
    let Some((ta, tb)) = materialize_pair(bytecode, dst, src1, src2) else {
        return false;
    };
    let exclude = [dst, ta, tb];
    let t = temps_excluding(2, &exclude);
    if t.len() < 2 {
        return false;
    }
    if should_rewrite(depth + 1) {
        emit_and_three_depth(bytecode, t[0], ta, tb, depth + 1);
    } else {
        raw_and(bytecode, t[0], ta, tb);
    }
    if should_rewrite(depth + 1) {
        emit_add_three_depth(bytecode, t[1], ta, tb, depth + 1);
    } else {
        raw_add(bytecode, t[1], ta, tb);
    }
    raw_sub(bytecode, t[1], t[1], t[0]);
    if should_rewrite(depth + 1) {
        emit_xor_three_depth(bytecode, t[0], ta, tb, depth + 1);
    } else {
        raw_xor(bytecode, t[0], ta, tb);
    }
    raw_sub(bytecode, dst, t[1], t[0]);
    true
}

/// Emit `dst = src1 + src2`, optionally via catalog MBA rewrite.
pub fn emit_add_three(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8) {
    emit_add_three_depth(bytecode, dst, src1, src2, 0);
}

fn emit_add_three_depth(bytecode: &mut Vec<u8>, dst: u8, src1: u8, src2: u8, depth: u32) {
    if should_rewrite(depth) {
        let ok = match pick_identity(MbaFamily::Add) {
            MbaIdentity::AddViaNeg => expand_add_via_neg(bytecode, dst, src1, src2),
            MbaIdentity::AddViaXorAnd => expand_add_via_xor_and(bytecode, dst, src1, src2, depth),
            _ => false,
        };
        if !ok {
            raw_add(bytecode, dst, src1, src2);
        }
    } else {
        raw_add(bytecode, dst, src1, src2);
    }
}

pub fn emit_add_reg_reg(bytecode: &mut Vec<u8>, dst: u8, src: u8) {
    emit_add_three(bytecode, dst, dst, src);
}

pub fn emit_add_reg_imm(bytecode: &mut Vec<u8>, dst: u8, imm: u64) {
    let exclude = [dst];
    let t = temps_excluding(1, &exclude);
    raw_load_imm(bytecode, t[0], imm);
    emit_add_three(bytecode, dst, dst, t[0]);
}

/// Emit `dst = lhs - rhs`, optionally via catalog MBA rewrite.
pub fn emit_sub_three(bytecode: &mut Vec<u8>, dst: u8, lhs: u8, rhs: u8) {
    emit_sub_three_depth(bytecode, dst, lhs, rhs, 0);
}

fn emit_sub_three_depth(bytecode: &mut Vec<u8>, dst: u8, lhs: u8, rhs: u8, depth: u32) {
    if should_rewrite(depth) {
        let ok = match pick_identity(MbaFamily::Sub) {
            MbaIdentity::SubViaNeg => expand_sub_via_neg(bytecode, dst, lhs, rhs),
            MbaIdentity::SubViaXorAnd => expand_sub_via_xor_and(bytecode, dst, lhs, rhs, depth),
            _ => false,
        };
        if !ok {
            raw_sub(bytecode, dst, lhs, rhs);
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
        let ok = match pick_identity(MbaFamily::Xor) {
            MbaIdentity::XorViaAddAnd => expand_xor_via_add_and(bytecode, dst, src1, src2, depth),
            _ => false,
        };
        if !ok {
            raw_xor(bytecode, dst, src1, src2);
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
        let ok = match pick_identity(MbaFamily::And) {
            MbaIdentity::AndViaOrXor => expand_and_via_or_xor(bytecode, dst, src1, src2, depth),
            _ => false,
        };
        if !ok {
            raw_and(bytecode, dst, src1, src2);
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

    fn run_add_bc(bc: &[u8], map: &OpcodeMap) -> u64 {
        use crate::vm::VirtualMachine;
        let mut vm = VirtualMachine::with_opcode_map(bc.to_vec(), map.clone());
        vm.run().unwrap();
        vm.get_register(0).unwrap()
    }

    fn bc_add_via_mba(dst: u8, src1: u8, src2: u8, level: u8, seed: u64) -> (Vec<u8>, OpcodeMap) {
        let map = OpcodeMap::from_seed(seed);
        crate::vm::set_active_map(&map);
        set_mba_context(level, seed);
        let mut bc = Vec::new();
        raw_load_imm(&mut bc, src1, 100);
        raw_load_imm(&mut bc, src2, 30);
        emit_add_three(&mut bc, dst, src1, src2);
        raw_move(&mut bc, 0, dst);
        bc.push(map.encode(OpCode::Exit));
        bc.push(0);
        clear_mba_context();
        crate::vm::clear_active_map();
        (bc, map)
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
    fn mba_xor_and_add_matches_native_add() {
        for seed in [0xAAAA_u64, 0xBBBB, 0xA11C_EED, 1] {
            let (bc, map) = bc_add_via_mba(3, 1, 2, 1, seed);
            assert_eq!(run_add_bc(&bc, &map), 130, "seed {seed:#x}");
            let (bc_overlap, map2) = bc_add_via_mba(11, 11, 12, 1, seed);
            assert_eq!(run_add_bc(&bc_overlap, &map2), 130, "overlap seed {seed:#x}");
        }
    }

    #[test]
    fn mba_level2_nested_matches_native_add() {
        for seed in [0xAAAA_u64, 0xBBBB, 0xA11C_EED] {
            let (bc, map) = bc_add_via_mba(4, 5, 6, 2, seed);
            assert_eq!(run_add_bc(&bc, &map), 130, "nested seed {seed:#x}");
        }
    }

    #[test]
    fn mba_sub_and_and_semantics() {
        use crate::vm::VirtualMachine;
        let seed = 0xBBBB;
        let map = OpcodeMap::from_seed(seed);
        crate::vm::set_active_map(&map);
        set_mba_context(1, seed);
        let mut bc = Vec::new();
        raw_load_imm(&mut bc, 1, 100);
        raw_load_imm(&mut bc, 2, 30);
        emit_sub_three(&mut bc, 0, 1, 2);
        bc.push(map.encode(OpCode::Exit));
        bc.push(0);
        clear_mba_context();
        crate::vm::clear_active_map();
        let mut vm = VirtualMachine::with_opcode_map(bc, map.clone());
        vm.run().unwrap();
        assert_eq!(vm.get_register(0).unwrap(), 70);

        set_mba_context(1, seed);
        crate::vm::set_active_map(&map);
        let mut bc2 = Vec::new();
        raw_load_imm(&mut bc2, 1, 0xF0);
        raw_load_imm(&mut bc2, 2, 0x0F);
        emit_and_three(&mut bc2, 0, 1, 2);
        bc2.push(map.encode(OpCode::Exit));
        bc2.push(0);
        clear_mba_context();
        crate::vm::clear_active_map();
        let mut vm2 = VirtualMachine::with_opcode_map(bc2, map);
        vm2.run().unwrap();
        assert_eq!(vm2.get_register(0).unwrap(), 0x00);
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
    fn ir_header_lists_level_and_catalog() {
        let hdr = format_ir_header(MbaLevel::Single, 0x1234);
        assert!(hdr.contains("level=1"));
        assert!(hdr.contains("(a^b)+2*(a&b)"));
    }

    /// Stack locals live in r8–r15; MBA must not clobber unrelated spill values.
    #[test]
    fn mba_preserves_live_spill_regs_across_xor_form_add() {
        use crate::vm::VirtualMachine;
        let seed = seed_picking(MbaFamily::Add, MbaIdentity::AddViaXorAnd);
        let map = OpcodeMap::from_seed(seed);
        crate::vm::set_active_map(&map);
        set_mba_context(1, seed);
        let mut bc = Vec::new();
        raw_load_imm(&mut bc, 1, 3);
        raw_load_imm(&mut bc, 2, 4);
        raw_load_imm(&mut bc, 11, 5); // live local `c` in spill reg r11
        raw_load_imm(&mut bc, 12, 999); // unrelated spill
        emit_add_three(&mut bc, 3, 1, 2); // (a+b) -> r3
        raw_move(&mut bc, 0, 3);
        bc.push(map.encode(OpCode::Exit));
        bc.push(0);
        clear_mba_context();
        crate::vm::clear_active_map();

        let mut vm = VirtualMachine::with_opcode_map(bc, map);
        vm.run().unwrap();
        assert_eq!(vm.get_register(0).unwrap(), 7);
        assert_eq!(vm.get_register(11).unwrap(), 5, "spill r11 must survive MBA add");
        assert_eq!(vm.get_register(12).unwrap(), 999, "spill r12 must survive MBA add");
    }

    #[test]
    fn mba_preserves_live_spill_regs_across_neg_form_add() {
        use crate::vm::VirtualMachine;
        let seed = seed_picking(MbaFamily::Add, MbaIdentity::AddViaNeg);
        let map = OpcodeMap::from_seed(seed);
        crate::vm::set_active_map(&map);
        set_mba_context(1, seed);
        let mut bc = Vec::new();
        raw_load_imm(&mut bc, 1, 3);
        raw_load_imm(&mut bc, 2, 4);
        raw_load_imm(&mut bc, 11, 5);
        emit_add_three(&mut bc, 3, 1, 2);
        raw_move(&mut bc, 0, 3);
        bc.push(map.encode(OpCode::Exit));
        bc.push(0);
        clear_mba_context();
        crate::vm::clear_active_map();

        let mut vm = VirtualMachine::with_opcode_map(bc, map);
        vm.run().unwrap();
        assert_eq!(vm.get_register(0).unwrap(), 7);
        assert_eq!(vm.get_register(11).unwrap(), 5);
    }

    /// Arith-shaped: add then mul while `c` stays in r11.
    #[test]
    fn mba_arith_shaped_add_mul_preserves_spills() {
        use crate::vm::VirtualMachine;
        for (level, seed) in [(1u8, 0xAAAA_u64), (1, 0xBBBB), (2, 0xAAAA), (2, 0xBBBB)] {
            let map = OpcodeMap::from_seed(seed);
            crate::vm::set_active_map(&map);
            set_mba_context(level, seed);
            let mut bc = Vec::new();
            raw_load_imm(&mut bc, 1, 3);
            raw_load_imm(&mut bc, 2, 4);
            raw_load_imm(&mut bc, 11, 5);
            emit_add_three(&mut bc, 3, 1, 2);
            raw_move(&mut bc, 4, 11);
            raw_mul(&mut bc, 0, 3, 4); // (a+b)*c
            bc.push(map.encode(OpCode::Exit));
            bc.push(0);
            clear_mba_context();
            crate::vm::clear_active_map();

            let mut vm = VirtualMachine::with_opcode_map(bc, map);
            vm.run().unwrap();
            assert_eq!(
                vm.get_register(0).unwrap(),
                35,
                "level={level} seed={seed:#x}"
            );
            assert_eq!(
                vm.get_register(11).unwrap(),
                5,
                "level={level} seed={seed:#x}"
            );
        }
    }

    #[test]
    fn mba_add_rewrite_avoids_push_spill_wrapper() {
        let seed = seed_picking(MbaFamily::Add, MbaIdentity::AddViaXorAnd);
        with_mba(1, seed, || {
            let map = OpcodeMap::from_seed(seed);
            let mut bc = Vec::new();
            raw_load_imm(&mut bc, 10, 3);
            raw_load_imm(&mut bc, 11, 4);
            emit_add_three(&mut bc, 2, 10, 11);
            assert!(
                !bc.contains(&map.encode(OpCode::Push)),
                "MBA add must not wrap in push/pop spill save"
            );
        });
    }
}
