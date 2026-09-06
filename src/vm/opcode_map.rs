use super::dispatch::DispatchMode;
use super::opcode::OpCode;
use std::cell::RefCell;

pub const KNV4_MAGIC: &[u8; 4] = b"KNV4";
pub const KNV4_VERSION_V1: u8 = 1;
pub const KNV4_VERSION: u8 = 2;
pub const CANONICAL_OPCODE_COUNT: usize = 20;
pub const KNV4_HEADER_SIZE_V1: usize = 4 + 1 + 8 + CANONICAL_OPCODE_COUNT;
pub const KNV4_HEADER_SIZE: usize = 4 + 1 + 1 + 8 + CANONICAL_OPCODE_COUNT;

/// Handler polymorphism (L4b): number of native bodies per logical opcode.
pub const ADD_HANDLER_VARIANT_COUNT: u8 = 3;
const HANDLER_VARIANT_SALT: u64 = 0x504F_4C59; // "POLY"

/// Logical opcodes implemented by the in-process stub (stable index order).
pub const CANONICAL_OPCODES: [OpCode; CANONICAL_OPCODE_COUNT] = [
    OpCode::Nop,
    OpCode::LoadImm,
    OpCode::Move,
    OpCode::Add,
    OpCode::Sub,
    OpCode::Mul,
    OpCode::Cmp,
    OpCode::Jmp,
    OpCode::JmpIf,
    OpCode::Call,
    OpCode::Ret,
    OpCode::NativeCall,
    OpCode::Push,
    OpCode::Pop,
    OpCode::LoadByte,
    OpCode::Cmp32,
    OpCode::And,
    OpCode::RunNative,
    OpCode::BailNative,
    OpCode::Exit,
];

/// Handler labels in canonical order (matches [`CANONICAL_OPCODES`]).
pub const CANONICAL_HANDLER_LABELS: [&str; CANONICAL_OPCODE_COUNT] = [
    "h_nop",
    "h_load_imm",
    "h_move",
    "h_add",
    "h_sub",
    "h_mul",
    "h_cmp",
    "h_jmp",
    "h_jmpif",
    "h_call",
    "h_ret",
    "h_native_call",
    "h_push",
    "h_pop",
    "h_load_byte",
    "h_cmp32",
    "h_and",
    "h_run_native",
    "h_bail_native",
    "h_exit",
];

thread_local! {
    static ACTIVE_MAP: RefCell<Option<OpcodeMap>> = RefCell::new(None);
}

#[derive(Clone, Debug)]
pub struct OpcodeMap {
    seed: u64,
    wire: [u8; CANONICAL_OPCODE_COUNT],
    decode: [Option<OpCode>; 256],
    handler_emit_order: [u8; CANONICAL_OPCODE_COUNT],
}

impl OpcodeMap {
    pub fn from_seed(seed: u64) -> Self {
        let wire = shuffle_wire_bytes(seed);
        let decode = build_decode_table(&wire);
        let handler_emit_order = shuffle_indices(seed ^ 0x4853_4C48);
        Self {
            seed,
            wire,
            decode,
            handler_emit_order,
        }
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn wire_table(&self) -> &[u8; CANONICAL_OPCODE_COUNT] {
        &self.wire
    }

    pub fn handler_emit_order(&self) -> &[u8; CANONICAL_OPCODE_COUNT] {
        &self.handler_emit_order
    }

    /// Native handler body index for polymorphic opcodes (L4b). Derived from pack seed.
    pub fn handler_variant(&self, op: OpCode) -> u8 {
        handler_variant_for(self.seed, op)
    }

    pub fn add_handler_variant(&self) -> u8 {
        self.handler_variant(OpCode::Add)
    }

    pub fn encode(&self, op: OpCode) -> u8 {
        let idx = canonical_index(op)
            .expect("attempted to encode opcode not in L4a canonical set");
        self.wire[idx]
    }

    pub fn decode(&self, wire: u8) -> Option<OpCode> {
        self.decode[wire as usize]
    }

    pub fn exit_wire(&self) -> u8 {
        self.encode(OpCode::Exit)
    }

    pub fn handler_table_entries(&self) -> Vec<(u8, &'static str)> {
        let mut entries = Vec::with_capacity(CANONICAL_OPCODE_COUNT);
        for (idx, op) in CANONICAL_OPCODES.iter().enumerate() {
            let wire = self.wire[idx];
            let label = handler_label_for(*op);
            entries.push((wire, label));
        }
        entries
    }

    pub fn handler_label(&self, op: OpCode) -> &'static str {
        handler_label_for(op)
    }

    pub fn to_embedded_bytes(&self) -> Vec<u8> {
        PackMetadata {
            opcode_map: self.clone(),
            dispatch_mode: DispatchMode::Table,
        }
            .to_embedded_bytes()
    }

    pub fn from_embedded(data: &[u8]) -> Option<Self> {
        PackMetadata::from_embedded(data).map(|m| m.opcode_map)
    }
}

/// L4a opcode map + L4c dispatch mode embedded in `.knvest`.
#[derive(Clone, Debug)]
pub struct PackMetadata {
    pub opcode_map: OpcodeMap,
    pub dispatch_mode: DispatchMode,
}

impl PackMetadata {
    pub fn from_seed(seed: u64, dispatch_mode: DispatchMode) -> Self {
        Self {
            opcode_map: OpcodeMap::from_seed(seed),
            dispatch_mode,
        }
    }

    pub fn seed(&self) -> u64 {
        self.opcode_map.seed()
    }

    pub fn to_embedded_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KNV4_HEADER_SIZE);
        out.extend_from_slice(KNV4_MAGIC);
        out.push(KNV4_VERSION);
        out.push(self.dispatch_mode.as_wire());
        out.extend_from_slice(&self.opcode_map.seed.to_le_bytes());
        out.extend_from_slice(&self.opcode_map.wire);
        out
    }

    pub fn from_embedded(data: &[u8]) -> Option<Self> {
        if data.len() < 4 + 1 || &data[0..4] != KNV4_MAGIC {
            return None;
        }
        match data[4] {
            KNV4_VERSION_V1 => {
                if data.len() < KNV4_HEADER_SIZE_V1 {
                    return None;
                }
                let seed = u64::from_le_bytes(data[5..13].try_into().unwrap());
                let mut wire = [0u8; CANONICAL_OPCODE_COUNT];
                wire.copy_from_slice(&data[13..13 + CANONICAL_OPCODE_COUNT]);
                if !wire_is_valid(&wire) {
                    return None;
                }
                Some(Self {
                    opcode_map: OpcodeMap::from_parts(seed, wire),
                    dispatch_mode: DispatchMode::Table,
                })
            }
            KNV4_VERSION => {
                if data.len() < KNV4_HEADER_SIZE {
                    return None;
                }
                let dispatch_mode = DispatchMode::from_wire(data[5])?;
                let seed = u64::from_le_bytes(data[6..14].try_into().unwrap());
                let mut wire = [0u8; CANONICAL_OPCODE_COUNT];
                wire.copy_from_slice(&data[14..14 + CANONICAL_OPCODE_COUNT]);
                if !wire_is_valid(&wire) {
                    return None;
                }
                Some(Self {
                    opcode_map: OpcodeMap::from_parts(seed, wire),
                    dispatch_mode,
                })
            }
            _ => None,
        }
    }
}

impl OpcodeMap {
    pub fn from_parts(seed: u64, wire: [u8; CANONICAL_OPCODE_COUNT]) -> Self {
        let decode = build_decode_table(&wire);
        let handler_emit_order = shuffle_indices(seed ^ 0x4853_4C48);
        Self {
            seed,
            wire,
            decode,
            handler_emit_order,
        }
    }
}

pub fn set_active_map(map: &OpcodeMap) {
    ACTIVE_MAP.with(|cell| *cell.borrow_mut() = Some(map.clone()));
}

pub fn clear_active_map() {
    ACTIVE_MAP.with(|cell| *cell.borrow_mut() = None);
}

pub fn active_encode(op: OpCode) -> u8 {
    ACTIVE_MAP.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|m| m.encode(op))
            .unwrap_or(op as u8)
    })
}

pub fn active_decode(wire: u8) -> Option<OpCode> {
    ACTIVE_MAP.with(|cell| {
        if let Some(map) = cell.borrow().as_ref() {
            map.decode(wire)
        } else {
            OpCode::from_u8(wire)
        }
    })
}

pub fn random_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    splitmix64(nanos ^ (std::process::id() as u64))
}

fn canonical_index(op: OpCode) -> Option<usize> {
    CANONICAL_OPCODES.iter().position(|&c| c == op)
}

fn handler_label_for(op: OpCode) -> &'static str {
    let idx = canonical_index(op).expect("handler label for unknown opcode");
    CANONICAL_HANDLER_LABELS[idx]
}

/// Polymorphic handler bodies supported per opcode (0 = single body only).
pub fn handler_variant_count(op: OpCode) -> u8 {
    match op {
        OpCode::Add => ADD_HANDLER_VARIANT_COUNT,
        _ => 1,
    }
}

fn handler_variant_for(seed: u64, op: OpCode) -> u8 {
    let count = handler_variant_count(op);
    if count <= 1 {
        return 0;
    }
    let idx = canonical_index(op).expect("variant for unknown opcode") as u64;
    let mixed = splitmix64(seed ^ HANDLER_VARIANT_SALT ^ idx);
    (mixed % u64::from(count)) as u8
}

fn wire_is_valid(wire: &[u8; CANONICAL_OPCODE_COUNT]) -> bool {
    let mut seen = [false; 256];
    for &b in wire {
        if seen[b as usize] {
            return false;
        }
        seen[b as usize] = true;
    }
    true
}

fn build_decode_table(wire: &[u8; CANONICAL_OPCODE_COUNT]) -> [Option<OpCode>; 256] {
    let mut decode = [None; 256];
    for (idx, &w) in wire.iter().enumerate() {
        decode[w as usize] = Some(CANONICAL_OPCODES[idx]);
    }
    decode
}

fn shuffle_wire_bytes(seed: u64) -> [u8; CANONICAL_OPCODE_COUNT] {
    let mut pool: Vec<u8> = (0u8..=255)
        .filter(|&b| b != super::block_map::META_WIRE_BYTE)
        .collect();
    fisher_yates(&mut pool, seed);
    let mut wire = [0u8; CANONICAL_OPCODE_COUNT];
    for i in 0..CANONICAL_OPCODE_COUNT {
        wire[i] = pool[i];
    }
    wire
}

fn shuffle_indices(seed: u64) -> [u8; CANONICAL_OPCODE_COUNT] {
    let mut order: Vec<u8> = (0..CANONICAL_OPCODE_COUNT as u8).collect();
    fisher_yates(&mut order, seed);
    let mut out = [0u8; CANONICAL_OPCODE_COUNT];
    for (i, v) in order.iter().enumerate() {
        out[i] = *v;
    }
    out
}

fn fisher_yates<T: Copy>(items: &mut [T], mut seed: u64) {
    if items.is_empty() {
        return;
    }
    for i in (1..items.len()).rev() {
        seed = splitmix64(seed);
        let j = (seed as usize) % (i + 1);
        items.swap(i, j);
    }
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
    use crate::vm::DispatchMode;

    #[test]
    fn different_seeds_produce_different_wire_tables() {
        let a = OpcodeMap::from_seed(1);
        let b = OpcodeMap::from_seed(2);
        assert_ne!(a.wire_table(), b.wire_table());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let map = OpcodeMap::from_seed(0xDEAD_BEEF);
        for &op in &CANONICAL_OPCODES {
            let wire = map.encode(op);
            assert_eq!(map.decode(wire), Some(op));
        }
    }

    #[test]
    fn pack_metadata_v2_threaded_roundtrip() {
        let meta = PackMetadata::from_seed(0xBEEF, DispatchMode::Threaded);
        let bytes = meta.to_embedded_bytes();
        assert_eq!(bytes[4], KNV4_VERSION);
        assert_eq!(bytes[5], DispatchMode::Threaded.as_wire());
        let parsed = PackMetadata::from_embedded(&bytes).unwrap();
        assert_eq!(parsed.dispatch_mode, DispatchMode::Threaded);
        assert_eq!(parsed.seed(), 0xBEEF);
    }

    #[test]
    fn embedded_roundtrip() {
        let map = OpcodeMap::from_seed(42);
        let bytes = map.to_embedded_bytes();
        let parsed = OpcodeMap::from_embedded(&bytes).unwrap();
        assert_eq!(parsed.seed(), 42);
        assert_eq!(parsed.wire_table(), map.wire_table());
        for &op in &CANONICAL_OPCODES {
            assert_eq!(parsed.encode(op), map.encode(op));
        }
    }

    #[test]
    fn handler_order_varies_by_seed() {
        let a = OpcodeMap::from_seed(10);
        let b = OpcodeMap::from_seed(11);
        assert_ne!(a.handler_emit_order(), b.handler_emit_order());
    }

    #[test]
    fn add_handler_variant_is_seed_derived_and_bounded() {
        for seed in [0u64, 1, 0xDEAD_BEEF, u64::MAX] {
            let map = OpcodeMap::from_seed(seed);
            assert!(map.add_handler_variant() < ADD_HANDLER_VARIANT_COUNT);
        }
    }

    #[test]
    fn add_handler_variant_differs_for_some_seed_pairs() {
        let mut seen = [false; ADD_HANDLER_VARIANT_COUNT as usize];
        for seed in 0..64u64 {
            seen[OpcodeMap::from_seed(seed).add_handler_variant() as usize] = true;
        }
        assert!(
            seen.iter().filter(|&&v| v).count() >= 2,
            "expected at least two Add handler variants across seeds 0..63"
        );
    }

    #[test]
    fn non_polymorphic_ops_always_variant_zero() {
        let map = OpcodeMap::from_seed(0x1234);
        for &op in &CANONICAL_OPCODES {
            if op != OpCode::Add {
                assert_eq!(map.handler_variant(op), 0);
            }
        }
    }
}
