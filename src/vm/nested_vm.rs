use super::block_map::META_WIRE_BYTE;
use super::opcode::OpCode;
use super::opcode_map::{CANONICAL_OPCODE_COUNT, CANONICAL_OPCODES, OpcodeMap};

/// Seed salt for the inner (execute-layer) opcode map (L5f).
pub const NESTED_INNER_SALT: u64 = 0x4E45_5354; // "NEST"

/// 256-byte outer→inner wire translation table embedded in the stub.
pub const OUTER_DECODE_TABLE_SIZE: usize = 256;

/// L5f nested VM plan: outer bytecode wires decode to inner handler-index wires.
#[derive(Clone, Debug)]
pub struct NestedVmPlan {
    pub enabled: bool,
    /// Maps outer wire byte (bytecode) → inner wire byte (handler table index).
    pub outer_decode: [u8; OUTER_DECODE_TABLE_SIZE],
    /// Inner opcode map used for handler-table keying at execute time.
    pub inner_map: OpcodeMap,
}

impl NestedVmPlan {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            outer_decode: [0u8; OUTER_DECODE_TABLE_SIZE],
            inner_map: OpcodeMap::from_seed(0),
        }
    }

    pub fn from_seed(pack_seed: u64, outer_maps: &[OpcodeMap]) -> Self {
        let inner_map = OpcodeMap::from_seed(pack_seed ^ NESTED_INNER_SALT);
        let outer_decode = build_outer_decode_table(&inner_map, outer_maps);
        Self {
            enabled: true,
            outer_decode,
            inner_map,
        }
    }

    /// Decode an outer wire byte to the inner wire used for handler dispatch.
    pub fn decode_outer(&self, outer_wire: u8) -> u8 {
        self.outer_decode[outer_wire as usize]
    }

    pub fn format_ir_header(&self, outer_map: &OpcodeMap) -> String {
        if !self.enabled {
            return String::new();
        }
        let mut out = String::new();
        out.push_str("L5f nested=outer_decode+inner_execute\n");
        out.push_str(&format!(
            "  inner_seed={:#x} (pack_seed ^ {:#x})\n",
            self.inner_map.seed(),
            NESTED_INNER_SALT
        ));
        out.push_str("  layers: outer reads bytecode wire → per-transition outer_decode (KNV6 v3) → inner indexes handler redirect table\n");
        out.push_str("  note: two dispatch hops per instruction (educational; slower than single-VM)\n");
        // Show a few canonical op mappings where outer ≠ inner.
        out.push_str("  sample outer→inner wires (canonical ops):\n");
        let mut shown = 0usize;
        for &op in &CANONICAL_OPCODES {
            let outer = outer_map.encode(op);
            let inner = self.inner_map.encode(op);
            if outer != inner && shown < 6 {
                out.push_str(&format!(
                    "    {} outer={:#04x} → inner={:#04x}\n",
                    op.name(),
                    outer,
                    inner
                ));
                shown += 1;
            }
        }
        if shown == 0 {
            out.push_str("    (all shown canonical ops share wire values; table still permutes non-op slots)\n");
        }
        out
    }
}

/// Per-transition outer→inner decode for one L5d wire table (canonical-indexed wires).
pub fn build_outer_decode_for_transition(
    inner_map: &OpcodeMap,
    outer_wire: &[u8; CANONICAL_OPCODE_COUNT],
) -> [u8; OUTER_DECODE_TABLE_SIZE] {
    let nop_inner = inner_map.encode(OpCode::Nop);
    let mut table = [nop_inner; OUTER_DECODE_TABLE_SIZE];
    for (idx, &op) in CANONICAL_OPCODES.iter().enumerate() {
        let outer = outer_wire[idx];
        let inner = inner_map.encode(op);
        table[outer as usize] = inner;
    }
    table[META_WIRE_BYTE as usize] = META_WIRE_BYTE;
    table
}

/// Build a merged table across transitions (IR display only — not used at runtime).
pub fn build_outer_decode_table(
    inner_map: &OpcodeMap,
    outer_maps: &[OpcodeMap],
) -> [u8; OUTER_DECODE_TABLE_SIZE] {
    let nop_inner = inner_map.encode(OpCode::Nop);
    let mut table = [nop_inner; OUTER_DECODE_TABLE_SIZE];
    for map in outer_maps {
        for &op in &CANONICAL_OPCODES {
            let outer = map.encode(op);
            let inner = inner_map.encode(op);
            table[outer as usize] = inner;
        }
    }
    table[META_WIRE_BYTE as usize] = META_WIRE_BYTE;
    table
}

/// Collect every distinct outer OpcodeMap that may appear in bytecode.
pub fn collect_outer_maps(pack_seed: u64, base: &OpcodeMap, block_plan: &super::block_map::BlockMapPlan) -> Vec<OpcodeMap> {
    let mut maps = vec![base.clone()];
    for entry in &block_plan.entries {
        maps.push(OpcodeMap::from_parts(pack_seed, entry.wire));
    }
    maps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::block_map::BlockMapPlan;

    #[test]
    fn inner_map_differs_from_outer() {
        let seed = 0xDEAD_BEEF_u64;
        let outer = OpcodeMap::from_seed(seed);
        let plan = NestedVmPlan::from_seed(seed, &[outer.clone()]);
        assert_ne!(plan.inner_map.wire_table(), outer.wire_table());
    }

    #[test]
    fn outer_decode_maps_canonical_ops() {
        let seed = 42u64;
        let outer = OpcodeMap::from_seed(seed);
        let table = build_outer_decode_for_transition(
            &OpcodeMap::from_seed(seed ^ NESTED_INNER_SALT),
            outer.wire_table(),
        );
        let inner = OpcodeMap::from_seed(seed ^ NESTED_INNER_SALT);
        for &op in &CANONICAL_OPCODES {
            let outer_wire = outer.encode(op);
            assert_eq!(table[outer_wire as usize], inner.encode(op));
        }
    }

    #[test]
    fn per_transition_outer_decode_differs_when_wires_collide() {
        let seed = 0x1234u64;
        let inner = OpcodeMap::from_seed(seed ^ NESTED_INNER_SALT);
        let mut plan = BlockMapPlan::default();
        let (_, map_a) = plan.record_transition(seed, 0, super::super::block_map::ENTRY_PRED_BB);
        let (_, map_b) = plan.record_transition(seed, 1, 0);
        let ta = build_outer_decode_for_transition(&inner, map_a.wire_table());
        let tb = build_outer_decode_for_transition(&inner, map_b.wire_table());
        for &op in &CANONICAL_OPCODES {
            let wa = map_a.encode(op);
            let wb = map_b.encode(op);
            if wa == wb && map_a.encode(op) != map_b.encode(op) {
                // impossible: same wire can't mean different ops in one map
            }
        }
        // Different transitions almost always differ at some outer slot.
        assert_ne!(ta, tb, "per-transition outer_decode must not be globally merged");
    }

    #[test]
    fn meta_wire_passthrough() {
        let seed = 1u64;
        let outer = OpcodeMap::from_seed(seed);
        let plan = NestedVmPlan::from_seed(seed, &[outer]);
        assert_eq!(plan.decode_outer(META_WIRE_BYTE), META_WIRE_BYTE);
    }

    #[test]
    fn collect_outer_maps_includes_transitions() {
        let seed = 0x1234u64;
        let base = OpcodeMap::from_seed(seed);
        let mut plan = BlockMapPlan::default();
        plan.record_transition(seed, 0, super::super::block_map::ENTRY_PRED_BB);
        plan.record_transition(seed, 1, 0);
        let maps = collect_outer_maps(seed, &base, &plan);
        assert!(maps.len() >= 2);
    }
}
