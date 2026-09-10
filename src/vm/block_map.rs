use super::opcode::OpCode;
use super::opcode_map::{CANONICAL_OPCODE_COUNT, CANONICAL_OPCODES, KNV4_MAGIC, OpcodeMap};

/// Synthetic predecessor for function / callee entry (L5d transition key).
pub const ENTRY_PRED_BB: u16 = 0xFFFF;

/// Fixed wire byte for L4e/L5d block-map refresh (never assigned to semantic opcodes).
pub const META_WIRE_BYTE: u8 = 0xFD;
/// Operand bytes after the meta wire byte at block entry (L5d: transition id).
pub const META_OPERAND_LEN: usize = 2;

pub const KNV6_MAGIC: &[u8; 4] = b"KNV6";
pub const KNV6_VERSION: u8 = 2;
pub const KNV6_HEADER_SIZE: usize = 4 + 1 + 4 + 2;
/// Byte offset of the 256×dword redirect table inside each KNV6 v2 entry.
pub const KNV6_ENTRY_HANDLER_TABLE_OFF: usize =
    2 + 2 + 2 + 4 + 1 + 1 + CANONICAL_OPCODE_COUNT;
pub const KNV6_ENTRY_SIZE: usize = KNV6_ENTRY_HANDLER_TABLE_OFF + 256 * 4;

const BLOCK_KEY_SALT: u64 = 0x424C_4B45; // "BLKE"
const KEY_SALT: u64 = 0x4445_434B; // "DECK"
const TRANSITION_KEY_SALT: u64 = 0x5452_4E53; // "TRNS"

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMapEntry {
    /// Dense transition id (META operand + KNV6 search key).
    pub tx_id: u16,
    /// Semantic basic block this transition enters.
    pub bb_id: u16,
    /// Predecessor block id or [`ENTRY_PRED_BB`] for function entry.
    pub pred_bb_id: u16,
    pub decode_key: u32,
    pub exit_wire: u8,
    pub wire: [u8; CANONICAL_OPCODE_COUNT],
    /// Runtime handler-table image: 256 dwords indexed by wire byte.
    pub handler_table: [u8; 256 * 4],
}

#[derive(Debug, Clone, Default)]
pub struct BlockMapPlan {
    pub decode_key: u32,
    pub entries: Vec<BlockMapEntry>,
    /// Pre-main callee function entry (file offset) → dense semantic bb_id.
    pub callee_entry_bb_ids: std::collections::HashMap<usize, u16>,
}

impl BlockMapPlan {
    pub fn global_decode_key(pack_seed: u64) -> u32 {
        (splitmix64(pack_seed ^ KEY_SALT) >> 32) as u32
    }

    pub fn block_decode_key(pack_seed: u64, bb_id: usize) -> u32 {
        (splitmix64(pack_seed ^ BLOCK_KEY_SALT ^ bb_id as u64) >> 32) as u32
    }

    pub fn transition_decode_key(pack_seed: u64, bb_id: u16, pred_bb_id: u16) -> u32 {
        (splitmix64(transition_mix(pack_seed, bb_id, pred_bb_id)) >> 32) as u32
    }

    pub fn block_opcode_map(pack_seed: u64, bb_id: usize) -> OpcodeMap {
        OpcodeMap::from_seed(pack_seed ^ BLOCK_KEY_SALT ^ bb_id as u64)
    }

    pub fn transition_opcode_map(pack_seed: u64, bb_id: u16, pred_bb_id: u16) -> OpcodeMap {
        OpcodeMap::from_seed(transition_mix(pack_seed, bb_id, pred_bb_id))
    }

    pub fn record_transition(
        &mut self,
        pack_seed: u64,
        bb_id: u16,
        pred_bb_id: u16,
    ) -> (u16, OpcodeMap) {
        let tx_id = self.entries.len() as u16;
        let map = Self::transition_opcode_map(pack_seed, bb_id, pred_bb_id);
        let decode_key = Self::transition_decode_key(pack_seed, bb_id, pred_bb_id);
        self.entries.push(BlockMapEntry {
            tx_id,
            bb_id,
            pred_bb_id,
            decode_key,
            exit_wire: map.exit_wire(),
            wire: *map.wire_table(),
            handler_table: [0u8; 256 * 4],
        });
        (tx_id, map)
    }

    /// L4e-compatible single-map-per-BB helper (tests / fallback).
    pub fn record_block(&mut self, pack_seed: u64, bb_id: usize) -> OpcodeMap {
        let pred = if bb_id == 0 {
            ENTRY_PRED_BB
        } else {
            bb_id as u16 - 1
        };
        self.record_transition(pack_seed, bb_id as u16, pred).1
    }

    /// Register a pre-main callee with the next dense bb_id and remember its entry offset.
    pub fn record_callee_entry(&mut self, pack_seed: u64, entry_offset: usize) -> u16 {
        let bb_id = self.entries.len() as u16;
        self.record_transition(pack_seed, bb_id, ENTRY_PRED_BB);
        self.callee_entry_bb_ids.insert(entry_offset, bb_id);
        bb_id
    }

    pub fn callee_entry_bb_id(&self, entry_offset: usize) -> Option<u16> {
        self.callee_entry_bb_ids.get(&entry_offset).copied()
    }

    pub fn transition_for_edge(&self, pred_bb_id: u16, bb_id: u16) -> Option<u16> {
        self.entries
            .iter()
            .find(|e| e.pred_bb_id == pred_bb_id && e.bb_id == bb_id)
            .map(|e| e.tx_id)
    }

    pub fn map_for_tx(&self, tx_id: u16) -> Option<&BlockMapEntry> {
        self.entries.iter().find(|e| e.tx_id == tx_id)
    }

    pub fn map_for_bb(&self, bb_id: u16) -> Option<&BlockMapEntry> {
        self.entries.iter().find(|e| e.bb_id == bb_id)
    }

    pub fn map_for_tx_or_base(&self, tx_id: u16, base: &OpcodeMap) -> OpcodeMap {
        self.map_for_tx(tx_id)
            .map(|e| OpcodeMap::from_parts(base.seed(), e.wire))
            .unwrap_or_else(|| Self::block_opcode_map(base.seed(), tx_id as usize))
    }

    pub fn map_for_bb_or_base(&self, bb_id: u16, base: &OpcodeMap) -> OpcodeMap {
        self.map_for_bb(bb_id)
            .map(|e| OpcodeMap::from_parts(base.seed(), e.wire))
            .unwrap_or_else(|| Self::block_opcode_map(base.seed(), bb_id as usize))
    }

    pub fn wire_map_hash(entry: &BlockMapEntry) -> u64 {
        let mut h = 0xcbf29ce484222325u64;
        for &b in &entry.wire {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    pub fn fill_handler_tables(&mut self, plan: &HandlerRedirectPlan) {
        for entry in &mut self.entries {
            entry.handler_table = plan.build_handler_table(&entry.wire);
        }
    }

    pub fn fill_handler_tables_with<F>(&mut self, mut handler_off: F, set_map_off: i32)
    where
        F: FnMut(OpCode) -> i32,
    {
        for entry in &mut self.entries {
            entry.handler_table =
                build_handler_table_image(&entry.wire, &mut handler_off, set_map_off);
        }
    }

    pub fn to_embedded_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KNV6_HEADER_SIZE + self.entries.len() * KNV6_ENTRY_SIZE);
        out.extend_from_slice(KNV6_MAGIC);
        out.push(KNV6_VERSION);
        out.extend_from_slice(&self.decode_key.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.tx_id.to_le_bytes());
            out.extend_from_slice(&entry.bb_id.to_le_bytes());
            out.extend_from_slice(&entry.pred_bb_id.to_le_bytes());
            out.extend_from_slice(&entry.decode_key.to_le_bytes());
            out.push(entry.exit_wire);
            out.push(0);
            out.extend_from_slice(&entry.wire);
            out.extend_from_slice(&entry.handler_table);
        }
        out
    }

    pub fn from_embedded(data: &[u8]) -> Option<Self> {
        if data.len() < KNV6_HEADER_SIZE || &data[0..4] != KNV6_MAGIC {
            return None;
        }
        let version = data[4];
        if version != KNV6_VERSION && version != 1 {
            return None;
        }
        let decode_key = u32::from_le_bytes(data[5..9].try_into().ok()?);
        let count = u16::from_le_bytes(data[9..11].try_into().ok()?) as usize;
        let mut offset = KNV6_HEADER_SIZE;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let entry_size = if version == 1 {
                2 + 4 + 1 + 1 + CANONICAL_OPCODE_COUNT + 256 * 4
            } else {
                KNV6_ENTRY_SIZE
            };
            if offset + entry_size > data.len() {
                return None;
            }
            let (tx_id, bb_id, pred_bb_id, block_key, exit_wire, wire_off, table_off) =
                if version == 1 {
                    let bb = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
                    (
                        bb,
                        bb,
                        ENTRY_PRED_BB,
                        u32::from_le_bytes(data[offset + 2..offset + 6].try_into().ok()?),
                        data[offset + 6],
                        offset + 8,
                        offset + 8 + CANONICAL_OPCODE_COUNT,
                    )
                } else {
                    let tx = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
                    let bb = u16::from_le_bytes(data[offset + 2..offset + 4].try_into().ok()?);
                    let pred = u16::from_le_bytes(data[offset + 4..offset + 6].try_into().ok()?);
                    (
                        tx,
                        bb,
                        pred,
                        u32::from_le_bytes(data[offset + 6..offset + 10].try_into().ok()?),
                        data[offset + 10],
                        offset + 12,
                        offset + 12 + CANONICAL_OPCODE_COUNT,
                    )
                };
            let mut wire = [0u8; CANONICAL_OPCODE_COUNT];
            wire.copy_from_slice(&data[wire_off..wire_off + CANONICAL_OPCODE_COUNT]);
            let mut handler_table = [0u8; 256 * 4];
            handler_table.copy_from_slice(&data[table_off..table_off + 256 * 4]);
            offset += entry_size;
            entries.push(BlockMapEntry {
                tx_id,
                bb_id,
                pred_bb_id,
                decode_key: block_key,
                exit_wire,
                wire,
                handler_table,
            });
        }
        Some(Self {
            decode_key,
            entries,
            callee_entry_bb_ids: Default::default(),
        })
    }

    pub fn format_ir_header(
        &self,
        base_map: &OpcodeMap,
        dispatch_mode: crate::vm::DispatchMode,
    ) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "L5d transition opcode maps | global_key={:#x} | seed={:#x} | dispatch={} | transitions={}\n",
            self.decode_key,
            base_map.seed(),
            dispatch_mode,
            self.entries.len()
        ));
        out.push_str("tx_id | bb_id | pred_bb | decode_key | exit_wire | load_imm wire | map_hash\n");
        out.push_str("------+-------+---------+------------+-----------+-------------+----------\n");
        for entry in &self.entries {
            let load_imm = entry.wire[CANONICAL_OPCODES
                .iter()
                .position(|&op| op == OpCode::LoadImm)
                .unwrap_or(0)];
            out.push_str(&format!(
                "{:5} | {:5} | {:#7x} | {:#10x} | {:#9x} | {:#11x} | {:#x}\n",
                entry.tx_id,
                entry.bb_id,
                entry.pred_bb_id,
                entry.decode_key,
                entry.exit_wire,
                load_imm,
                Self::wire_map_hash(entry),
            ));
        }
        out.push('\n');
        out
    }
}

pub fn emit_block_map_refresh(bytecode: &mut Vec<u8>, tx_id: u16) {
    bytecode.push(META_WIRE_BYTE);
    bytecode.extend_from_slice(&tx_id.to_le_bytes());
}

pub fn block_wires_for_semantic(
    pack_seed: u64,
    block_plan: &BlockMapPlan,
    op: OpCode,
) -> Vec<u8> {
    let mut wires = Vec::new();
    let mut push = |w: u8| {
        if !wires.contains(&w) {
            wires.push(w);
        }
    };
    if block_plan.entries.is_empty() {
        push(OpcodeMap::from_seed(pack_seed).encode(op));
        for bb in 0..16usize {
            push(BlockMapPlan::block_opcode_map(pack_seed, bb).encode(op));
        }
        return wires;
    }
    for entry in &block_plan.entries {
        push(OpcodeMap::from_parts(pack_seed, entry.wire).encode(op));
    }
    wires
}

pub fn bytecode_contains_semantic(
    bytecode: &[u8],
    pack_seed: u64,
    block_plan: &BlockMapPlan,
    op: OpCode,
) -> bool {
    block_wires_for_semantic(pack_seed, block_plan, op)
        .into_iter()
        .any(|w| bytecode.contains(&w))
}

pub fn block_wire_for_bb(pack_seed: u64, bb_id: usize, op: OpCode) -> u8 {
    BlockMapPlan::block_opcode_map(pack_seed, bb_id).encode(op)
}

pub fn meta_instruction_len(dispatch_mode: crate::vm::DispatchMode) -> usize {
    let base = 1 + META_OPERAND_LEN;
    if dispatch_mode == crate::vm::DispatchMode::Threaded {
        base + crate::vm::dispatch::THREAD_TARGET_SIZE
    } else {
        base
    }
}

pub fn build_handler_table_image<F>(
    wire: &[u8; CANONICAL_OPCODE_COUNT],
    handler_off: &mut F,
    set_map_off: i32,
) -> [u8; 256 * 4]
where
    F: FnMut(OpCode) -> i32,
{
    let default = handler_off(OpCode::Nop);
    let mut table = [0u8; 256 * 4];
    for slot in table.chunks_exact_mut(4) {
        slot.copy_from_slice(&default.to_le_bytes());
    }
    for (idx, &w) in wire.iter().enumerate() {
        let op = CANONICAL_OPCODES[idx];
        let off = handler_off(op);
        let patch = (w as usize) * 4;
        table[patch..patch + 4].copy_from_slice(&off.to_le_bytes());
    }
    let meta_patch = (META_WIRE_BYTE as usize) * 4;
    table[meta_patch..meta_patch + 4].copy_from_slice(&set_map_off.to_le_bytes());
    table
}

pub const HANDLER_REDIRECT_TABLE_SIZE: usize = 256 * 4;

/// Cached canonical handler offsets relative to `handler_table` (L4a layout).
/// Built once from a finalized stub **before** any runtime redirect-table patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerRedirectPlan {
    /// Per canonical opcode index (same order as [`CANONICAL_OPCODES`]).
    pub by_op: [i32; CANONICAL_OPCODE_COUNT],
    pub nop_default: i32,
    pub set_block_map: i32,
}

impl HandlerRedirectPlan {
    pub fn offset_for(&self, op: OpCode) -> i32 {
        let idx = CANONICAL_OPCODES
            .iter()
            .position(|&o| o == op)
            .expect("canonical opcode only");
        self.by_op[idx]
    }

    pub fn build_handler_table(
        &self,
        wire: &[u8; CANONICAL_OPCODE_COUNT],
    ) -> [u8; HANDLER_REDIRECT_TABLE_SIZE] {
        build_handler_table_from_plan(wire, self)
    }
}

/// First byte after handler bodies (PackMetadata / string pool); dispatch must stay below this.
pub fn handler_region_end(stub: &[u8], table_base: usize) -> usize {
    let handler_lo = table_base.saturating_add(HANDLER_REDIRECT_TABLE_SIZE);
    for pos in handler_lo..stub.len().saturating_sub(KNV4_MAGIC.len()) {
        if &stub[pos..pos + KNV4_MAGIC.len()] == KNV4_MAGIC {
            return pos;
        }
    }
    stub.len()
}

/// Capture L4a-class redirect dwords from a finalized stub (base wire layout, pre-patch).
pub fn collect_handler_redirect_plan(
    stub: &[u8],
    opcode_map: &OpcodeMap,
) -> HandlerRedirectPlan {
    let table_base = crate::pe::threaded::handler_table_base(stub);
    let mut by_op = [0i32; CANONICAL_OPCODE_COUNT];
    for (idx, op) in CANONICAL_OPCODES.iter().enumerate() {
        let wire = opcode_map.encode(*op) as usize;
        let patch_at = table_base + wire * 4;
        by_op[idx] = i32::from_le_bytes(
            stub[patch_at..patch_at + 4]
                .try_into()
                .expect("handler slot"),
        );
    }
    let nop_idx = CANONICAL_OPCODES
        .iter()
        .position(|&o| o == OpCode::Nop)
        .unwrap();
    let meta_patch = table_base + (META_WIRE_BYTE as usize) * 4;
    HandlerRedirectPlan {
        by_op,
        nop_default: by_op[nop_idx],
        set_block_map: i32::from_le_bytes(
            stub[meta_patch..meta_patch + 4]
                .try_into()
                .expect("meta slot"),
        ),
    }
}

pub fn build_handler_table_from_plan(
    wire: &[u8; CANONICAL_OPCODE_COUNT],
    plan: &HandlerRedirectPlan,
) -> [u8; HANDLER_REDIRECT_TABLE_SIZE] {
    let mut table = [0u8; HANDLER_REDIRECT_TABLE_SIZE];
    for slot in table.chunks_exact_mut(4) {
        slot.copy_from_slice(&plan.nop_default.to_le_bytes());
    }
    for (idx, &w) in wire.iter().enumerate() {
        let patch = (w as usize) * 4;
        table[patch..patch + 4].copy_from_slice(&plan.by_op[idx].to_le_bytes());
    }
    let meta_patch = (META_WIRE_BYTE as usize) * 4;
    table[meta_patch..meta_patch + 4].copy_from_slice(&plan.set_block_map.to_le_bytes());
    table
}

/// Verify every slot resolves to a stub handler body (not metadata/bytecode).
pub fn validate_handler_table_targets(
    stub: &[u8],
    table_base: usize,
    table: &[u8; HANDLER_REDIRECT_TABLE_SIZE],
) -> Result<(), String> {
    let handler_lo = table_base
        .checked_add(HANDLER_REDIRECT_TABLE_SIZE)
        .ok_or_else(|| "handler_table base overflow".to_string())?;
    let handler_hi = handler_region_end(stub, table_base);
    for (slot, chunk) in table.chunks_exact(4).enumerate() {
        let off = i32::from_le_bytes(chunk.try_into().map_err(|_| "slot len")?);
        if off == 0 {
            return Err(format!(
                "slot {slot:#04x} has zero offset — dispatch add rax,rbx would land in handler_table"
            ));
        }
        if off < HANDLER_REDIRECT_TABLE_SIZE as i32 {
            return Err(format!(
                "slot {slot:#04x} rel off {off:#x} < {:#x} — target still inside redirect table",
                HANDLER_REDIRECT_TABLE_SIZE
            ));
        }
        let target = table_base as i64 + off as i64;
        if target < handler_lo as i64 {
            return Err(format!(
                "slot {slot:#04x} rel off {off:#x} -> {target:#x} precedes handler region ({handler_lo:#x})"
            ));
        }
        if target as usize >= handler_hi {
            return Err(format!(
                "slot {slot:#04x} rel off {off:#x} -> {target:#x} past handler region ({handler_hi:#x})"
            ));
        }
    }
    Ok(())
}

/// Apply one KNV6 entry's redirect table to the stub image (pack-time BB0 pre-install).
pub fn install_handler_table_in_stub(
    stub: &mut [u8],
    table_base: usize,
    table: &[u8; HANDLER_REDIRECT_TABLE_SIZE],
) {
    stub[table_base..table_base + HANDLER_REDIRECT_TABLE_SIZE].copy_from_slice(table);
}

fn transition_mix(pack_seed: u64, bb_id: u16, pred_bb_id: u16) -> u64 {
    let mixed = (bb_id as u64) ^ ((pred_bb_id as u64) << 32);
    pack_seed ^ TRANSITION_KEY_SALT ^ mixed
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
    fn different_blocks_get_different_wire_for_load_imm() {
        let seed = 0x1234_5678u64;
        let a = BlockMapPlan::block_opcode_map(seed, 0);
        let b = BlockMapPlan::block_opcode_map(seed, 1);
        assert_ne!(
            a.encode(OpCode::LoadImm),
            b.encode(OpCode::LoadImm),
            "same semantic load_imm must use different wire bytes in different blocks"
        );
    }

    #[test]
    fn same_bb_different_entry_paths_get_different_maps() {
        let seed = 0x15D0_2026u64;
        let from_entry = BlockMapPlan::transition_opcode_map(seed, 2, ENTRY_PRED_BB);
        let from_bb1 = BlockMapPlan::transition_opcode_map(seed, 2, 1);
        assert_ne!(
            from_entry.encode(OpCode::LoadImm),
            from_bb1.encode(OpCode::LoadImm),
            "same semantic BB must get different wires for different entry paths"
        );
        let mut plan = BlockMapPlan::default();
        plan.record_transition(seed, 2, ENTRY_PRED_BB);
        plan.record_transition(seed, 2, 1);
        assert_ne!(
            BlockMapPlan::wire_map_hash(&plan.entries[0]),
            BlockMapPlan::wire_map_hash(&plan.entries[1]),
        );
    }

    #[test]
    fn meta_wire_never_assigned_to_semantic_opcodes() {
        for bb in 0..8usize {
            let map = BlockMapPlan::block_opcode_map(99, bb);
            for &op in &CANONICAL_OPCODES {
                assert_ne!(
                    map.encode(op),
                    META_WIRE_BYTE,
                    "semantic opcode wire must not collide with meta byte"
                );
            }
        }
    }

    #[test]
    fn validate_handler_table_rejects_zero_slot() {
        use super::validate_handler_table_targets;

        let mut stub = vec![0u8; 0x2000];
        let table_base = 0x1000;
        stub[0x1800..0x1804].copy_from_slice(KNV4_MAGIC);
        let mut table = [0u8; HANDLER_REDIRECT_TABLE_SIZE];
        table[0x42 * 4..0x42 * 4 + 4].copy_from_slice(&0x800i32.to_le_bytes());
        assert!(validate_handler_table_targets(&stub, table_base, &table).is_err());
    }

    #[test]
    fn validate_handler_table_rejects_forward_offset_into_tail() {
        use super::validate_handler_table_targets;

        let mut stub = vec![0u8; 0x2000];
        let table_base = 0x1000;
        stub[0x1800..0x1804].copy_from_slice(KNV4_MAGIC);
        let mut table = [0u8; HANDLER_REDIRECT_TABLE_SIZE];
        table[0xB5 * 4..0xB5 * 4 + 4].copy_from_slice(&0x800i32.to_le_bytes());
        assert!(validate_handler_table_targets(&stub, table_base, &table).is_err());
    }

    #[test]
    fn knv6_roundtrip_preserves_handler_tables() {
        let mut plan = BlockMapPlan {
            decode_key: 0xAABB,
            entries: Vec::new(),
            ..Default::default()
        };
        plan.record_transition(42, 0, ENTRY_PRED_BB);
        plan.record_transition(42, 1, 0);
        let mut counter = 0i32;
        plan.fill_handler_tables_with(|_| {
            counter += 1;
            counter
        }, 0x1234);
        let bytes = plan.to_embedded_bytes();
        let parsed = BlockMapPlan::from_embedded(&bytes).unwrap();
        assert_eq!(parsed.decode_key, 0xAABB);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].handler_table, plan.entries[0].handler_table);
        assert_ne!(parsed.entries[0].wire, parsed.entries[1].wire);
        assert_eq!(parsed.entries[0].tx_id, 0);
        assert_eq!(parsed.entries[1].pred_bb_id, 0);
    }
}
