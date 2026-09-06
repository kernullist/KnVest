use super::opcode::OpCode;
use super::opcode_map::{CANONICAL_OPCODE_COUNT, CANONICAL_OPCODES, KNV4_MAGIC, OpcodeMap};

/// Fixed wire byte for L4e block-map refresh (never assigned to semantic opcodes).
pub const META_WIRE_BYTE: u8 = 0xFD;
/// Operand bytes after the meta wire byte at block entry.
pub const META_OPERAND_LEN: usize = 2;

pub const KNV6_MAGIC: &[u8; 4] = b"KNV6";
pub const KNV6_VERSION: u8 = 1;
pub const KNV6_HEADER_SIZE: usize = 4 + 1 + 4 + 2;
pub const KNV6_ENTRY_SIZE: usize = 2 + 4 + 1 + 1 + CANONICAL_OPCODE_COUNT + 256 * 4;

const BLOCK_KEY_SALT: u64 = 0x424C_4B45; // "BLKE"
const KEY_SALT: u64 = 0x4445_434B; // "DECK"

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMapEntry {
    pub bb_id: u16,
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
}

impl BlockMapPlan {
    pub fn global_decode_key(pack_seed: u64) -> u32 {
        (splitmix64(pack_seed ^ KEY_SALT) >> 32) as u32
    }

    pub fn block_decode_key(pack_seed: u64, bb_id: usize) -> u32 {
        (splitmix64(pack_seed ^ BLOCK_KEY_SALT ^ bb_id as u64) >> 32) as u32
    }

    pub fn block_opcode_map(pack_seed: u64, bb_id: usize) -> OpcodeMap {
        OpcodeMap::from_seed(pack_seed ^ BLOCK_KEY_SALT ^ bb_id as u64)
    }

    pub fn record_block(&mut self, pack_seed: u64, bb_id: usize) -> OpcodeMap {
        let map = Self::block_opcode_map(pack_seed, bb_id);
        let decode_key = Self::block_decode_key(pack_seed, bb_id);
        self.entries.push(BlockMapEntry {
            bb_id: bb_id as u16,
            decode_key,
            exit_wire: map.exit_wire(),
            wire: *map.wire_table(),
            handler_table: [0u8; 256 * 4],
        });
        map
    }

    pub fn map_for_bb(&self, bb_id: u16) -> Option<&BlockMapEntry> {
        self.entries.iter().find(|e| e.bb_id == bb_id)
    }

    pub fn map_for_bb_or_base(&self, bb_id: u16, base: &OpcodeMap) -> OpcodeMap {
        self.map_for_bb(bb_id)
            .map(|e| OpcodeMap::from_parts(base.seed(), e.wire))
            .unwrap_or_else(|| Self::block_opcode_map(base.seed(), bb_id as usize))
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
            out.extend_from_slice(&entry.bb_id.to_le_bytes());
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
        if data[4] != KNV6_VERSION {
            return None;
        }
        let decode_key = u32::from_le_bytes(data[5..9].try_into().ok()?);
        let count = u16::from_le_bytes(data[9..11].try_into().ok()?) as usize;
        let mut offset = KNV6_HEADER_SIZE;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if offset + KNV6_ENTRY_SIZE > data.len() {
                return None;
            }
            let bb_id = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
            offset += 2;
            let block_key = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
            offset += 4;
            let exit_wire = data[offset];
            offset += 2;
            let mut wire = [0u8; CANONICAL_OPCODE_COUNT];
            wire.copy_from_slice(&data[offset..offset + CANONICAL_OPCODE_COUNT]);
            offset += CANONICAL_OPCODE_COUNT;
            let mut handler_table = [0u8; 256 * 4];
            handler_table.copy_from_slice(&data[offset..offset + 256 * 4]);
            offset += 256 * 4;
            entries.push(BlockMapEntry {
                bb_id,
                decode_key: block_key,
                exit_wire,
                wire,
                handler_table,
            });
        }
        Some(Self { decode_key, entries })
    }

    pub fn format_ir_header(
        &self,
        base_map: &OpcodeMap,
        dispatch_mode: crate::vm::DispatchMode,
    ) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "L4e block opcode maps | global_key={:#x} | seed={:#x} | dispatch={} | blocks={}\n",
            self.decode_key,
            base_map.seed(),
            dispatch_mode,
            self.entries.len()
        ));
        out.push_str("BB id | decode_key | exit_wire | load_imm wire\n");
        out.push_str("------+------------+-----------+-------------\n");
        for entry in &self.entries {
            let load_imm = entry.wire[CANONICAL_OPCODES
                .iter()
                .position(|&op| op == OpCode::LoadImm)
                .unwrap_or(0)];
            out.push_str(&format!(
                "{:5} | {:#10x} | {:#9x} | {:#11x}\n",
                entry.bb_id, entry.decode_key, entry.exit_wire, load_imm
            ));
        }
        out.push('\n');
        out
    }
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

pub fn block_wire_for_bb(pack_seed: u64, bb_id: usize, op: OpCode) -> u8 {
    BlockMapPlan::block_opcode_map(pack_seed, bb_id).encode(op)
}

pub fn emit_block_map_refresh(bytecode: &mut Vec<u8>, bb_id: usize) {
    bytecode.push(META_WIRE_BYTE);
    bytecode.extend_from_slice(&(bb_id as u16).to_le_bytes());
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

/// Apply one KNV6 entry's redirect table to the stub image (same as `h_set_block_map` copy).
pub fn install_handler_table_in_stub(
    stub: &mut [u8],
    table_base: usize,
    table: &[u8; HANDLER_REDIRECT_TABLE_SIZE],
) {
    stub[table_base..table_base + HANDLER_REDIRECT_TABLE_SIZE].copy_from_slice(table);
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
        // Place PackMetadata marker so handler region ends before the tail.
        stub[0x1800..0x1804].copy_from_slice(KNV4_MAGIC);
        let mut table = [0u8; HANDLER_REDIRECT_TABLE_SIZE];
        // Lands in metadata / appended-bytecode region, not in handler bodies.
        table[0xB5 * 4..0xB5 * 4 + 4].copy_from_slice(&0x800i32.to_le_bytes());
        assert!(validate_handler_table_targets(&stub, table_base, &table).is_err());
    }

    #[test]
    fn knv6_roundtrip_preserves_handler_tables() {
        let mut plan = BlockMapPlan {
            decode_key: 0xAABB,
            entries: Vec::new(),
        };
        plan.record_block(42, 0);
        plan.record_block(42, 1);
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
    }
}
