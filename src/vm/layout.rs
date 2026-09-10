use super::block_map::{BlockMapPlan, META_OPERAND_LEN, META_WIRE_BYTE};
use super::dispatch::{DispatchMode, THREAD_TARGET_SIZE};
use super::opcode::OpCode;
use super::opcode_map::{CANONICAL_OPCODES, OpcodeMap};

pub const KNV7_MAGIC: &[u8; 4] = b"KNV7";
pub const KNV7_VERSION: u8 = 1;
pub const KNV7_HEADER_SIZE: usize = 4 + 1 + 4 + 21 + 1;

const LAYOUT_KEY_SALT: u64 = 0x4C41_594F; // "LAYO"
const WIRE_PAD_SALT: u64 = 0x5750_4144; // "WPAD"
const META_WIRE_PAD_SALT: u64 = 0x4D57_5044; // "MWPD"

/// L5c: seed-derived post-wire slot offsets (padding before operand bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytecodeLayout {
    pub layout_key: u32,
    pub post_wire_pad: [u8; 21],
    pub meta_post_wire_pad: u8,
}

impl BytecodeLayout {
    pub fn from_seed(seed: u64) -> Self {
        let layout_key = (splitmix64(seed ^ LAYOUT_KEY_SALT) >> 32) as u32;
        let mut post_wire_pad = [0u8; 21];
        for (idx, op) in CANONICAL_OPCODES.iter().enumerate() {
            post_wire_pad[idx] = pad_for_opcode(seed, WIRE_PAD_SALT, *op);
        }
        let meta_post_wire_pad = (splitmix64(seed ^ META_WIRE_PAD_SALT) & 3) as u8;
        Self {
            layout_key,
            post_wire_pad,
            meta_post_wire_pad,
        }
    }

    /// Identity layout (no padding) for raw bytecode without KNV7.
    pub fn identity() -> Self {
        Self {
            layout_key: 0,
            post_wire_pad: [0; 21],
            meta_post_wire_pad: 0,
        }
    }

    pub fn post_wire_pad_for(&self, op: OpCode) -> u8 {
        canonical_index(op).map(|i| self.post_wire_pad[i]).unwrap_or(0)
    }

    /// Byte offset from instruction start to first operand byte (table mode).
    pub fn operands_offset(&self, op: OpCode, is_meta: bool) -> usize {
        self.operands_offset_dispatch(op, is_meta, DispatchMode::Table)
    }

    pub fn operands_offset_dispatch(
        &self,
        op: OpCode,
        is_meta: bool,
        dispatch_mode: DispatchMode,
    ) -> usize {
        let header = match dispatch_mode {
            DispatchMode::Table => 1,
            DispatchMode::Threaded => 1 + THREAD_TARGET_SIZE,
        };
        if is_meta {
            header + self.meta_post_wire_pad as usize
        } else {
            header + self.post_wire_pad_for(op) as usize
        }
    }

    pub fn table_insn_len(&self, op: OpCode, operand_len: usize) -> usize {
        1 + self.post_wire_pad_for(op) as usize + operand_len
    }

    pub fn table_meta_len(&self) -> usize {
        1 + self.meta_post_wire_pad as usize + META_OPERAND_LEN
    }

    pub fn insn_len(
        &self,
        op: OpCode,
        operand_len: usize,
        dispatch_mode: DispatchMode,
        is_meta: bool,
    ) -> usize {
        if is_meta {
            match dispatch_mode {
                DispatchMode::Table => self.table_meta_len(),
                DispatchMode::Threaded => {
                    1 + THREAD_TARGET_SIZE + self.meta_post_wire_pad as usize + META_OPERAND_LEN
                }
            }
        } else {
            match dispatch_mode {
                DispatchMode::Table => self.table_insn_len(op, operand_len),
                DispatchMode::Threaded => {
                    1 + THREAD_TARGET_SIZE + self.post_wire_pad_for(op) as usize + operand_len
                }
            }
        }
    }

    pub fn to_embedded_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KNV7_HEADER_SIZE);
        out.extend_from_slice(KNV7_MAGIC);
        out.push(KNV7_VERSION);
        out.extend_from_slice(&self.layout_key.to_le_bytes());
        out.extend_from_slice(&self.post_wire_pad);
        out.push(self.meta_post_wire_pad);
        out
    }

    pub fn from_embedded(data: &[u8]) -> Option<Self> {
        if data.len() < KNV7_HEADER_SIZE || &data[0..4] != KNV7_MAGIC {
            return None;
        }
        if data[4] != KNV7_VERSION {
            return None;
        }
        let layout_key = u32::from_le_bytes(data[5..9].try_into().unwrap());
        let mut post_wire_pad = [0u8; 21];
        post_wire_pad.copy_from_slice(&data[9..30]);
        Some(Self {
            layout_key,
            post_wire_pad,
            meta_post_wire_pad: data[30],
        })
    }

    pub fn format_ir_header(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "L5c bytecode layout | layout_key={:#x} | wire_pad[load_imm]={} | meta_wire_pad={}\n",
            self.layout_key,
            self.post_wire_pad_for(OpCode::LoadImm),
            self.meta_post_wire_pad,
        ));
        out.push_str("op        | wire_pad\n");
        out.push_str("----------+---------\n");
        for (idx, op) in CANONICAL_OPCODES.iter().enumerate() {
            out.push_str(&format!("{:<9} | {:8}\n", op.name(), self.post_wire_pad[idx]));
        }
        out.push('\n');
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawInsnKind {
    Semantic(OpCode),
    SetBlockMap,
}

#[derive(Clone, Copy, Debug)]
pub struct RawInsn {
    pub start: usize,
    pub kind: RawInsnKind,
    pub raw_len: usize,
}

pub fn enumerate_raw_instructions(
    bytecode: &[u8],
    base_map: &OpcodeMap,
    block_plan: &BlockMapPlan,
    layout: &BytecodeLayout,
    dispatch_mode: DispatchMode,
) -> Vec<RawInsn> {
    let mut out = Vec::new();
    let mut offset = 0;
    let mut current_bb: Option<u16> = None;
    while offset < bytecode.len() {
        let wire = bytecode[offset];
        if wire == META_WIRE_BYTE {
            let total = layout.insn_len(
                OpCode::SetBlockMap,
                META_OPERAND_LEN,
                dispatch_mode,
                true,
            );
            if offset + total > bytecode.len() {
                break;
            }
            let op_off = offset + layout.operands_offset_dispatch(OpCode::SetBlockMap, true, dispatch_mode);
            current_bb = Some(u16::from_le_bytes([bytecode[op_off], bytecode[op_off + 1]]));
            out.push(RawInsn {
                start: offset,
                kind: RawInsnKind::SetBlockMap,
                raw_len: total,
            });
            offset += total;
            continue;
        }
        let map = current_bb
            .map(|id| block_plan.map_for_tx_or_base(id, base_map))
            .unwrap_or_else(|| base_map.clone());
        let op = match map.decode(wire) {
            Some(op) => op,
            None => break,
        };
        let operand_len = op.operand_len();
        let total = layout.insn_len(op, operand_len, dispatch_mode, false);
        if offset + total > bytecode.len() {
            break;
        }
        out.push(RawInsn {
            start: offset,
            kind: RawInsnKind::Semantic(op),
            raw_len: total,
        });
        offset += total;
    }
    out
}

fn canonical_index(op: OpCode) -> Option<usize> {
    CANONICAL_OPCODES.iter().position(|&o| o == op)
}

fn pad_for_opcode(seed: u64, salt: u64, op: OpCode) -> u8 {
    let idx = canonical_index(op).unwrap_or(0) as u64;
    (splitmix64(seed ^ salt ^ idx) & 3) as u8
}

fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_differs_by_seed() {
        let a = BytecodeLayout::from_seed(1);
        let b = BytecodeLayout::from_seed(2);
        assert_ne!(a.layout_key, b.layout_key);
        assert_ne!(a.post_wire_pad, b.post_wire_pad);
    }

    #[test]
    fn knv7_roundtrip() {
        let layout = BytecodeLayout::from_seed(0xABCD);
        let bytes = layout.to_embedded_bytes();
        let parsed = BytecodeLayout::from_embedded(&bytes).unwrap();
        assert_eq!(parsed, layout);
    }

    #[test]
    fn identity_layout_zero_pads() {
        let id = BytecodeLayout::identity();
        assert_eq!(id.post_wire_pad_for(OpCode::Add), 0);
        assert_eq!(id.table_insn_len(OpCode::LoadImm, 9), 10);
    }
}
