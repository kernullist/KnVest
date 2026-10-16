use super::block_map::{BlockMapPlan, META_OPERAND_LEN, META_WIRE_BYTE};
use super::dispatch::{DispatchMode, THREAD_TARGET_SIZE};
use super::isa_mode::IsaMode;
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
    isa_mode: IsaMode,
) -> Vec<RawInsn> {
    enumerate_raw_instructions_masked(
        bytecode,
        base_map,
        block_plan,
        layout,
        dispatch_mode,
        isa_mode,
        None,
    )
}

/// Same walk as [`enumerate_raw_instructions`], but XOR each instruction-start
/// wire with `rolling_wire_mask(seed, offset)` before decode when `rolling_seed` is set.
pub fn enumerate_raw_instructions_masked(
    bytecode: &[u8],
    base_map: &OpcodeMap,
    block_plan: &BlockMapPlan,
    layout: &BytecodeLayout,
    dispatch_mode: DispatchMode,
    isa_mode: IsaMode,
    rolling_seed: Option<u64>,
) -> Vec<RawInsn> {
    let mut out = Vec::new();
    let mut offset = 0;
    let mut current_bb: Option<u16> = None;
    while offset < bytecode.len() {
        let mut wire = bytecode[offset];
        if let Some(seed) = rolling_seed {
            wire ^= super::l8::rolling_wire_mask(seed, offset);
        }
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
        let operand_len = op.operand_len_for_isa(isa_mode);
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

const STREAM_CIPHER_SALT: u64 = 0x4B4E_5637_5354_524D; // "KNV7STRM"
const REG_PERM_SALT: u64 = 0x4B4E_5637_5250_4552; // "KNV7RPER"

/// L7.4: Rolling SplitMix64 stream cipher for bytecode & metadata obfuscation
/// and seed-derived register slot permutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytecodeCipher {
    pub seed: u64,
    pub initial_state: u64,
    pub reg_perm: [u8; 32],
    pub inv_reg_perm: [u8; 32],
}

impl BytecodeCipher {
    pub fn from_seed(seed: u64) -> Self {
        let initial_state = splitmix64(seed ^ STREAM_CIPHER_SALT);
        // Permute extended local spill slots r16..=r31 while keeping ABI & core slots r0..=r15 fixed
        // so Win64 ABI conventions (r0..r3) and scratch slots (r14, r15) remain deterministic.
        let mut reg_perm = [0u8; 32];
        let mut inv_reg_perm = [0u8; 32];
        for i in 0..32u8 {
            reg_perm[i as usize] = i;
        }
        let mut s = seed ^ REG_PERM_SALT;
        for i in (17..32usize).rev() {
            s = splitmix64(s);
            let span = i - 16 + 1;
            let j = 16 + (s as usize % span);
            reg_perm.swap(i, j);
        }
        for (idx, &mapped) in reg_perm.iter().enumerate() {
            inv_reg_perm[mapped as usize] = idx as u8;
        }
        Self {
            seed,
            initial_state,
            reg_perm,
            inv_reg_perm,
        }
    }

    /// Generate the rolling XOR key byte at stream position `offset`.
    #[inline]
    pub fn keystream_byte(&self, offset: usize) -> u8 {
        let word_idx = (offset / 8) as u64;
        let byte_idx = (offset % 8) * 8;
        let word = splitmix64(self.initial_state.wrapping_add(word_idx.wrapping_mul(0x9E37_79B9_7F4A_7C15)));
        ((word >> byte_idx) & 0xFF) as u8
    }

    /// Apply symmetric rolling XOR stream cipher in-place.
    pub fn apply_keystream(&self, buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= self.keystream_byte(i);
        }
    }

    /// Encrypt a slice and return the ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = plaintext.to_vec();
        self.apply_keystream(&mut out);
        out
    }

    /// Decrypt a slice and return the plaintext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut out = ciphertext.to_vec();
        self.apply_keystream(&mut out);
        out
    }

    /// Map a logical VM register index (`0..32`) to its seed-diversified physical slot.
    #[inline]
    pub fn map_reg(&self, logical_reg: u8) -> u8 {
        if (logical_reg as usize) < 32 {
            self.reg_perm[logical_reg as usize]
        } else {
            logical_reg
        }
    }

    /// Map a physical slot index (`0..32`) back to its logical VM register.
    #[inline]
    pub fn unmap_reg(&self, physical_reg: u8) -> u8 {
        if (physical_reg as usize) < 32 {
            self.inv_reg_perm[physical_reg as usize]
        } else {
            physical_reg
        }
    }
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
