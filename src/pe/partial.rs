use super::cfg::BasicBlock;
use super::lifter::X64Instruction;
use super::parser::{PEFile, PEResult};
use std::collections::HashSet;

pub const KNV5_MAGIC: &[u8; 4] = b"KNV5";
pub const KNV5_VERSION: u8 = 1;
pub const KNV5_ENTRY_SIZE: usize = 2 + 4 + 4 + 1;

const SELECT_SALT: u64 = 0x4C34_4400; // "L4D\0"
const KEY_SALT: u64 = 0x4445_434B; // "DECK"

#[derive(Debug, Clone)]
pub struct PartialVirtPlan {
    pub decode_key: u32,
    pub blocks: Vec<PartialBlockInfo>,
    pub vm_bb_ids: HashSet<usize>,
    /// When true, every main BB is virtualized (legacy full-virt path).
    pub full_virt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialBlockInfo {
    pub id: usize,
    pub start_rva: u32,
    pub end_rva: u32,
    pub virtualized: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NativeSledBuilder {
    pub sleds: Vec<NativeSledEntry>,
}

#[derive(Debug, Clone)]
pub struct NativeSledEntry {
    pub bytes: Vec<u8>,
    pub source_rva: u32,
}

impl NativeSledBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_range_sled(
        &mut self,
        pe: &PEFile,
        instrs: &[X64Instruction],
        bb: &BasicBlock,
    ) -> PEResult<(usize, u32)> {
        let mut copy = Vec::new();
        for idx in bb.leader_idx..=bb.tail_idx {
            copy.extend_from_slice(&instrs[idx].bytes);
        }
        copy.push(0xC3);
        let source_rva = pe.file_offset_to_rva(instrs[bb.leader_idx].offset)?;
        let index = self.sleds.len();
        self.sleds.push(NativeSledEntry {
            bytes: copy,
            source_rva,
        });
        Ok((index, source_rva))
    }

    pub fn add_instr_sled(&mut self, pe: &PEFile, instr: &X64Instruction) -> PEResult<(usize, u32)> {
        let mut copy = instr.bytes.clone();
        copy.push(0xC3);
        let source_rva = pe.file_offset_to_rva(instr.offset)?;
        let index = self.sleds.len();
        self.sleds.push(NativeSledEntry {
            bytes: copy,
            source_rva,
        });
        Ok((index, source_rva))
    }

    pub fn blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for sled in &self.sleds {
            out.extend_from_slice(&sled.bytes);
        }
        out
    }

    pub fn sled_offset(&self, index: usize) -> u64 {
        self.sleds
            .iter()
            .take(index)
            .map(|s| s.bytes.len() as u64)
            .sum()
    }
}

impl PartialVirtPlan {
    pub fn from_seed(
        seed: u64,
        blocks: &[BasicBlock],
        main_start: usize,
        pe: &PEFile,
        partial_enabled: bool,
    ) -> PEResult<Self> {
        let decode_key = (splitmix64(seed ^ KEY_SALT) >> 32) as u32;
        let main_blocks: Vec<&BasicBlock> = blocks
            .iter()
            .filter(|b| b.start >= main_start)
            .collect();

        if main_blocks.is_empty() || !partial_enabled {
            let mut infos = Vec::new();
            for bb in &main_blocks {
                let start_rva = pe.file_offset_to_rva(bb.start)?;
                let end_rva = pe.file_offset_to_rva(bb.end.saturating_sub(1))?;
                infos.push(PartialBlockInfo {
                    id: bb.id,
                    start_rva,
                    end_rva,
                    virtualized: true,
                });
            }
            let vm_bb_ids: HashSet<usize> = main_blocks.iter().map(|b| b.id).collect();
            return Ok(Self {
                decode_key,
                blocks: infos,
                vm_bb_ids,
                full_virt: true,
            });
        }

        let vm_bb_ids = select_vm_bb_ids(seed, &main_blocks);
        let full_virt = vm_bb_ids.len() == main_blocks.len();

        let mut infos = Vec::with_capacity(main_blocks.len());
        for bb in &main_blocks {
            let start_rva = pe.file_offset_to_rva(bb.start)?;
            let end_rva = pe.file_offset_to_rva(bb.end.saturating_sub(1))?;
            infos.push(PartialBlockInfo {
                id: bb.id,
                start_rva,
                end_rva,
                virtualized: vm_bb_ids.contains(&bb.id),
            });
        }

        Ok(Self {
            decode_key,
            blocks: infos,
            vm_bb_ids,
            full_virt,
        })
    }

    pub fn is_vm_bb(&self, bb_id: usize) -> bool {
        self.full_virt || self.vm_bb_ids.contains(&bb_id)
    }

    pub fn to_embedded_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(KNV5_MAGIC);
        out.push(KNV5_VERSION);
        out.extend_from_slice(&self.decode_key.to_le_bytes());
        out.push(if self.full_virt { 1 } else { 0 });
        out.extend_from_slice(&(self.blocks.len() as u16).to_le_bytes());
        for entry in &self.blocks {
            out.extend_from_slice(&(entry.id as u16).to_le_bytes());
            out.extend_from_slice(&entry.start_rva.to_le_bytes());
            out.extend_from_slice(&entry.end_rva.to_le_bytes());
            out.push(if entry.virtualized { 1 } else { 0 });
        }
        out
    }

    pub fn from_embedded(data: &[u8]) -> Option<Self> {
        let min = 4 + 1 + 4 + 1 + 2;
        if data.len() < min || &data[0..4] != KNV5_MAGIC {
            return None;
        }
        if data[4] != KNV5_VERSION {
            return None;
        }
        let decode_key = u32::from_le_bytes(data[5..9].try_into().ok()?);
        let full_virt = data[9] != 0;
        let count = u16::from_le_bytes(data[10..12].try_into().ok()?) as usize;
        let mut offset = 12usize;
        let mut blocks = Vec::with_capacity(count);
        let mut vm_bb_ids = HashSet::new();
        for _ in 0..count {
            if offset + KNV5_ENTRY_SIZE > data.len() {
                return None;
            }
            let id = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
            let start_rva = u32::from_le_bytes(data[offset + 2..offset + 6].try_into().ok()?);
            let end_rva = u32::from_le_bytes(data[offset + 6..offset + 10].try_into().ok()?);
            let virtualized = data[offset + 10] != 0;
            offset += KNV5_ENTRY_SIZE;
            if virtualized {
                vm_bb_ids.insert(id);
            }
            blocks.push(PartialBlockInfo {
                id,
                start_rva,
                end_rva,
                virtualized,
            });
        }
        Some(Self {
            decode_key,
            blocks,
            vm_bb_ids,
            full_virt,
        })
    }

    pub fn format_ir_header(&self, opcode_map: &crate::vm::OpcodeMap) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "L4d partial virt | decode_key={:#x} | seed={:#x} | mode={}\n",
            self.decode_key,
            opcode_map.seed(),
            if self.full_virt {
                "full"
            } else {
                "partial"
            }
        ));
        out.push_str("BB id | RVA range        | VM?\n");
        out.push_str("------+------------------+-----\n");
        for bb in &self.blocks {
            out.push_str(&format!(
                "{:5} | {:#010x}..{:#x} | {}\n",
                bb.id,
                bb.start_rva,
                bb.end_rva,
                if bb.virtualized { "yes" } else { "native" }
            ));
        }
        out.push_str("\n");
        out
    }
}

fn select_vm_bb_ids(seed: u64, main_blocks: &[&BasicBlock]) -> HashSet<usize> {
    if main_blocks.len() <= 1 {
        return main_blocks.iter().map(|b| b.id).collect();
    }

    let loop_ids: Vec<usize> = main_blocks
        .iter()
        .filter(|b| b.has_back_edge)
        .map(|b| b.id)
        .collect();
    let native_eligible: Vec<usize> = main_blocks
        .iter()
        .filter(|b| b.native_eligible)
        .map(|b| b.id)
        .collect();

    if loop_ids.is_empty() && native_eligible.is_empty() {
        return main_blocks.iter().map(|b| b.id).collect();
    }

    let mut vm_ids: HashSet<usize> = loop_ids.iter().copied().collect();

    let mut candidates: Vec<usize> = main_blocks
        .iter()
        .filter(|b| !vm_ids.contains(&b.id))
        .map(|b| b.id)
        .collect();
    candidates.sort_unstable();

    if candidates.is_empty() {
        return vm_ids;
    }

    let pick = splitmix64(seed ^ SELECT_SALT) as usize % candidates.len();
    vm_ids.insert(candidates[pick]);

    if vm_ids.len() >= main_blocks.len() {
        if let Some(strip) = native_eligible
            .iter()
            .find(|id| vm_ids.contains(id))
            .copied()
        {
            vm_ids.remove(&strip);
        }
    }

    if vm_ids.is_empty() {
        vm_ids.insert(candidates[pick]);
    }

    vm_ids
}

pub fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::cfg::{build_basic_blocks, disassemble_main_window};
    use crate::pe::test_pe;

    #[test]
    fn partial_plan_roundtrip_and_selects_loop_bb() {
        let pe_data = test_pe::create_pe64_with_countdown_loop();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_start = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let text_end = text_start + text.size_of_raw_data as usize;
        let main_off = text_start + 0x20;
        let instrs = disassemble_main_window(&pe.data, main_off, text_end);
        let blocks = build_basic_blocks(&instrs, main_off);
        assert!(blocks.len() >= 2, "expected multiple BBs, got {}", blocks.len());

        let plan = PartialVirtPlan::from_seed(0x14D_2026, &blocks, main_off, &pe, true).unwrap();
        assert!(!plan.full_virt);
        assert!(plan.blocks.iter().any(|b| b.virtualized));
        assert!(plan.blocks.iter().any(|b| !b.virtualized));

        let bytes = plan.to_embedded_bytes();
        let parsed = PartialVirtPlan::from_embedded(&bytes).unwrap();
        assert_eq!(parsed.decode_key, plan.decode_key);
        assert_eq!(parsed.blocks.len(), plan.blocks.len());
    }

    #[test]
    fn different_seeds_change_vm_bb_set_or_key() {
        let pe_data = test_pe::create_pe64_with_countdown_loop();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_start = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let text_end = text_start + text.size_of_raw_data as usize;
        let main_off = text_start + 0x20;
        let instrs = disassemble_main_window(&pe.data, main_off, text_end);
        let blocks = build_basic_blocks(&instrs, main_off);
        let a = PartialVirtPlan::from_seed(1, &blocks, main_off, &pe, true).unwrap();
        let b = PartialVirtPlan::from_seed(2, &blocks, main_off, &pe, true).unwrap();
        assert!(
            a.decode_key != b.decode_key
                || a.vm_bb_ids != b.vm_bb_ids
                || a.blocks != b.blocks,
            "seed must diversify selection or decode key"
        );
    }
}
