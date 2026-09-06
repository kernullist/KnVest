pub mod vm;
pub mod ir;
pub mod pe;
pub mod pack;

pub use pe::test_pe;
pub use vm::{OpCode, OpcodeMap, DispatchMode, PackMetadata};
pub use pe::{PEFile, packer};
pub use pe::partial::{PartialVirtPlan, KNV5_MAGIC};
pub use vm::{BlockMapPlan, KNV6_MAGIC, META_WIRE_BYTE};
pub use ir::Instruction;

pub fn pack_executable<P: AsRef<std::path::Path>, Q: AsRef<std::path::Path>>(
    input: P,
    output: Q,
    rva: Option<u32>,
    seed: Option<u64>,
    partial: bool,
    dispatch_mode: DispatchMode,
) -> anyhow::Result<OpcodeMap> {
    pack::pack_executable(input, output, rva, seed, partial, dispatch_mode)
}

pub fn extract_opcode_map(pe: &PEFile) -> Result<OpcodeMap, pe::PEError> {
    packer::extract_opcode_map_from_packed(pe)
}

pub fn extract_bytecode(pe: &PEFile) -> Result<Vec<u8>, pe::PEError> {
    packer::extract_bytecode_from_packed(pe)
}

pub fn disassemble(bytecode: &[u8], opcode_map: &OpcodeMap, dispatch_mode: DispatchMode) -> Vec<Instruction> {
    Instruction::disassemble(bytecode, opcode_map, dispatch_mode)
}

pub fn extract_block_map_plan(pe: &PEFile) -> Result<BlockMapPlan, pe::PEError> {
    packer::extract_block_map_from_packed(pe)
}

pub fn disassemble_with_block_maps(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    block_plan: Option<&BlockMapPlan>,
    dispatch_mode: DispatchMode,
) -> Vec<Instruction> {
    Instruction::disassemble_with_block_maps(bytecode, opcode_map, block_plan, dispatch_mode)
}

pub fn pretty_print(instructions: &[Instruction]) -> String {
    Instruction::pretty_print(instructions)
}

pub fn extract_partial_plan(pe: &PEFile) -> Result<PartialVirtPlan, pe::PEError> {
    packer::extract_partial_plan_from_packed(pe)
}
