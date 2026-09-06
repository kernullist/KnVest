pub mod vm;
pub mod ir;
pub mod pe;
pub mod pack;

pub use pe::test_pe;
pub use vm::{OpCode, OpcodeMap};
pub use pe::{PEFile, packer};
pub use pe::partial::{PartialVirtPlan, KNV5_MAGIC};
pub use ir::Instruction;

pub fn pack_executable<P: AsRef<std::path::Path>, Q: AsRef<std::path::Path>>(
    input: P,
    output: Q,
    rva: Option<u32>,
    seed: Option<u64>,
) -> anyhow::Result<OpcodeMap> {
    pack::pack_executable(input, output, rva, seed)
}

pub fn extract_opcode_map(pe: &PEFile) -> Result<OpcodeMap, pe::PEError> {
    packer::extract_opcode_map_from_packed(pe)
}

pub fn extract_bytecode(pe: &PEFile) -> Result<Vec<u8>, pe::PEError> {
    packer::extract_bytecode_from_packed(pe)
}

pub fn disassemble(bytecode: &[u8], opcode_map: &OpcodeMap) -> Vec<Instruction> {
    Instruction::disassemble(bytecode, opcode_map)
}

pub fn pretty_print(instructions: &[Instruction]) -> String {
    Instruction::pretty_print(instructions)
}

pub fn extract_partial_plan(pe: &PEFile) -> Result<PartialVirtPlan, pe::PEError> {
    packer::extract_partial_plan_from_packed(pe)
}
