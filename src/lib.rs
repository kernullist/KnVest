pub mod vm;
pub mod ir;
pub mod pe;
pub mod pack;

pub use pe::test_pe;
pub use vm::OpCode;
pub use pe::{PEFile, packer};
pub use ir::Instruction;

pub fn pack_executable<P: AsRef<std::path::Path>, Q: AsRef<std::path::Path>>(
    input: P,
    output: Q,
    rva: Option<u32>,
) -> anyhow::Result<()> {
    pack::pack_executable(input, output, rva)
}

pub fn extract_bytecode(pe: &PEFile) -> Result<Vec<u8>, pe::PEError> {
    packer::extract_bytecode_from_packed(pe)
}

pub fn disassemble(bytecode: &[u8]) -> Vec<Instruction> {
    Instruction::disassemble(bytecode)
}

pub fn pretty_print(instructions: &[Instruction]) -> String {
    Instruction::pretty_print(instructions)
}
