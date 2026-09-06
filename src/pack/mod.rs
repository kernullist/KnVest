use crate::pe::{PEFile, packer};
use crate::vm::OpcodeMap;
use anyhow::{Context, Result};
use std::path::Path;

pub fn pack_executable<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    function_rva: Option<u32>,
    seed: Option<u64>,
    partial: bool,
) -> Result<OpcodeMap> {
    let mut pe = PEFile::from_file(&input_path)
        .context("Failed to parse input PE file")?;

    let pack_result = packer::pack_function(&mut pe, function_rva, seed, partial)
        .context("Failed to pack function")?;

    eprintln!(
        "Generated {} bytes of VM bytecode (L4a seed={})",
        pack_result.bytecode.len(),
        pack_result.seed
    );

    pe.write_to_file(&output_path)
        .context("Failed to write output PE file")?;

    Ok(pack_result.opcode_map)
}
