use crate::pe::{PEFile, pack_function};
use anyhow::{Context, Result};
use std::path::Path;

pub fn pack_executable<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    function_rva: Option<u32>,
) -> Result<()> {
    let mut pe = PEFile::from_file(&input_path)
        .context("Failed to parse input PE file")?;

    let bytecode = pack_function(&mut pe, function_rva)
        .context("Failed to pack function")?;

    eprintln!("Generated {} bytes of VM bytecode", bytecode.len());

    pe.write_to_file(&output_path)
        .context("Failed to write output PE file")?;

    Ok(())
}
