use crate::pe::{PEFile, packer};
use crate::vm::{DispatchMode, IsaMode, OpcodeMap};
use anyhow::{Context, Result};
use std::path::Path;

pub fn pack_executable<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    function_rva: Option<u32>,
    seed: Option<u64>,
    partial: bool,
    dispatch_mode: DispatchMode,
    mba_level: u8,
    isa_mode: IsaMode,
) -> Result<OpcodeMap> {
    let mut pe = PEFile::from_file(&input_path)
        .context("Failed to parse input PE file")?;

    let pack_result = packer::pack_function(
        &mut pe,
        function_rva,
        seed,
        partial,
        dispatch_mode,
        mba_level,
        isa_mode,
    )
        .context("Failed to pack function")?;

    eprintln!(
        "Generated {} bytes of VM bytecode (L4a seed={}, dispatch={}, mba={}, isa={})",
        pack_result.bytecode.len(),
        pack_result.seed,
        pack_result.dispatch_mode,
        mba_level,
        isa_mode
    );

    pe.write_to_file(&output_path)
        .context("Failed to write output PE file")?;

    Ok(pack_result.opcode_map)
}
