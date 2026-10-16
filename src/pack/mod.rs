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
    nested_vm: bool,
) -> Result<OpcodeMap> {
    pack_executable_with_options(
        input_path,
        output_path,
        function_rva,
        seed,
        partial,
        dispatch_mode,
        mba_level,
        isa_mode,
        nested_vm,
        false,
        None,
    )
}

pub fn pack_executable_with_options<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    function_rva: Option<u32>,
    seed: Option<u64>,
    partial: bool,
    dispatch_mode: DispatchMode,
    mba_level: u8,
    isa_mode: IsaMode,
    nested_vm: bool,
    strip_meta: bool,
    sidecar_path: Option<&Path>,
) -> Result<OpcodeMap> {
    pack_executable_with_full_options(
        input_path,
        output_path,
        function_rva,
        seed,
        partial,
        dispatch_mode,
        mba_level,
        isa_mode,
        nested_vm,
        strip_meta,
        sidecar_path,
        false,
        false,
    )
}

pub fn pack_executable_with_full_options<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    function_rva: Option<u32>,
    seed: Option<u64>,
    partial: bool,
    dispatch_mode: DispatchMode,
    mba_level: u8,
    isa_mode: IsaMode,
    nested_vm: bool,
    strip_meta: bool,
    sidecar_path: Option<&Path>,
    strict: bool,
    return_mode: bool,
) -> Result<OpcodeMap> {
    let rvas: Vec<u32> = function_rva.into_iter().collect();
    pack_executable_l8(
        input_path,
        output_path,
        &rvas,
        seed,
        partial,
        dispatch_mode,
        mba_level,
        isa_mode,
        nested_vm,
        strip_meta,
        sidecar_path,
        strict,
        return_mode,
        false,
    )
}

/// Pack one or more RVAs. An empty slice auto-detects `main`.
pub fn pack_executable_l8<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    rvas: &[u32],
    seed: Option<u64>,
    partial: bool,
    dispatch_mode: DispatchMode,
    mba_level: u8,
    isa_mode: IsaMode,
    nested_vm: bool,
    strip_meta: bool,
    sidecar_path: Option<&Path>,
    strict: bool,
    return_mode: bool,
    rolling_cipher: bool,
) -> Result<OpcodeMap> {
    let mut pe = PEFile::from_file(&input_path)
        .context("Failed to parse input PE file")?;

    let pack_result = packer::pack_functions_l8(
        &mut pe,
        rvas,
        seed,
        partial,
        dispatch_mode,
        mba_level,
        isa_mode,
        nested_vm,
        strict,
        return_mode,
        rolling_cipher,
    )
        .context("Failed to pack function")?;

    if strip_meta || sidecar_path.is_some() {
        let sidecar = if strip_meta {
            packer::scrub_embedded_metadata_in_pe(&mut pe, pack_result.seed)
                .context("Failed to scrub embedded metadata")?
        } else {
            packer::SidecarMap::from_packed_pe(&pe)
                .context("Failed to extract sidecar map")?
        };
        let default_sc_path = {
            let mut s = output_path.as_ref().as_os_str().to_os_string();
            s.push(".knvmap");
            std::path::PathBuf::from(s)
        };
        let target_sc = sidecar_path.unwrap_or(&default_sc_path);
        sidecar
            .save_to_path(target_sc)
            .context("Failed to write .knvmap sidecar file")?;
    }

    eprintln!(
        "Generated {} bytes of VM bytecode (L4a seed={}, dispatch={}, mba={}, isa={}, nested={}, strip_meta={})",
        pack_result.bytecode.len(),
        pack_result.seed,
        pack_result.dispatch_mode,
        mba_level,
        isa_mode,
        nested_vm,
        strip_meta,
    );

    pe.write_to_file(&output_path)
        .context("Failed to write output PE file")?;

    Ok(pack_result.opcode_map)
}
