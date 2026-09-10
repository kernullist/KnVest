mod vm;
mod ir;
mod pe;
mod pack;
mod cli;

use anyhow::Result;
use cli::{Cli, Commands};
use pe::{PEFile, packer};

fn main() -> Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Commands::Ir { input } => {
            handle_ir_command(input)?;
        }
        Commands::Pack { input, output, rva, seed, partial, dispatch, mba } => {
            let rva_value = if let Some(rva_str) = rva {
                let rva_str = rva_str.trim_start_matches("0x");
                Some(u32::from_str_radix(rva_str, 16)?)
            } else {
                None
            };
            let seed_value = if let Some(seed_str) = seed {
                Some(parse_seed(&seed_str)?)
            } else {
                None
            };
            let dispatch_mode = dispatch
                .parse::<crate::vm::DispatchMode>()
                .map_err(|e| anyhow::anyhow!(e))?;
            handle_pack_command(input, output, rva_value, seed_value, partial, dispatch_mode, mba)?;
        }
    }

    Ok(())
}

fn parse_seed(seed_str: &str) -> Result<u64> {
    let s = seed_str.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(s.parse()?)
    }
}

fn handle_ir_command(input: std::path::PathBuf) -> Result<()> {
    let pe = PEFile::from_file(&input)?;
    
    let pack_meta = packer::extract_pack_metadata_from_packed(&pe)?;
    let opcode_map = pack_meta.opcode_map;
    let dispatch_mode = pack_meta.dispatch_mode;
    let partial_plan = packer::extract_partial_plan_from_packed(&pe).ok();
    let bytecode = packer::extract_bytecode_from_packed(&pe)?;
    
    println!(
        "L4c dispatch={} | L4a seed={:#x}",
        dispatch_mode,
        opcode_map.seed()
    );
    
    if let Some(plan) = partial_plan {
        print!("{}", plan.format_ir_header(&opcode_map, dispatch_mode));
    }

    let block_plan = packer::extract_block_map_from_packed(&pe).ok();
    if let Some(ref plan) = block_plan {
        print!("{}", plan.format_ir_header(&opcode_map, dispatch_mode));
    }

    if pack_meta.mba_enabled {
        print!("{}", crate::pe::mba::format_ir_header(true));
    }

    print!(
        "{}",
        crate::vm::virt_isa::format_ir_header(&opcode_map, dispatch_mode)
    );
    
    let instructions = ir::Instruction::disassemble_with_block_maps(
        &bytecode,
        &opcode_map,
        block_plan.as_ref(),
        dispatch_mode,
    );
    let output = ir::Instruction::pretty_print_with_mba(&instructions, pack_meta.mba_enabled);
    
    println!("{}", output);
    
    Ok(())
}

fn handle_pack_command(
    input: std::path::PathBuf,
    output: std::path::PathBuf,
    rva: Option<u32>,
    seed: Option<u64>,
    partial: bool,
    dispatch_mode: crate::vm::DispatchMode,
    mba: bool,
) -> Result<()> {
    pack::pack_executable(&input, &output, rva, seed, partial, dispatch_mode, mba)?;
    println!("Successfully packed {} -> {}", input.display(), output.display());
    Ok(())
}
