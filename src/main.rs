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
        Commands::Pack { input, output, rva, seed } => {
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
            handle_pack_command(input, output, rva_value, seed_value)?;
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
    
    let opcode_map = packer::extract_opcode_map_from_packed(&pe)?;
    let bytecode = packer::extract_bytecode_from_packed(&pe)?;
    
    let instructions = ir::Instruction::disassemble(&bytecode, &opcode_map);
    let output = ir::Instruction::pretty_print(&instructions);
    
    println!("{}", output);
    
    Ok(())
}

fn handle_pack_command(
    input: std::path::PathBuf,
    output: std::path::PathBuf,
    rva: Option<u32>,
    seed: Option<u64>,
) -> Result<()> {
    pack::pack_executable(&input, &output, rva, seed)?;
    println!("Successfully packed {} -> {}", input.display(), output.display());
    Ok(())
}
