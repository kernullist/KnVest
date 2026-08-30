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
        Commands::Pack { input, output, rva } => {
            let rva_value = if let Some(rva_str) = rva {
                let rva_str = rva_str.trim_start_matches("0x");
                Some(u32::from_str_radix(rva_str, 16)?)
            } else {
                None
            };
            handle_pack_command(input, output, rva_value)?;
        }
    }

    Ok(())
}

fn handle_ir_command(input: std::path::PathBuf) -> Result<()> {
    let pe = PEFile::from_file(&input)?;
    
    let bytecode = packer::extract_bytecode_from_packed(&pe)?;
    
    let instructions = ir::Instruction::disassemble(&bytecode);
    let output = ir::Instruction::pretty_print(&instructions);
    
    println!("{}", output);
    
    Ok(())
}

fn handle_pack_command(
    input: std::path::PathBuf,
    output: std::path::PathBuf,
    rva: Option<u32>,
) -> Result<()> {
    pack::pack_executable(&input, &output, rva)?;
    println!("Successfully packed {} -> {}", input.display(), output.display());
    Ok(())
}
