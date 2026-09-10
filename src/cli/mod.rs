use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "knvest")]
#[command(about = "Toy VM protector + IR viewer for PE64 binaries", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Pretty-print VM bytecode from a packed executable")]
    Ir {
        #[arg(help = "Input executable file")]
        input: PathBuf,
    },
    
    #[command(about = "Pack an executable with VM protection")]
    Pack {
        #[arg(help = "Input executable file")]
        input: PathBuf,
        
        #[arg(short, long, help = "Output executable file")]
        output: PathBuf,
        
        #[arg(long, help = "Function RVA to protect (hex format, e.g., 0x1000)")]
        rva: Option<String>,
        #[arg(long, help = "Opcode shuffle seed (u64); random per pack if omitted")]
        seed: Option<String>,
        #[arg(
            long,
            help = "Enable L4d partial BB virtualization (default: full VM lift like L4b)"
        )]
        partial: bool,
        #[arg(
            long,
            value_name = "MODE",
            default_value = "table",
            help = "VM dispatch mode: table (handler table) or threaded (inline handler targets)"
        )]
        dispatch: String,
        #[arg(
            long,
            value_name = "LEVEL",
            num_args = 0..=1,
            default_missing_value = "1",
            help = "MBA substitution level: 0/off (default), 1=single catalog rewrite, 2=nested depth-limited"
        )]
        mba: Option<String>,
        #[arg(
            long,
            value_name = "MODE",
            default_value = "reg",
            help = "VM ISA mode: reg (default, 3-operand registers) or stack (push/pop ALU)"
        )]
        isa: String,
        #[arg(
            long,
            help = "Enable L5f nested VM (outer decode + inner execute; table dispatch only)"
        )]
        nested: bool,
    },
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

pub fn parse_isa_mode(isa: &str) -> anyhow::Result<crate::vm::IsaMode> {
    crate::vm::IsaMode::from_str(isa).map_err(|e| anyhow::anyhow!(e))
}

pub fn parse_mba_level(mba: &Option<String>) -> anyhow::Result<u8> {
    match mba {
        None => Ok(0),
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "0" | "off" | "false" => Ok(0),
            "1" | "on" | "true" => Ok(1),
            "2" => Ok(2),
            other => anyhow::bail!(
                "invalid --mba level {other:?}; expected 0/off, 1/on, or 2"
            ),
        },
    }
}
