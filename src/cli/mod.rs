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
            help = "Enable L4f MBA algebraic substitution for integer add (default: off)"
        )]
        mba: bool,
    },
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
