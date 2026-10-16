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
        #[arg(
            long,
            value_name = "PATH",
            help = "Optional .knvmap sidecar file (auto-detected as <input>.knvmap when embedded metadata is stripped)"
        )]
        sidecar: Option<PathBuf>,
    },
    
    #[command(about = "Pack an executable with VM protection")]
    Pack {
        #[arg(help = "Input executable file")]
        input: PathBuf,
        
        #[arg(short, long, help = "Output executable file")]
        output: PathBuf,
        
        #[arg(
            long,
            action = clap::ArgAction::Append,
            help = "Function RVA to protect (hex). Repeat the flag or separate values with commas"
        )]
        rva: Vec<String>,
        #[arg(
            long,
            value_name = "HEX",
            help = "Comma-separated function RVAs (same as repeated --rva)"
        )]
        rvas: Option<String>,
        #[arg(
            long,
            help = "L8: XOR each bytecode wire with a position/seed rolling key inside the VM fetch loop"
        )]
        rolling_cipher: bool,
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
        #[arg(
            long,
            help = "L7: Strip/scrub embedded KNV4..KNV7 & VMBC headers from .knvest and emit a .knvmap sidecar"
        )]
        strip_meta: bool,
        #[arg(
            long,
            value_name = "PATH",
            help = "L7: Custom output path for the .knvmap sidecar file (defaults to <output>.knvmap when --strip-meta is set)"
        )]
        sidecar: Option<PathBuf>,
        #[arg(
            long,
            help = "Strict lifting mode: fail if any non-prologue/epilogue instruction cannot be virtualized without BailNative"
        )]
        strict: bool,
        #[arg(
            long,
            help = "Function-level VM exit mode: return to caller with epilogue/ret instead of calling ExitProcess"
        )]
        return_mode: bool,
    },
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_rva_list;

    #[test]
    fn parse_rva_list_accepts_repeat_and_commas() {
        let got = parse_rva_list(&["0x1000".into(), "1100,0x1200".into()], Some("0x1300;1400")).unwrap();
        assert_eq!(got, vec![0x1000, 0x1100, 0x1200, 0x1300, 0x1400]);
    }
}

pub fn parse_isa_mode(isa: &str) -> anyhow::Result<crate::vm::IsaMode> {
    crate::vm::IsaMode::from_str(isa).map_err(|e| anyhow::anyhow!(e))
}

/// Parse repeated `--rva` values and an optional `--rvas` list. Hex, optional `0x`, commas or semicolons.
pub fn parse_rva_list(rvas: &[String], extra: Option<&str>) -> anyhow::Result<Vec<u32>> {
    let mut out = Vec::new();
    let mut push_field = |field: &str| -> anyhow::Result<()> {
        for part in field.split(|c| c == ',' || c == ';') {
            let token = part.trim();
            if token.is_empty() {
                continue;
            }
            let hex = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
                .unwrap_or(token);
            out.push(u32::from_str_radix(hex, 16).map_err(|err| {
                anyhow::anyhow!("invalid RVA {token:?}: {err}")
            })?);
        }
        Ok(())
    };
    for field in rvas {
        push_field(field)?;
    }
    if let Some(field) = extra {
        push_field(field)?;
    }
    Ok(out)
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
