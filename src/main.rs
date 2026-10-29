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
        Commands::Ir { input, sidecar } => {
            handle_ir_command(input, sidecar)?;
        }
        Commands::Pack {
            input,
            output,
            rva,
            seed,
            partial,
            dispatch,
            mba,
            isa,
            nested,
            strip_meta,
            sidecar,
            strict,
            return_mode,
            rvas,
            rolling_cipher,
            reg_encrypt,
            superops,
            imm_cipher,
        } => {
            let rva_values = cli::parse_rva_list(&rva, rvas.as_deref())?;
            let seed_value = if let Some(seed_str) = seed {
                Some(parse_seed(&seed_str)?)
            } else {
                None
            };
            let dispatch_mode = dispatch
                .parse::<crate::vm::DispatchMode>()
                .map_err(|e| anyhow::anyhow!(e))?;
            let mba_level = cli::parse_mba_level(&mba)?;
            let isa_mode = cli::parse_isa_mode(&isa)?;
            handle_pack_command(
                input,
                output,
                &rva_values,
                seed_value,
                partial,
                dispatch_mode,
                mba_level,
                isa_mode,
                nested,
                strip_meta,
                sidecar,
                strict,
                return_mode,
                rolling_cipher,
                reg_encrypt,
                superops,
                imm_cipher,
            )?;
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

fn handle_ir_command(
    input: std::path::PathBuf,
    sidecar_opt: Option<std::path::PathBuf>,
) -> Result<()> {
    let pe = PEFile::from_file(&input)?;

    let auto_sidecar = {
        let mut p = input.as_os_str().to_os_string();
        p.push(".knvmap");
        std::path::PathBuf::from(p)
    };
    let loaded_sidecar = if let Some(ref sc_path) = sidecar_opt {
        Some(packer::SidecarMap::load_from_path(sc_path)?)
    } else if packer::extract_pack_metadata_from_packed(&pe).is_err() && auto_sidecar.exists() {
        Some(packer::SidecarMap::load_from_path(&auto_sidecar)?)
    } else {
        None
    };

    let pack_meta = if let Some(ref sc) = loaded_sidecar {
        sc.pack_meta.clone()
    } else {
        packer::extract_pack_metadata_from_packed(&pe)?
    };
    let mba_level = pack_meta.mba_level;
    let pack_seed = pack_meta.seed();
    let opcode_map = pack_meta.opcode_map;
    let dispatch_mode = pack_meta.dispatch_mode;
    let partial_plan = if let Some(ref sc) = loaded_sidecar {
        Some(sc.partial_plan.clone())
    } else {
        packer::extract_partial_plan_from_packed(&pe).ok()
    };
    let bytecode =
        packer::extract_bytecode_from_packed_with_sidecar(&pe, loaded_sidecar.as_ref())?;
    
    println!(
        "L4c dispatch={} | L4a seed={:#x}",
        dispatch_mode,
        opcode_map.seed()
    );
    
    if let Some(plan) = partial_plan {
        print!("{}", plan.format_ir_header(&opcode_map, dispatch_mode));
    }

    let block_plan = if let Some(ref sc) = loaded_sidecar {
        Some(sc.block_map_plan.clone())
    } else {
        packer::extract_block_map_from_packed(&pe).ok()
    };
    if let Some(ref plan) = block_plan {
        print!("{}", plan.format_ir_header(&opcode_map, dispatch_mode));
    }

    let layout_plan = if let Some(ref sc) = loaded_sidecar {
        sc.layout_plan.clone()
    } else {
        packer::extract_layout_from_packed(&pe)?
    };
    print!("{}", layout_plan.format_ir_header());

    if mba_level >= 1 {
        print!(
            "{}",
            crate::pe::mba::format_ir_header(
                crate::pe::mba::MbaLevel::from_u8(mba_level),
                pack_seed,
            )
        );
    }

    print!(
        "{}",
        crate::vm::virt_isa::format_ir_header(&opcode_map, dispatch_mode)
    );

    print!(
        "{}",
        crate::vm::isa_mode::format_ir_header(
            pack_meta.isa_mode,
            &opcode_map,
            dispatch_mode,
        )
    );

    if pack_meta.rolling_cipher {
        println!(
            "L8 rolling_cipher=on key32={:#x}",
            crate::vm::rolling_wire_key32(pack_seed)
        );
    }
    if pack_meta.reg_encrypt {
        println!("L9 reg_encrypt=on seed={pack_seed:#x}");
    }
    if pack_meta.imm_cipher {
        println!("L10 imm_cipher=on seed={pack_seed:#x}");
    }

    if pack_meta.nested_vm {
        let nested_plan = crate::vm::NestedVmPlan::from_seed(
            pack_seed,
            &crate::vm::collect_outer_maps(
                pack_seed,
                &opcode_map,
                block_plan.as_ref().unwrap_or(&crate::vm::BlockMapPlan::default()),
            ),
        );
        print!("{}", nested_plan.format_ir_header(&opcode_map));
    }
    
    let instructions = ir::Instruction::disassemble_with_ciphers(
        &bytecode,
        &opcode_map,
        block_plan.as_ref(),
        dispatch_mode,
        &layout_plan,
        pack_meta.isa_mode,
        pack_meta.rolling_cipher,
        pack_meta.imm_cipher,
        pack_seed,
    );
    let output = ir::Instruction::pretty_print_with_mba(&instructions, mba_level);
    
    println!("{}", output);

    if let Some(section) = knvest_bytes(&pe) {
        let extras = if let Some(sc) = &loaded_sidecar {
            sc.functions.clone()
        } else {
            packer::sidecar_functions_from_section(section)
        };
        for (index, func) in extras.iter().enumerate().skip(1) {
            println!(
                "--- function {index} vmbc={:#x} bytecode_len={} ---",
                func.vmbc_offset, func.bytecode_len
            );
            print!(
                "{}",
                func.block_map_plan
                    .format_ir_header(&func.pack_meta.opcode_map, func.pack_meta.dispatch_mode)
            );
            let Ok(bc) = func.bytecode_in(section) else {
                println!("(bytecode bounds exceed .knvest)");
                continue;
            };
            let fn_insns = ir::Instruction::disassemble_with_ciphers(
                bc,
                &func.pack_meta.opcode_map,
                Some(&func.block_map_plan),
                func.pack_meta.dispatch_mode,
                &func.layout_plan,
                func.pack_meta.isa_mode,
                func.pack_meta.rolling_cipher,
                func.pack_meta.imm_cipher,
                func.pack_meta.seed(),
            );
            println!(
                "{}",
                ir::Instruction::pretty_print_with_mba(&fn_insns, func.pack_meta.mba_level)
            );
        }
    }

    Ok(())
}

fn knvest_bytes(pe: &PEFile) -> Option<&[u8]> {
    let section = pe.get_section(".knvest").ok()?;
    let start = section.pointer_to_raw_data as usize;
    let end = start + section.size_of_raw_data as usize;
    pe.data.get(start..end.min(pe.data.len()))
}

fn handle_pack_command(
    input: std::path::PathBuf,
    output: std::path::PathBuf,
    rvas: &[u32],
    seed: Option<u64>,
    partial: bool,
    dispatch_mode: crate::vm::DispatchMode,
    mba_level: u8,
    isa_mode: crate::vm::IsaMode,
    nested_vm: bool,
    strip_meta: bool,
    sidecar: Option<std::path::PathBuf>,
    strict: bool,
    return_mode: bool,
    rolling_cipher: bool,
    reg_encrypt: bool,
    superops: bool,
    imm_cipher: bool,
) -> Result<()> {
    pack::pack_executable_l9(
        &input,
        &output,
        rvas,
        seed,
        partial,
        dispatch_mode,
        mba_level,
        isa_mode,
        nested_vm,
        strip_meta,
        sidecar.as_deref(),
        strict,
        return_mode,
        rolling_cipher,
        reg_encrypt,
        superops,
        imm_cipher,
    )?;
    println!("Successfully packed {} -> {}", input.display(), output.display());
    Ok(())
}
