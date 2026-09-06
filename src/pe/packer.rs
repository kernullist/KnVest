use super::parser::{PEFile, PEResult, PEError};
use super::lifter::{
    lift_to_vm_bytecode_for_main, native_stack_sync_pairs_from_map, prebuild_stack_map,
};
use super::vm_stub::create_vm_interpreter_stub;
use super::threaded::{self, embed_thread_targets, handler_offset_for_op};
use super::cfg::{collect_cfg_entries, disassemble_cfg_function, build_basic_blocks};
use super::partial::{NativeSledBuilder, PartialVirtPlan, KNV5_MAGIC};
use crate::vm::{BlockMapPlan, DispatchMode, OpcodeMap, PackMetadata, random_seed, set_active_map, clear_active_map, KNV6_MAGIC};
use crate::vm::opcode_map::KNV4_MAGIC;

const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;

pub struct PackResult {
    pub bytecode: Vec<u8>,
    pub opcode_map: OpcodeMap,
    pub dispatch_mode: DispatchMode,
    pub seed: u64,
    pub partial_plan: PartialVirtPlan,
    pub block_map_plan: BlockMapPlan,
    pub native_sleds: Vec<u8>,
    pub native_sync: Vec<(i32, u8)>,
}

pub fn pack_function(
    pe: &mut PEFile,
    function_rva: Option<u32>,
    seed: Option<u64>,
    partial_enabled: bool,
    dispatch_mode: DispatchMode,
) -> PEResult<PackResult> {
    let explicit_rva = function_rva.is_some();
    let target_rva = if let Some(rva) = function_rva {
        rva
    } else {
        detect_main_rva(pe)?
    };
    let original_entry_rva = pe.entry_point_rva;

    let pack_seed = seed.unwrap_or_else(random_seed);
    let opcode_map = OpcodeMap::from_seed(pack_seed);

    let mut translated = translate_to_vm_bytecode(
        pe,
        target_rva,
        original_entry_rva,
        explicit_rva,
        &opcode_map,
        pack_seed,
        partial_enabled,
    )?;

    let section_bytecode = build_section_bytecode(
        &translated.bytecode,
        &opcode_map,
        dispatch_mode,
        &translated.partial_plan,
        &mut translated.block_map_plan,
        &translated.native_sleds,
        &translated.native_sync,
    )?;

    add_vm_section(
        pe,
        section_bytecode.stub,
        &section_bytecode.bytecode,
    )?;

    Ok(PackResult {
        bytecode: section_bytecode.bytecode,
        opcode_map,
        dispatch_mode,
        seed: pack_seed,
        partial_plan: translated.partial_plan,
        block_map_plan: translated.block_map_plan,
        native_sleds: translated.native_sleds,
        native_sync: translated.native_sync,
    })
}

struct SectionBytecode {
    stub: Vec<u8>,
    bytecode: Vec<u8>,
}

fn build_section_bytecode(
    bytecode: &[u8],
    opcode_map: &OpcodeMap,
    dispatch_mode: DispatchMode,
    partial_plan: &PartialVirtPlan,
    block_map_plan: &mut BlockMapPlan,
    native_sleds: &[u8],
    native_sync: &[(i32, u8)],
) -> PEResult<SectionBytecode> {
    let knv5 = partial_plan.to_embedded_bytes();
    let (mut vm_stub, _) = create_vm_interpreter_stub(
        0,
        0,
        opcode_map,
        dispatch_mode,
        &knv5,
        block_map_plan,
        native_sleds,
        native_sync,
    );
    let handler_off = |op: crate::vm::OpCode| {
        threaded::handler_offset_for_op(&vm_stub, opcode_map, op)
    };
    let set_map_off = threaded::handler_offset_for_set_block_map(&vm_stub);
    block_map_plan.fill_handler_tables(handler_off, set_map_off);
    // Patch KNV6 blob after handler offsets are known.
    patch_knv6_in_stub(&mut vm_stub, block_map_plan);
    let section_bytecode = if dispatch_mode == DispatchMode::Threaded {
        embed_thread_targets(
            bytecode,
            opcode_map,
            block_map_plan,
            &|op| threaded::handler_offset_for_op(&vm_stub, opcode_map, op),
            set_map_off,
        )
    } else {
        bytecode.to_vec()
    };
    Ok(SectionBytecode {
        stub: vm_stub,
        bytecode: section_bytecode,
    })
}

fn has_stack_prologue(text_data: &[u8], offset: usize) -> bool {
    if offset + 7 >= text_data.len() {
        return false;
    }
    // sub rsp, imm8  (48 83 EC xx)
    if text_data[offset + 4] == 0x48
        && text_data[offset + 5] == 0x83
        && text_data[offset + 6] == 0xEC
    {
        return true;
    }
    // sub rsp, imm32 (48 81 EC xx xx xx xx)
    offset + 10 < text_data.len()
        && text_data[offset + 4] == 0x48
        && text_data[offset + 5] == 0x81
        && text_data[offset + 6] == 0xEC
}

fn has_near_call_in_window(text_data: &[u8], offset: usize, window: usize) -> bool {
    let start = offset + 4;
    let end = std::cmp::min(offset + window, text_data.len());
    if start + 5 > end {
        return false;
    }
    text_data[start..end].contains(&0xE8)
}

/// Max bytes scanned inside a candidate function body (avoids bleed into the next symbol).
const MAIN_BODY_SCAN_MAX: usize = 0x48;

/// Collect targets of `call rel32` (0xE8) within the first `scan_len` bytes.
fn near_rel32_call_targets(text_data: &[u8], offset: usize, scan_len: usize) -> Vec<usize> {
    let end = (offset + scan_len).min(text_data.len());
    if offset >= end {
        return Vec::new();
    }
    let w = &text_data[offset..end];
    let mut targets = Vec::new();
    for i in 0..w.len().saturating_sub(5) {
        if w[i] != 0xE8 {
            continue;
        }
        let rel = i32::from_le_bytes([w[i + 1], w[i + 2], w[i + 3], w[i + 4]]);
        let call_from = offset + i;
        let target = call_from as i64 + 5 + rel as i64;
        if target >= 0 {
            targets.push(target as usize);
        }
    }
    targets
}

fn candidate_body_len(text_data: &[u8], offset: usize, sorted_offsets: &[usize]) -> usize {
    let next_off = sorted_offsets.iter().find(|next| **next > offset).copied();
    let gap_cap = next_off
        .map(|n| n - offset)
        .unwrap_or(MAIN_BODY_SCAN_MAX);
    let cap = gap_cap.min(MAIN_BODY_SCAN_MAX).min(text_data.len() - offset);
    for i in 12..cap {
        if text_data[offset + i] == 0xC3 {
            return i + 1;
        }
    }
    cap
}

/// MinGW `__do_global_ctors` walker — must never be auto-selected as user `main`.
fn is_global_ctors_walker(body: &[u8]) -> bool {
    let has_ptr_walk = body.windows(4).any(|x| {
        x == [0x48, 0x83, 0xC3, 0x08] || x == [0x48, 0x83, 0xC6, 0x08]
    });
    let has_indirect_call = body.windows(2).any(|x| {
        x == [0xFF, 0x13] || x == [0xFF, 0x10] || x == [0xFF, 0xD0]
    });
    let has_ctor_list_load = body.windows(3).any(|x| {
        x == [0x48, 0x8B, 0x1D] || x == [0x48, 0x8B, 0x35]
    });
    (has_ptr_walk && has_indirect_call)
        || (has_ctor_list_load && has_indirect_call && has_ptr_walk)
}

/// Stdio I/O inside a bounded function body (printf/puts), not bleed from neighbors.
fn has_stdio_in_body(body: &[u8]) -> bool {
    for i in 0..body.len().saturating_sub(14) {
        if body[i] != 0x48 || body.get(i + 1) != Some(&0x8D) {
            continue;
        }
        let modrm = body.get(i + 2).copied().unwrap_or(0);
        if !matches!(modrm, 0x05 | 0x0D | 0x15 | 0x1D | 0x35 | 0x3D) {
            continue;
        }
        let tail = &body[i..body.len().min(i + 18)];
        if tail.contains(&0xE8) || tail.windows(2).any(|x| x == [0xFF, 0x15]) {
            return true;
        }
    }
    for i in 0..body.len().saturating_sub(6) {
        if body[i] == 0xB9 && body.get(i + 5) == Some(&0xE8) {
            return true;
        }
    }
    false
}

fn has_return_zero_epilogue(body: &[u8]) -> bool {
    body.windows(2).any(|x| x == [0x31, 0xC0])
        || body.windows(5).any(|x| x == [0xB8, 0, 0, 0, 0])
}

fn has_stack_local_init(body: &[u8]) -> bool {
    body.windows(2).any(|x| x[0] == 0xC7 && x[1] == 0x45)
}

/// CRT `__main` shim: short body, no stdio; may call in-text CRT helpers or be
/// called from user `main` (MinGW: user main calls __main, not the reverse).
fn is_crt___main_shim(body: &[u8], in_text_targets: usize, caller_count: usize) -> bool {
    if is_global_ctors_walker(body) || has_stdio_in_body(body) {
        return false;
    }
    body.len() <= 0x34 && (in_text_targets >= 1 || caller_count >= 1)
}

fn candidates_calling_target(
    text_data: &[u8],
    candidates: &[(u32, usize)],
    target_off: usize,
    body_len_at: &impl Fn(usize) -> usize,
) -> Vec<(u32, usize)> {
    candidates
        .iter()
        .copied()
        .filter(|&(_, off)| {
            let len = body_len_at(off);
            near_rel32_call_targets(text_data, off, len).contains(&target_off)
        })
        .collect()
}

fn count_candidate_callers(
    text_data: &[u8],
    candidates: &[(u32, usize)],
    target_off: usize,
    body_len_at: &impl Fn(usize) -> usize,
) -> usize {
    candidates_calling_target(text_data, candidates, target_off, body_len_at).len()
}

/// Helper like `factorial`: callee of a stdio-bearing function, no stdio itself.
fn is_in_text_helper(
    text_data: &[u8],
    offset: usize,
    body_len: usize,
    candidates: &[(u32, usize)],
    sorted_offsets: &[usize],
    body_len_at: &impl Fn(usize) -> usize,
) -> bool {
    let body = &text_data[offset..offset + body_len];
    if has_stdio_in_body(body) || is_global_ctors_walker(body) {
        return false;
    }
    sorted_offsets.iter().any(|caller_off| {
        if *caller_off == offset {
            return false;
        }
        let caller_len = body_len_at(*caller_off);
        let caller_body = &text_data[*caller_off..*caller_off + caller_len];
        if is_global_ctors_walker(caller_body) || is_crt___main_shim(
            caller_body,
            near_rel32_call_targets(text_data, *caller_off, caller_len)
                .iter()
                .filter(|t| sorted_offsets.contains(t))
                .count(),
            count_candidate_callers(text_data, candidates, *caller_off, body_len_at),
        ) {
            return false;
        }
        has_stdio_in_body(caller_body)
            && near_rel32_call_targets(text_data, *caller_off, caller_len).contains(&offset)
    })
}

fn fallback_user_main_score(body: &[u8]) -> i32 {
    let mut score = 0i32;
    if has_stack_local_init(body) {
        score += 10;
    }
    if has_stdio_in_body(body) {
        score += 20;
    }
    if has_return_zero_epilogue(body) {
        score += 6;
    }
    score
}

fn detect_main_rva(pe: &PEFile) -> PEResult<u32> {
    let text_section = pe
        .get_section(".text")
        .or_else(|_| pe.get_section("CODE"))?;

    let text_start_rva = text_section.virtual_address;

    let text_offset = pe.rva_to_file_offset(text_start_rva)?;
    let text_data = &pe.data
        [text_offset..std::cmp::min(text_offset + text_section.size_of_raw_data as usize, pe.data.len())];

    let mut candidates = Vec::new();

    for offset in 0..text_data.len().saturating_sub(50) {
        if text_data[offset] == 0x55
            && text_data[offset + 1] == 0x48
            && text_data[offset + 2] == 0x89
            && text_data[offset + 3] == 0xE5
            && has_stack_prologue(text_data, offset)
            && has_near_call_in_window(text_data, offset, 0x100)
            && (0x350..=0x900).contains(&offset)
        {
            candidates.push((text_start_rva + offset as u32, offset));
        }
    }

    let mut sorted_offsets: Vec<usize> = candidates.iter().map(|(_, off)| *off).collect();
    sorted_offsets.sort_unstable();

    let body_len_at = |off: usize| candidate_body_len(text_data, off, &sorted_offsets);

    let is_eligible_user_main = |off: usize| -> bool {
        let len = body_len_at(off);
        let body = &text_data[off..off + len];
        !is_global_ctors_walker(body)
            && !is_crt___main_shim(
                body,
                near_rel32_call_targets(text_data, off, len)
                    .iter()
                    .filter(|t| sorted_offsets.contains(t))
                    .count(),
                count_candidate_callers(text_data, &candidates, off, &body_len_at),
            )
            && !is_in_text_helper(
                text_data,
                off,
                len,
                &candidates,
                &sorted_offsets,
                &body_len_at,
            )
    };

    // Primary (MinGW): user `main` calls CRT `__main`; find callers of the shim.
    for &(shim_rva, shim_off) in &candidates {
        let shim_len = body_len_at(shim_off);
        let shim_body = &text_data[shim_off..shim_off + shim_len];
        let in_text = near_rel32_call_targets(text_data, shim_off, shim_len)
            .iter()
            .filter(|t| sorted_offsets.contains(t))
            .count();
        let callers = count_candidate_callers(text_data, &candidates, shim_off, &body_len_at);
        if !is_crt___main_shim(shim_body, in_text, callers) {
            continue;
        }
        let main_callers: Vec<(u32, usize)> = candidates_calling_target(
            text_data,
            &candidates,
            shim_off,
            &body_len_at,
        )
        .into_iter()
        .filter(|&(_, off)| is_eligible_user_main(off))
        .collect();
        if let Some(&(main_rva, main_off)) = main_callers.iter().max_by(|a, b| {
            let a_body = &text_data[a.1..a.1 + body_len_at(a.1)];
            let b_body = &text_data[b.1..b.1 + body_len_at(b.1)];
            fallback_user_main_score(a_body)
                .cmp(&fallback_user_main_score(b_body))
                .then_with(|| {
                    let a_stdio = has_stdio_in_body(a_body) as i32;
                    let b_stdio = has_stdio_in_body(b_body) as i32;
                    a_stdio.cmp(&b_stdio)
                })
                .then_with(|| b.1.cmp(&a.1))
        }) {
            eprintln!(
                "Auto-detected main at RVA {:#x} (.text+{:#x}) as caller of CRT __main at {:#x}",
                main_rva,
                main_off,
                shim_rva
            );
            return Ok(main_rva);
        }
    }

    let eligible: Vec<(u32, usize)> = candidates
        .iter()
        .copied()
        .filter(|(_, off)| is_eligible_user_main(*off))
        .collect();

    let pick_from = if eligible.is_empty() {
        candidates
            .iter()
            .copied()
            .filter(|(_, off)| {
                let body = &text_data[*off..*off + body_len_at(*off)];
                !is_global_ctors_walker(body)
            })
            .collect::<Vec<_>>()
    } else {
        eligible
    };

    if let Some(&(rva, offset)) = pick_from.iter().max_by(|a, b| {
        let a_body = &text_data[a.1..a.1 + body_len_at(a.1)];
        let b_body = &text_data[b.1..b.1 + body_len_at(b.1)];
        fallback_user_main_score(a_body)
            .cmp(&fallback_user_main_score(b_body))
            .then_with(|| {
                let a_stdio = has_stdio_in_body(a_body) as i32;
                let b_stdio = has_stdio_in_body(b_body) as i32;
                a_stdio.cmp(&b_stdio)
            })
            .then_with(|| b.1.cmp(&a.1))
    }) {
        eprintln!("Auto-detected main at RVA {:#x} (.text+{:#x})", rva, offset);
        return Ok(rva);
    }

    eprintln!(
        "Could not auto-detect main, using entry point {:#x}",
        pe.entry_point_rva
    );
    Ok(pe.entry_point_rva)
}

struct TranslateResult {
    bytecode: Vec<u8>,
    partial_plan: PartialVirtPlan,
    block_map_plan: BlockMapPlan,
    native_sleds: Vec<u8>,
    native_sync: Vec<(i32, u8)>,
}

fn translate_to_vm_bytecode(
    pe: &PEFile,
    target_rva: u32,
    _original_entry: u32,
    explicit_rva: bool,
    opcode_map: &OpcodeMap,
    pack_seed: u64,
    partial_enabled: bool,
) -> PEResult<TranslateResult> {
    let file_offset = pe.rva_to_file_offset(target_rva)?;

    if file_offset + 16 > pe.data.len() {
        return Err(PEError::InvalidPE("Code section too small".to_string()));
    }

    let text_section = pe
        .get_section(".text")
        .or_else(|_| pe.get_section("CODE"))?;
    let text_start = pe.rva_to_file_offset(text_section.virtual_address)?;
    let text_end = text_start + text_section.size_of_raw_data as usize;

    let imports = pe.parse_imports()?;
    let cfg_entries = collect_cfg_entries(
        pe,
        file_offset,
        file_offset,
        text_start,
        text_end,
        &imports,
        explicit_rva,
    )?;

    if cfg_entries.is_empty() {
        return Err(PEError::InvalidPE("CFG found no functions to lift".to_string()));
    }

    let mut all_instrs = Vec::new();
    for &entry in &cfg_entries {
        let max_end = (entry + super::cfg::MAX_FUNCTION_BYTES).min(text_end);
        let code = &pe.data[entry..max_end];
        let mut instrs = disassemble_cfg_function(code, entry);
        all_instrs.append(&mut instrs);
    }

    all_instrs.sort_by_key(|i| i.offset);

    if all_instrs.is_empty() {
        return Err(PEError::InvalidPE("Failed to disassemble CFG functions".to_string()));
    }

    let string_literal = find_string_literal_in_pe(pe);

    let main_blocks = build_basic_blocks(&all_instrs, file_offset);
    let partial_plan = PartialVirtPlan::from_seed(
        pack_seed,
        &main_blocks,
        file_offset,
        pe,
        partial_enabled,
        &all_instrs,
    )?;
    let mut block_map_plan = BlockMapPlan {
        decode_key: BlockMapPlan::global_decode_key(pack_seed),
        entries: Vec::new(),
    };
    for bb in &main_blocks {
        block_map_plan.record_block(pack_seed, bb.id);
    }
    let mut sled_builder = NativeSledBuilder::new();

    set_active_map(opcode_map);
    let (bytecode, stack_map) = lift_to_vm_bytecode_for_main(
        &all_instrs,
        target_rva,
        file_offset,
        pe,
        string_literal.as_deref(),
        &imports,
        opcode_map,
        Some(&partial_plan),
        &block_map_plan,
        &mut sled_builder,
    );
    clear_active_map();

    let native_sleds = sled_builder.blob();
    let native_sync = native_stack_sync_pairs_from_map(&stack_map, &all_instrs, file_offset);
    Ok(TranslateResult {
        bytecode,
        partial_plan,
        block_map_plan,
        native_sleds,
        native_sync,
    })
}

fn find_string_literal_in_pe(pe: &PEFile) -> Option<Vec<u8>> {
    const NEEDLES: &[&[u8]] = &[
        b"IAT puts hello\0",
        b"IAT puts hello\n",
        b"Hello, World!\n",
        b"Hello, World!",
    ];
    for name in [".rdata", ".rdata$zzz", ".rodata", ".data"] {
        if let Ok(sec) = pe.get_section(name) {
            let start = sec.pointer_to_raw_data as usize;
            let end = (start + sec.size_of_raw_data as usize).min(pe.data.len());
            if start >= end {
                continue;
            }
            let data = &pe.data[start..end];
            for needle in NEEDLES {
                if data.windows(needle.len()).any(|w| w == *needle) {
                    return Some(needle.to_vec());
                }
            }
        }
    }
    None
}

fn add_vm_section(
    pe: &mut PEFile,
    vm_stub: Vec<u8>,
    bytecode: &[u8],
) -> PEResult<()> {
    let _original_entry_rva = pe.entry_point_rva;
    
    let last_section = get_last_section(pe)?;
    
    let new_virtual_address = align_up(
        last_section.virtual_address + last_section.virtual_size,
        SECTION_ALIGNMENT
    );
    
    let theoretical_raw_ptr = align_up(
        last_section.pointer_to_raw_data + last_section.size_of_raw_data,
        FILE_ALIGNMENT
    );
    
    let actual_file_size = pe.data.len();
    let new_pointer_to_raw = if theoretical_raw_ptr < actual_file_size as u32 {
        align_up(actual_file_size as u32, FILE_ALIGNMENT)
    } else {
        theoretical_raw_ptr
    };
    
    let image_base = 0x140000000u64;
    let _ = image_base;
    
    let mut section_data = Vec::new();
    section_data.extend_from_slice(&vm_stub);
    section_data.extend_from_slice(bytecode);
    
    let virtual_size = section_data.len() as u32;
    let size_of_raw_data = align_up(section_data.len() as u32, FILE_ALIGNMENT);
    
    while section_data.len() < size_of_raw_data as usize {
        section_data.push(0x00);
    }
    
    let section_header = create_section_header(
        b".knvest\0",
        virtual_size,
        new_virtual_address,
        size_of_raw_data,
        new_pointer_to_raw,
        0xE0000020,
    );
    
    let section_table_offset = pe.sections_offset + (pe.num_sections as usize * 40);
    
    if section_table_offset + 40 > pe.data.len() {
        return Err(PEError::InvalidPE("No space for new section header".to_string()));
    }
    
    pe.data[section_table_offset..section_table_offset + 40]
        .copy_from_slice(&section_header);
    
    let coff_offset = pe.pe_header_offset + 4;
    let new_section_count = pe.num_sections + 1;
    pe.data[coff_offset + 2] = (new_section_count & 0xFF) as u8;
    pe.data[coff_offset + 3] = ((new_section_count >> 8) & 0xFF) as u8;
    
    pe.num_sections = new_section_count;
    
    let old_entry_offset = pe.optional_header_offset + 16;
    pe.data[old_entry_offset..old_entry_offset + 4]
        .copy_from_slice(&new_virtual_address.to_le_bytes());
    pe.entry_point_rva = new_virtual_address;
    
    let image_size_offset = pe.optional_header_offset + 56;
    let new_image_size = align_up(new_virtual_address + virtual_size, SECTION_ALIGNMENT);
    pe.data[image_size_offset..image_size_offset + 4]
        .copy_from_slice(&new_image_size.to_le_bytes());
    
    while pe.data.len() < new_pointer_to_raw as usize {
        pe.data.push(0x00);
    }
    
    pe.data.extend_from_slice(&section_data);
    
    Ok(())
}

fn get_last_section(pe: &PEFile) -> PEResult<LastSectionInfo> {
    let mut last_va = 0u32;
    let mut last_vs = 0u32;
    let mut last_ptr = 0u32;
    let mut last_size = 0u32;
    
    for i in 0..pe.num_sections {
        let section_offset = pe.sections_offset + (i as usize * 40);
        if section_offset + 40 > pe.data.len() {
            continue;
        }
        
        let virtual_size = u32::from_le_bytes([
            pe.data[section_offset + 8],
            pe.data[section_offset + 9],
            pe.data[section_offset + 10],
            pe.data[section_offset + 11],
        ]);
        
        let virtual_address = u32::from_le_bytes([
            pe.data[section_offset + 12],
            pe.data[section_offset + 13],
            pe.data[section_offset + 14],
            pe.data[section_offset + 15],
        ]);
        
        let size_of_raw_data = u32::from_le_bytes([
            pe.data[section_offset + 16],
            pe.data[section_offset + 17],
            pe.data[section_offset + 18],
            pe.data[section_offset + 19],
        ]);
        
        let pointer_to_raw_data = u32::from_le_bytes([
            pe.data[section_offset + 20],
            pe.data[section_offset + 21],
            pe.data[section_offset + 22],
            pe.data[section_offset + 23],
        ]);
        
        if virtual_address >= last_va {
            last_va = virtual_address;
            last_vs = virtual_size;
            last_ptr = pointer_to_raw_data;
            last_size = size_of_raw_data;
        }
    }
    
    Ok(LastSectionInfo {
        virtual_address: last_va,
        virtual_size: last_vs,
        pointer_to_raw_data: last_ptr,
        size_of_raw_data: last_size,
    })
}

struct LastSectionInfo {
    virtual_address: u32,
    virtual_size: u32,
    pointer_to_raw_data: u32,
    size_of_raw_data: u32,
}

fn align_up(value: u32, alignment: u32) -> u32 {
    ((value + alignment - 1) / alignment) * alignment
}

fn create_section_header(
    name: &[u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
) -> Vec<u8> {
    let mut header = vec![0u8; 40];
    header[0..8].copy_from_slice(name);
    header[8..12].copy_from_slice(&virtual_size.to_le_bytes());
    header[12..16].copy_from_slice(&virtual_address.to_le_bytes());
    header[16..20].copy_from_slice(&size_of_raw_data.to_le_bytes());
    header[20..24].copy_from_slice(&pointer_to_raw_data.to_le_bytes());
    header[36..40].copy_from_slice(&characteristics.to_le_bytes());
    header
}

pub fn extract_pack_metadata_from_packed(pe: &PEFile) -> PEResult<PackMetadata> {
    let section = pe.get_section(".knvest")?;
    let section_start = section.pointer_to_raw_data as usize;
    let section_end = section_start + section.size_of_raw_data as usize;
    if section_end > pe.data.len() {
        return Err(PEError::InvalidPE("Section data out of bounds".to_string()));
    }
    let section_data = &pe.data[section_start..section_end];
    for i in 0..section_data.len().saturating_sub(KNV4_MAGIC.len()) {
        if &section_data[i..i + KNV4_MAGIC.len()] == KNV4_MAGIC {
            if let Some(meta) = PackMetadata::from_embedded(&section_data[i..]) {
                return Ok(meta);
            }
        }
    }
    Err(PEError::InvalidPE(
        "Packed image missing KNV4 opcode map (L4a); raw bytecode cannot be decoded".to_string(),
    ))
}

pub fn extract_opcode_map_from_packed(pe: &PEFile) -> PEResult<OpcodeMap> {
    extract_pack_metadata_from_packed(pe).map(|m| m.opcode_map)
}

pub fn extract_dispatch_mode_from_packed(pe: &PEFile) -> PEResult<DispatchMode> {
    extract_pack_metadata_from_packed(pe).map(|m| m.dispatch_mode)
}

pub fn extract_partial_plan_from_packed(pe: &PEFile) -> PEResult<PartialVirtPlan> {
    let section = pe.get_section(".knvest")?;
    let section_start = section.pointer_to_raw_data as usize;
    let section_end = section_start + section.size_of_raw_data as usize;
    if section_end > pe.data.len() {
        return Err(PEError::InvalidPE("Section data out of bounds".to_string()));
    }
    let section_data = &pe.data[section_start..section_end];
    for i in 0..section_data.len().saturating_sub(KNV5_MAGIC.len()) {
        if &section_data[i..i + KNV5_MAGIC.len()] == KNV5_MAGIC {
            if let Some(plan) = PartialVirtPlan::from_embedded(&section_data[i..]) {
                return Ok(plan);
            }
        }
    }
    Err(PEError::InvalidPE(
        "Packed image missing KNV5 partial-virt metadata (L4d)".to_string(),
    ))
}

pub fn extract_block_map_from_packed(pe: &PEFile) -> PEResult<BlockMapPlan> {
    let section = pe.get_section(".knvest")?;
    let section_start = section.pointer_to_raw_data as usize;
    let section_end = section_start + section.size_of_raw_data as usize;
    if section_end > pe.data.len() {
        return Err(PEError::InvalidPE("Section data out of bounds".to_string()));
    }
    let section_data = &pe.data[section_start..section_end];
    for i in 0..section_data.len().saturating_sub(KNV6_MAGIC.len()) {
        if &section_data[i..i + KNV6_MAGIC.len()] == KNV6_MAGIC {
            if let Some(plan) = BlockMapPlan::from_embedded(&section_data[i..]) {
                return Ok(plan);
            }
        }
    }
    Err(PEError::InvalidPE(
        "Packed image missing KNV6 block-map metadata (L4e)".to_string(),
    ))
}

fn patch_knv6_in_stub(stub: &mut [u8], block_map_plan: &BlockMapPlan) {
    for i in 0..stub.len().saturating_sub(KNV6_MAGIC.len()) {
        if &stub[i..i + KNV6_MAGIC.len()] == KNV6_MAGIC {
            let bytes = block_map_plan.to_embedded_bytes();
            if i + bytes.len() <= stub.len() {
                stub[i..i + bytes.len()].copy_from_slice(&bytes);
            }
            return;
        }
    }
}

pub fn extract_bytecode_from_packed(pe: &PEFile) -> PEResult<Vec<u8>> {
    let knvest_section = pe.get_section(".knvest");
    
    if let Ok(section) = knvest_section {
        let section_start = section.pointer_to_raw_data as usize;
        let section_end = section_start + section.size_of_raw_data as usize;
        
        if section_end > pe.data.len() {
            return Err(PEError::InvalidPE("Section data out of bounds".to_string()));
        }
        
        let section_data = &pe.data[section_start..section_end];
        
        for i in 0..section_data.len().saturating_sub(4) {
            if &section_data[i..i+4] == b"VMBC" {
                let bytecode_start = i + 4;
                let mut bytecode_end = bytecode_start;
                
                while bytecode_end < section_data.len() {
                    let byte = section_data[bytecode_end];
                    if byte == 0xCC || byte == 0x00 {
                        let rest_is_padding = section_data[bytecode_end..].iter()
                            .all(|&b| b == 0xCC || b == 0x00);
                        if rest_is_padding {
                            break;
                        }
                    }
                    bytecode_end += 1;
                }
                
                if bytecode_end > bytecode_start {
                    return Ok(section_data[bytecode_start..bytecode_end].to_vec());
                }
            }
        }
    }
    
    Err(PEError::InvalidPE("No VM bytecode found in packed PE".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::imports::{
        iat_native_call_ids_in_bytecode_with_map, is_iat_native_call, is_iat_ptr_native_call,
        native_call_iat_ptr_id, native_call_ids_in_bytecode_with_map,
        native_call_ids_in_bytecode_with_map_dispatch,
    };
    use crate::pe::test_pe;
    use crate::vm::block_map::{block_wire_for_bb, bytecode_contains_semantic, BlockMapPlan, META_WIRE_BYTE};
    use crate::vm::{OpCode, OpcodeMap};

    const TEST_SEED: u64 = 0x4C344100;

    fn disasm_packed(packed: &PackResult) -> Vec<crate::ir::Instruction> {
        use crate::ir::Instruction;
        Instruction::disassemble_with_block_maps(
            &packed.bytecode,
            &packed.opcode_map,
            Some(&packed.block_map_plan),
            packed.dispatch_mode,
        )
    }

    fn ir_pretty(packed: &PackResult) -> String {
        use crate::ir::Instruction;
        Instruction::pretty_print(&disasm_packed(packed))
    }

    fn packed_contains_op(packed: &PackResult, op: OpCode) -> bool {
        disasm_packed(packed).iter().any(|i| i.opcode == op)
    }

    fn block_wire(seed: u64, bb_id: usize, op: OpCode) -> u8 {
        block_wire_for_bb(seed, bb_id, op)
    }

    fn pack_pe(pe: &mut PEFile, rva: Option<u32>) -> PackResult {
        pack_function(pe, rva, Some(TEST_SEED), false, crate::vm::DispatchMode::Table).unwrap()
    }

    fn pack_pe_seed(pe: &mut PEFile, rva: Option<u32>, seed: u64) -> PackResult {
        pack_function(pe, rva, Some(seed), false, crate::vm::DispatchMode::Table).unwrap()
    }

    fn pack_pe_partial(pe: &mut PEFile, rva: Option<u32>, seed: u64) -> PackResult {
        pack_function(pe, rva, Some(seed), true, crate::vm::DispatchMode::Table).unwrap()
    }

    /// MinGW gcc 16 educational samples: user `main` at `.text+offset` (see sample/README).
    fn assert_mingw_auto_main(pe: &PEFile, text_main_offset: u32) {
        let text = pe.get_section(".text").unwrap();
        let expected = text.virtual_address + text_main_offset;
        let detected = detect_main_rva(pe).unwrap();
        assert_eq!(
            detected,
            expected,
            "auto-detect must pick user main at .text+{:#x}, not {:#x}",
            text_main_offset,
            detected - text.virtual_address
        );
    }

    fn bytecode_has_char_output_native(bytecode: &[u8], map: &OpcodeMap) -> bool {
        !native_call_ids_in_bytecode_with_map(bytecode, map).is_empty()
    }

    #[test]
    fn test_pack_mingw_printf_stub_skips_clobber_chain() {
        let pe_data = test_pe::create_pe64_with_mingw_printf_stub();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x400;
        let packed = pack_pe(&mut pe, Some(main_rva));
        let ir = ir_pretty(&packed);
        assert!(
            !ir.contains("move r15, r8"),
            "packed printf stub must not emit r15<-r8:\n{ir}"
        );
        assert!(
            !ir.contains("move r2, r0"),
            "packed printf stub must not reload format into r2:\n{ir}"
        );
        assert!(
            ir.contains("r2, 0x23"),
            "packed main must keep int in r2:\n{ir}"
        );
        assert!(
            ir.contains("native_call  | 0x2"),
            "packed printf stub must emit nc2:\n{ir}"
        );
        assert!(
            packed.bytecode.len() < 260,
            "real-style collapse should shrink bytecode, got {} bytes",
            packed.bytecode.len()
        );
    }

    #[test]
    fn test_pack_real_mingw_arith_preserves_nc2_int() {
        use crate::ir::Instruction;
        use std::path::Path;

        let pe_path = Path::new("sample/arith.exe");
        if !pe_path.exists() {
            eprintln!("skip test_pack_real_mingw_arith: sample/arith.exe missing");
            return;
        }
        let mut pe = PEFile::from_bytes(std::fs::read(pe_path).unwrap()).unwrap();
        assert_mingw_auto_main(&pe, 0x760);
        let packed = pack_pe(&mut pe, None);
        let bc = packed.bytecode;
        let map = packed.opcode_map;
        assert!(
            bc.len() < 300,
            "packed real arith bytecode should stay compact, got {}",
            bc.len()
        );
        let ir = Instruction::pretty_print(&Instruction::disassemble(&bc, &map, crate::vm::DispatchMode::Table));
        let lines: Vec<&str> = ir.lines().collect();
        let nc2_idx = lines
            .iter()
            .position(|l| l.contains("native_call") && l.contains("0x2"))
            .expect("nc2 in packed real arith IR");
        let window = &lines[nc2_idx.saturating_sub(8)..nc2_idx];
        assert!(
            !window.iter().any(|l| l.contains("move r2, r0")),
            "printf wrapper must not reload format into r2 before nc2:\n{ir}"
        );
        assert!(
            !ir.contains("move r14, r1") && !ir.contains("move r15, r2"),
            "stack-based MinGW printf must not emit register-save shuffles:\n{ir}"
        );
        assert!(
            ir.contains("mul") && ir.contains("move         | r2,"),
            "main must pass computed int in r2:\n{ir}"
        );
    }

    #[test]
    fn test_pack_real_mingw_hello_uses_nc1() {
        use crate::ir::Instruction;
        use std::path::Path;

        let pe_path = Path::new("sample/hello.exe");
        if !pe_path.exists() {
            return;
        }
        let mut pe = PEFile::from_bytes(std::fs::read(pe_path).unwrap()).unwrap();
        let packed = pack_pe(&mut pe, None);
        let bc = packed.bytecode;
        let map = packed.opcode_map;
        let ir = Instruction::pretty_print(&Instruction::disassemble(&bc, &map, crate::vm::DispatchMode::Table));
        assert!(
            ir.contains("native_call  | 0x1"),
            "hello must use nc1 WriteFile string path:\n{ir}"
        );
        assert!(
            !ir.contains("native_call  | 0x2"),
            "hello must not use nc2 integer print:\n{ir}"
        );
        assert!(
            !ir.contains("move         | r1, r0"),
            "hello must not shuffle unset rcx from rax after skipped format lea:\n{ir}"
        );
        assert!(
            bc.len() < 200,
            "hello bytecode should stay compact, got {}",
            bc.len()
        );
    }

    #[test]
    fn test_pack_real_mingw_fact_auto_main() {
        use crate::ir::Instruction;
        use std::path::Path;

        let pe_path = Path::new("sample/fact.exe");
        if !pe_path.exists() {
            return;
        }
        let mut pe = PEFile::from_bytes(std::fs::read(pe_path).unwrap()).unwrap();
        assert_mingw_auto_main(&pe, 0x78f);
        let packed = pack_pe(&mut pe, None);
        let bc = packed.bytecode;
        let map = packed.opcode_map;
        assert!(
            (200..=500).contains(&bc.len()),
            "fact auto-main pack expected substantial CFG lift, got {} bytes",
            bc.len()
        );
        let ir = Instruction::pretty_print(&Instruction::disassemble(&bc, &map, crate::vm::DispatchMode::Table));
        assert!(
            ir.contains("call         | 0x"),
            "fact must recurse via vm call:\n{ir}"
        );
        assert!(
            ir.contains("native_call  | 0x2")
                || ir.contains("native_call  | 0x1")
                || ir.contains("native_call  | 0x10000"),
            "fact must print result via nc1/nc2 or IAT printf:\n{ir}"
        );
        assert!(
            !ir.contains("move r2, r0") || ir.matches("move         | r2, r0").count() <= 1,
            "only main may move computed int into r2, not printf wrapper:\n{ir}"
        );
    }

    #[test]
    fn test_pack_real_mingw_nested_putchar_in_r0() {
        use crate::ir::Instruction;
        use std::path::Path;

        let pe_path = Path::new("sample/nested.exe");
        if !pe_path.exists() {
            return;
        }
        let mut pe = PEFile::from_bytes(std::fs::read(pe_path).unwrap()).unwrap();
        let packed = pack_pe(&mut pe, None);
        let bc = packed.bytecode;
        let map = packed.opcode_map;
        let ir = Instruction::pretty_print(&Instruction::disassemble(&bc, &map, crate::vm::DispatchMode::Table));
        assert!(
            ir.contains("native_call  | 0x10000"),
            "nested must use IAT putchar:\n{ir}"
        );
        assert!(
            !ir.contains("native_call  | 0x180"),
            "putchar must not use ptr-flag IAT id:\n{ir}"
        );
        for (idx, line) in ir.lines().enumerate() {
            if line.contains("native_call  | 0x10000") {
                let window = ir
                    .lines()
                    .skip(idx.saturating_sub(4))
                    .take(4)
                    .collect::<Vec<_>>()
                    .join("\n");
                assert!(
                    window.contains("move         | r0, r1"),
                    "putchar IAT must receive char in r0:\n{window}\n{ir}"
                );
            }
        }
        // Main→callee calls must spill only main rbp locals (r10..r12), not callee +0x10 slot r13.
        let push_r13_before_print = ir.match_indices("push         | r13").count();
        assert_eq!(
            push_r13_before_print, 0,
            "main internal calls must not push callee spill r13:\n{ir}"
        );
        assert!(
            ir.contains("and          | r"),
            "nested must u32-zero-extend before 32-bit imul:\n{ir}"
        );
        // product<=9 always single-digit: cmp32 r12,9 then unconditional jmp (fused from JLE).
        assert!(
            ir.contains("cmp32        | r12, r15") || ir.contains("cmp32          | r12, r15"),
            "nested must cmp32 product against 9:\n{ir}"
        );
        let product_cmp = bc
            .windows(3)
            .position(|w| w == [map.encode(OpCode::Cmp32), 12, 15])
            .expect("nested bytecode must contain cmp32 r12,r15");
        assert_eq!(
            bc.get(product_cmp + 3),
            Some(&(map.encode(OpCode::Jmp))),
            "cmp32 r12,r15 must be followed by jmp to single-digit path"
        );
        let jle_after_product_nine = bc
            .windows(13)
            .position(|w| {
                w[0] == map.encode(OpCode::LoadImm)
                    && w[1] == 15
                    && u64::from_le_bytes(w[2..10].try_into().unwrap()) == 9
                    && w[10] == map.encode(OpCode::Cmp32)
                    && w[11] == 12
                    && w[12] == 15
            })
            .and_then(|p| {
                let after = p + 13;
                (after < bc.len() && bc[after] == map.encode(OpCode::JmpIf)).then_some(after)
            });
        assert!(
            jle_after_product_nine.is_none(),
            "product<=9 must not use jmp_if JLE into two-digit path"
        );
    }

    fn register_packed_putchar_natives(
        vm: &mut crate::vm::VirtualMachine,
        bytecode: &[u8],
        map: &OpcodeMap,
        putchar: fn(&mut crate::vm::VirtualMachine) -> crate::vm::VMResult<()>,
    ) {
        for id in iat_native_call_ids_in_bytecode_with_map(bytecode, map) {
            if !is_iat_ptr_native_call(id) {
                vm.register_native(id, putchar);
            }
        }
        vm.register_native(3, putchar);
    }

    fn register_packed_stdio_natives(
        vm: &mut crate::vm::VirtualMachine,
        bytecode: &[u8],
        map: &OpcodeMap,
        putchar: fn(&mut crate::vm::VirtualMachine) -> crate::vm::VMResult<()>,
        printf: fn(&mut crate::vm::VirtualMachine) -> crate::vm::VMResult<()>,
    ) {
        for id in native_call_ids_in_bytecode_with_map(bytecode, map) {
            if is_iat_ptr_native_call(id) {
                vm.register_native(id, printf);
            } else if is_iat_native_call(id) {
                vm.register_native(id, putchar);
            }
        }
        vm.register_native(2, printf);
        vm.register_native(3, putchar);
    }

    #[test]
    fn test_pack_real_mingw_nested_stdout_matches_unpacked() {
        use crate::vm::VirtualMachine;
        use std::cell::RefCell;
        use std::path::Path;

        thread_local! {
            static NESTED_OUT: RefCell<Vec<u8>> = RefCell::new(Vec::new());
        }

        let pe_path = Path::new("sample/nested.exe");
        if !pe_path.exists() {
            return;
        }

        const GOLDEN: &[u8] = b"1x1=1\r\n1x2=2\r\n1x3=3\r\n2x1=2\r\n2x2=4\r\n2x3=6\r\n3x1=3\r\n3x2=6\r\n3x3=9\r\n";

        let mut pe = PEFile::from_bytes(std::fs::read(pe_path).unwrap()).unwrap();
        assert_mingw_auto_main(&pe, 0x79c);
        let packed = pack_pe(&mut pe, None);
        let bc = packed.bytecode;
        let map = packed.opcode_map;

        NESTED_OUT.with(|buf| buf.borrow_mut().clear());

        fn putchar_native(vm: &mut VirtualMachine) -> crate::vm::VMResult<()> {
            let ch = vm.get_register(0)? as u8;
            NESTED_OUT.with(|buf| {
                let mut out = buf.borrow_mut();
                if ch == b'\n' {
                    out.extend_from_slice(b"\r\n");
                } else {
                    out.push(ch);
                }
            });
            Ok(())
        }

        assert!(
            bytecode_has_char_output_native(&bc, &map),
            "packed nested must emit at least one native_call for char output, got {:?}",
            native_call_ids_in_bytecode_with_map(&bc, &map)
        );
        let mut vm = VirtualMachine::with_opcode_map(bc.clone(), map.clone());
        register_packed_putchar_natives(&mut vm, &bc, &map, putchar_native);
        vm.run().expect("nested VM run");

        let out = NESTED_OUT.with(|buf| buf.borrow().clone());
        assert_eq!(
            out.len(),
            GOLDEN.len(),
            "nested stdout length must match unpacked (63 bytes CRLF)"
        );
        assert_eq!(
            out.as_slice(),
            GOLDEN,
            "packed nested stdout must match unpacked golden (got {:?})",
            String::from_utf8_lossy(&out)
        );
    }

    #[test]
    fn test_pack_real_mingw_loop_stdout_matches_unpacked() {
        use crate::vm::VirtualMachine;
        use std::cell::RefCell;
        use std::path::Path;

        thread_local! {
            static LOOP_OUT: RefCell<Vec<u8>> = RefCell::new(Vec::new());
        }

        let pe_path = Path::new("sample/loop.exe");
        if !pe_path.exists() {
            return;
        }

        const GOLDEN: &[u8] = b"5\n4\n3\n2\n1\n";

        let mut pe = PEFile::from_bytes(std::fs::read(pe_path).unwrap()).unwrap();
        let packed = pack_pe(&mut pe, None);
        let bc = packed.bytecode;
        let map = packed.opcode_map;

        LOOP_OUT.with(|buf| buf.borrow_mut().clear());

        fn putchar_native(vm: &mut VirtualMachine) -> crate::vm::VMResult<()> {
            let ch = vm.get_register(0)? as u8;
            LOOP_OUT.with(|buf| buf.borrow_mut().push(ch));
            Ok(())
        }

        fn printf_native(vm: &mut VirtualMachine) -> crate::vm::VMResult<()> {
            let n = vm.get_register(2)?;
            let s = format!("{n}\n");
            for &ch in s.as_bytes() {
                vm.set_register(0, ch as u64)?;
                putchar_native(vm)?;
            }
            Ok(())
        }

        let mut vm = VirtualMachine::with_opcode_map(bc.clone(), map.clone());
        register_packed_stdio_natives(&mut vm, &bc, &map, putchar_native, printf_native);
        vm.run().expect("loop VM run");

        let out = LOOP_OUT.with(|buf| buf.borrow().clone());
        assert_eq!(out.as_slice(), GOLDEN, "loop stdout mismatch: {:?}", String::from_utf8_lossy(&out));
    }

    #[test]
    fn test_pack_real_mingw_fact_stdout_matches_unpacked() {
        use crate::vm::VirtualMachine;
        use std::cell::RefCell;
        use std::path::Path;

        thread_local! {
            static FACT_OUT: RefCell<Vec<u8>> = RefCell::new(Vec::new());
        }

        let pe_path = Path::new("sample/fact.exe");
        if !pe_path.exists() {
            return;
        }

        const GOLDEN: &[u8] = b"120\n";

        let mut pe = PEFile::from_bytes(std::fs::read(pe_path).unwrap()).unwrap();
        let packed = pack_pe(&mut pe, None);
        let bc = packed.bytecode;
        let map = packed.opcode_map;

        FACT_OUT.with(|buf| buf.borrow_mut().clear());

        fn putchar_native(vm: &mut VirtualMachine) -> crate::vm::VMResult<()> {
            let ch = vm.get_register(0)? as u8;
            FACT_OUT.with(|buf| buf.borrow_mut().push(ch));
            Ok(())
        }

        fn printf_native(vm: &mut VirtualMachine) -> crate::vm::VMResult<()> {
            let n = vm.get_register(2)?;
            let s = format!("{n}\n");
            for &ch in s.as_bytes() {
                vm.set_register(0, ch as u64)?;
                putchar_native(vm)?;
            }
            Ok(())
        }

        let mut vm = VirtualMachine::with_opcode_map(bc.clone(), map.clone());
        register_packed_stdio_natives(&mut vm, &bc, &map, putchar_native, printf_native);
        vm.run().expect("fact VM run");

        let out = FACT_OUT.with(|buf| buf.borrow().clone());
        assert_eq!(out.as_slice(), GOLDEN, "fact stdout mismatch: {:?}", String::from_utf8_lossy(&out));
    }

    #[test]
    fn test_pack_with_explicit_rva() {
        let pe_data = test_pe::create_pe64_with_callee();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x20;
        pack_pe(&mut pe, Some(main_rva));
        let map = extract_opcode_map_from_packed(&pe).unwrap();
        let bc = extract_bytecode_from_packed(&pe).unwrap();
        assert!(!bc.is_empty());
        assert!(bytecode_contains_semantic(&bc, TEST_SEED, &BlockMapPlan::default(), OpCode::LoadImm)
            || bc.iter().any(|&b| b == META_WIRE_BYTE));
    }

    #[test]
    fn test_cfg_collects_multiple_functions() {
        let pe_data = test_pe::create_pe64_with_callee();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_start = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let text_end = text_start + text.size_of_raw_data as usize;
        let main_off = text_start + 0x20;
        let entries = collect_cfg_entries(
            &pe,
            main_off,
            main_off,
            text_start,
            text_end,
            &pe.parse_imports().unwrap(),
            false,
        )
        .unwrap();
        assert!(entries.len() >= 2);
    }

    #[test]
    fn test_pack_creates_valid_pe() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let original_entry = pe.entry_point_rva;
        
        let packed = pack_pe(&mut pe, None);
        assert!(!packed.bytecode.is_empty());
        assert!(packed_contains_op(&packed, OpCode::LoadImm));
    }

    #[test]
    fn test_packed_pe_has_knvest_section() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        
        pack_pe(&mut pe, None);
        
        let section = pe.get_section(".knvest");
        assert!(section.is_ok());
    }

    #[test]
    fn test_extract_bytecode_from_packed() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        
        pack_pe(&mut pe, None);
        let map = extract_opcode_map_from_packed(&pe).unwrap();
        
        let bytecode = extract_bytecode_from_packed(&pe);
        assert!(bytecode.is_ok());
        
        let bc = bytecode.unwrap();
        assert!(!bc.is_empty());
        assert!(bytecode_contains_semantic(&bc, TEST_SEED, &BlockMapPlan::default(), OpCode::LoadImm)
            || bc.iter().any(|&b| b == META_WIRE_BYTE));
    }

    #[test]
    fn test_bytecode_contains_vm_opcodes() {
        use crate::ir::Instruction;
        use crate::vm::DispatchMode;

        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        
        pack_pe(&mut pe, None);
        let map = extract_opcode_map_from_packed(&pe).unwrap();
        let block_plan = extract_block_map_from_packed(&pe).unwrap();
        let bytecode = extract_bytecode_from_packed(&pe).unwrap();
        let insns = Instruction::disassemble_with_block_maps(
            &bytecode,
            &map,
            Some(&block_plan),
            DispatchMode::Table,
        );

        assert!(insns.iter().any(|i| i.opcode == OpCode::LoadImm), "Bytecode should contain LoadImm");
        assert!(insns.iter().any(|i| i.opcode == OpCode::Exit), "Bytecode should contain Exit");
    }

    #[test]
    fn test_pack_pe_with_overlay() {
        let pe_data = test_pe::create_pe64_with_overlay();
        let original_size = pe_data.len();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        
        pack_pe(&mut pe, None);
        
        let section = pe.get_section(".knvest").unwrap();
        let ptr = section.pointer_to_raw_data as usize;
        
        assert!(ptr >= original_size, "New section should be after original file");
        
        assert!(ptr < pe.data.len(), "PointerToRawData should be within file");
        
        let stub_byte = pe.data[ptr];
        assert_eq!(stub_byte, 0x55, "Entry point should have VM stub (0x55 = push rbp)");
        
        let bytecode = extract_bytecode_from_packed(&pe);
        assert!(bytecode.is_ok(), "Should extract bytecode from packed PE with overlay");
    }
    
    #[test]
    fn test_stub_encoding_correctness() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        
        let mut i = 0;
        while i < stub.len() {
            if stub[i] == 0xE9 {
                assert!(i + 5 <= stub.len(), "E9 (jmp rel32) at offset {} must have 4 bytes following", i);
                i += 1;
                continue;
            }
            
            if i + 3 < stub.len() {
                let b0 = stub[i];
                let b1 = stub[i + 1];
                let b2 = stub[i + 2];
                let disp8 = stub[i + 3];
                
                if (b0 == 0x48 || b0 == 0x4C) && 
                   (b1 == 0x89 || b1 == 0x8B || b1 == 0x8D || b1 == 0xFF) &&
                   (b2 == 0x45 || b2 == 0x4D || b2 == 0x55 || b2 == 0x5D) {
                    let known_api_offsets = [0xC0, 0xB8, 0xB0, 0xA8, 0xA0, 0xD0];
                    if known_api_offsets.contains(&disp8) {
                        panic!(
                            "Invalid disp8 encoding at offset {}: {:02X} {:02X} {:02X} {:02X} (API offset 0x{:02X} requires disp32)",
                            i, b0, b1, b2, disp8, disp8
                        );
                    }
                }
            }
            
            i += 1;
        }
    }

    #[test]
    fn test_stub_does_not_clobber_writefile_slot() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        // mov [rbp-0xB0], rsi would clobber the WriteFile function pointer slot
        let clobber_pattern = [0x48u8, 0x89, 0xB5, 0x50, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(clobber_pattern.len()).any(|w| w == clobber_pattern),
            "stub must not store to [rbp-0xB0] (WriteFile pointer slot)"
        );
        // WriteFile pointer store uses mov [rbp-0xB0], rax
        let writefile_store = [0x48u8, 0x89, 0x85, 0x50, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(writefile_store.len()).any(|w| w == writefile_store),
            "stub must still store WriteFile pointer at [rbp-0xB0]"
        );
    }

    #[test]
    fn test_loadbyte_uses_rip_rel_bytecode_base() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let vmbc = stub.windows(4).position(|w| w == b"VMBC").expect("VMBC marker");
        let bytecode_offset = vmbc + 4;
        let cache_store = [0x48u8, 0x89, 0xB5, 0xE8, 0xFE, 0xFF, 0xFF];
        assert!(
            !stub.windows(cache_store.len()).any(|w| w == cache_store),
            "LoadByte must not use [rbp-0x118] cache"
        );
        let loadbyte_add = [0x48u8, 0x01, 0xD0];
        assert!(
            stub.windows(loadbyte_add.len()).any(|w| w == loadbyte_add),
            "LoadByte must add VM offset to rip-rel bytecode base"
        );
        let lea_pattern = [0x48u8, 0x8D, 0x15];
        let mut loadbyte_lea_found = false;
        for i in 0..stub.len().saturating_sub(7) {
            if stub[i..i + 3] != lea_pattern {
                continue;
            }
            let disp = i32::from_le_bytes([
                stub[i + 3],
                stub[i + 4],
                stub[i + 5],
                stub[i + 6],
            ]);
            let target = (i + 7) as i32 + disp;
            if target as usize == bytecode_offset {
                loadbyte_lea_found = true;
                break;
            }
        }
        assert!(loadbyte_lea_found, "LoadByte lea rdx must patch to opcode 0 (VMBC+4)");
    }

    #[test]
    fn test_prologue_uses_near_jb_ja_not_jl_jg() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let cmp_a = [0x83u8, 0xF8, 0x41];
        let mut found_jb = false;
        for i in 0..stub.len().saturating_sub(cmp_a.len() + 3) {
            if stub[i..i + 3] != cmp_a {
                continue;
            }
            assert_eq!(
                stub[i + 3],
                0x0F,
                "unsigned char range check must use near jcc"
            );
            assert_eq!(
                stub[i + 4],
                0x82,
                "cmp eax,'A' must be followed by near jb (0F 82), not jl"
            );
            found_jb = true;
            break;
        }
        assert!(found_jb, "kernel32 lowercase prologue must exist");
    }

    #[test]
    fn test_handler_table_resolves_handlers() {
        let map = OpcodeMap::from_seed(0);
        let (stub, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let dispatch_lea = [0x48u8, 0x8D, 0x1D];
        let mut table_base = None;
        for i in 0..stub.len().saturating_sub(7) {
            if stub[i..i + 3] == dispatch_lea {
                let disp = i32::from_le_bytes([stub[i + 3], stub[i + 4], stub[i + 5], stub[i + 6]]);
                table_base = Some((i + 7) as isize + disp as isize);
                break;
            }
        }
        let table_base = table_base.expect("dispatch lea rbx,[handler_table]") as usize;
        let load_imm_wire = map.encode(OpCode::LoadImm) as usize;
        let load_imm_off = i32::from_le_bytes([
            stub[table_base + load_imm_wire * 4],
            stub[table_base + load_imm_wire * 4 + 1],
            stub[table_base + load_imm_wire * 4 + 2],
            stub[table_base + load_imm_wire * 4 + 3],
        ]);
        assert!(load_imm_off > 0, "handler offsets must be positive (handlers after table)");
        let h_load_imm = (table_base as i64 + load_imm_off as i64) as usize;
        assert_eq!(stub[h_load_imm], 0x0F);
        assert_eq!(stub[h_load_imm + 1], 0xB6);
    }

    #[test]
    fn test_l4c_threaded_stub_uses_inline_handler_targets() {
        let map = OpcodeMap::from_seed(0xC0FF_EE01);
        let (stub, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Threaded, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let inline_load = [0x48u8, 0x63, 0x46, 0x01]; // movsxd rax, dword [rsi+1]
        assert!(
            stub.windows(inline_load.len()).any(|w| w == inline_load),
            "threaded dispatch must load per-instruction handler rel32 from bytecode stream"
        );
        let table_indexed = [0x48u8, 0x63, 0x04, 0x83]; // movsxd rax, [rbx+rax*4]
        assert!(
            !stub.windows(table_indexed.len()).any(|w| w == table_indexed),
            "threaded stub must not use opcode-indexed handler table dispatch"
        );
    }

    #[test]
    fn test_l4c_threaded_pack_embeds_targets_and_preserves_ir() {
        use crate::ir::Instruction;

        let pe_data = test_pe::create_minimal_pe64();
        let mut pe_table = PEFile::from_bytes(pe_data.clone()).unwrap();
        let mut pe_thread = PEFile::from_bytes(pe_data).unwrap();
        let seed = 0xA11C_EEDu64;
        let packed_table =
            pack_function(&mut pe_table, None, Some(seed), false, crate::vm::DispatchMode::Table)
                .unwrap();
        let packed_thread = pack_function(
            &mut pe_thread,
            None,
            Some(seed),
            false,
            crate::vm::DispatchMode::Threaded,
        )
        .unwrap();

        assert_eq!(packed_table.dispatch_mode, crate::vm::DispatchMode::Table);
        assert_eq!(packed_thread.dispatch_mode, crate::vm::DispatchMode::Threaded);
        assert_ne!(packed_table.bytecode, packed_thread.bytecode);
        assert!(
            packed_thread.bytecode.len() > packed_table.bytecode.len(),
            "threaded bytecode must grow by rel32 per instruction"
        );

        let ir_table = Instruction::disassemble(
            &packed_table.bytecode,
            &packed_table.opcode_map,
            packed_table.dispatch_mode,
        );
        let ir_thread = Instruction::disassemble(
            &packed_thread.bytecode,
            &packed_thread.opcode_map,
            packed_thread.dispatch_mode,
        );
        assert_eq!(
            ir_table.len(),
            ir_thread.len(),
            "instruction count must match across dispatch modes"
        );
        for (a, b) in ir_table.iter().zip(ir_thread.iter()) {
            assert_eq!(a.opcode, b.opcode);
            assert_eq!(a.operands, b.operands);
        }

        let meta = extract_pack_metadata_from_packed(&pe_thread).unwrap();
        assert_eq!(meta.dispatch_mode, crate::vm::DispatchMode::Threaded);
    }

    #[test]
    fn test_l4c_partial_threaded_pack_smoke() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let packed = pack_function(
            &mut pe,
            None,
            Some(0x14D0_2026),
            true,
            crate::vm::DispatchMode::Threaded,
        )
        .unwrap();
        assert_eq!(packed.dispatch_mode, crate::vm::DispatchMode::Threaded);
        assert!(!packed.bytecode.is_empty());
        assert!(!packed.partial_plan.blocks.is_empty());
    }

    #[test]
    fn test_l4c_threaded_hello_preserves_string_pool() {
        use crate::ir::Instruction;
        use crate::pe::threaded::{bytecode_prefix_offset, threaded_string_pool_link};
        use std::path::Path;

        let pe_path = Path::new("sample/hello.exe");
        if !pe_path.exists() {
            return;
        }
        let mut pe = PEFile::from_bytes(std::fs::read(pe_path).unwrap()).unwrap();
        let packed = pack_function(
            &mut pe,
            None,
            Some(0x4C34_4100),
            false,
            crate::vm::DispatchMode::Threaded,
        )
        .unwrap();
        let msg = b"Hello, World!";
        let str_off = bytecode_prefix_offset(&packed.bytecode, msg).expect(
            "threaded hello must retain embedded Hello string in bytecode",
        );
        let (pool_off, imm) = threaded_string_pool_link(&packed.bytecode, &packed.opcode_map, msg)
            .expect("load_imm must point at Hello string pool");
        assert_eq!(pool_off, str_off);
        assert!(
            packed.bytecode[imm..].starts_with(msg),
            "load_imm must reference Hello prefix at {imm}"
        );
        let ir = Instruction::pretty_print(&Instruction::disassemble(
            &packed.bytecode,
            &packed.opcode_map,
            packed.dispatch_mode,
        ));
        assert!(
            ir.contains("native_call  | 0x1"),
            "threaded hello must still use nc1 WriteFile path:\n{ir}"
        );
    }

    #[test]
    fn test_l4c_threaded_puts_hello_preserves_string_pool() {
        use crate::pe::threaded::{bytecode_prefix_offset, threaded_string_pool_link};
        use std::path::Path;

        let pe_path = Path::new("sample/puts_hello.exe");
        if !pe_path.exists() {
            return;
        }
        let mut pe = PEFile::from_bytes(std::fs::read(pe_path).unwrap()).unwrap();
        let packed = pack_function(
            &mut pe,
            None,
            Some(0x4C34_4100),
            false,
            crate::vm::DispatchMode::Threaded,
        )
        .unwrap();
        let msg = b"IAT puts hello";
        let str_off = bytecode_prefix_offset(&packed.bytecode, msg).expect(
            "threaded puts_hello must retain embedded string in bytecode",
        );
        let (pool_off, imm) = threaded_string_pool_link(&packed.bytecode, &packed.opcode_map, msg)
            .expect("load_imm must point at IAT puts string pool");
        assert_eq!(pool_off, str_off);
        assert!(
            packed.bytecode[imm..].starts_with(msg),
            "load_imm must reference IAT puts prefix at {imm}"
        );
        let ids = native_call_ids_in_bytecode_with_map_dispatch(
            &packed.bytecode,
            &packed.opcode_map,
            packed.dispatch_mode,
            Some(&packed.block_map_plan),
        );
        assert!(
            ids.iter().any(|id| is_iat_ptr_native_call(*id)),
            "threaded puts_hello must keep IAT ptr native_call, got {:?}",
            ids
        );
    }

    #[test]
    fn test_native_call_saves_and_restores_rsi() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let save_rsi = [0x48u8, 0x89, 0xB5, 0x68, 0xFF, 0xFF, 0xFF];
        let restore_rsi = [0x48u8, 0x8B, 0xB5, 0x68, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(save_rsi.len()).any(|w| w == save_rsi),
            "native_call must save bytecode rsi at [rbp-0x98]"
        );
        assert!(
            stub.windows(restore_rsi.len()).any(|w| w == restore_rsi),
            "native_call must restore bytecode rsi from [rbp-0x98]"
        );
        let rsi_on_push_depth = [0x48u8, 0x89, 0xB5, 0x18, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(rsi_on_push_depth.len()).any(|w| w == rsi_on_push_depth),
            "bytecode rsi save must not use push-depth slot [rbp-0xE8]"
        );
    }

    #[test]
    fn test_detect_main_prefers_hello_over_crt___main() {
        let pe_data = test_pe::create_pe64_hello_vs_crt___main();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let rva = super::detect_main_rva(&pe).unwrap();
        assert_eq!(
            rva,
            text.virtual_address + 0x760,
            "must pick user main, not CRT __main shim"
        );
    }

    #[test]
    fn test_detect_main_prefers_main_over_factorial_helper() {
        let pe_data = test_pe::create_pe64_fact_helper_before_main();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let rva = super::detect_main_rva(&pe).unwrap();
        assert_eq!(
            rva,
            text.virtual_address + 0x78f,
            "must pick printf main, not factorial helper"
        );
    }

    #[test]
    fn test_detect_main_prefers_hello_over_global_ctors() {
        let pe_data = test_pe::create_pe64_hello_vs_global_ctors();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let rva = super::detect_main_rva(&pe).unwrap();
        assert_eq!(
            rva,
            text.virtual_address + 0x760,
            "must pick lea+call user main, not __do_global_ctors walker"
        );
    }

    #[test]
    fn test_detect_main_mingw_combined_main_ctors___main() {
        let pe_data = test_pe::create_pe64_mingw_main_ctors___main_combined();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let rva = super::detect_main_rva(&pe).unwrap();
        assert_eq!(
            rva,
            text.virtual_address + 0x760,
            "must pick user main @0x760, not __do_global_ctors @0x7cf or __main @0x847"
        );
    }

    #[test]
    fn test_detect_main_prefers_user_main_pattern() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_off = pe.rva_to_file_offset(text.virtual_address).unwrap();
        let sec_off = pe.sections_offset;
        pe.data[sec_off + 16..sec_off + 20].copy_from_slice(&0x600u32.to_le_bytes());
        while pe.data.len() < text_off + 0x600 {
            pe.data.push(0x90);
        }
        let crt = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x05, 0x00, 0x00, 0x00, 0x90, 0xC3];
        pe.data[text_off + 0x380..text_off + 0x380 + crt.len()].copy_from_slice(&crt);
        let mainfn = [
            0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xC7, 0x45, 0xFC, 0x03, 0x00, 0x00,
            0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xC3,
        ];
        pe.data[text_off + 0x400..text_off + 0x400 + mainfn.len()].copy_from_slice(&mainfn);
        let rva = super::detect_main_rva(&pe).unwrap();
        assert_eq!(rva, text.virtual_address + 0x400);
    }

    #[test]
    fn test_jmpif_ne_uses_jne_not_je() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let ne_cond = [0x83u8, 0xF9, 0x02];
        let push_flags = [0xFFu8, 0xB5, 0x70, 0xFF, 0xFF, 0xFF];
        let mut found = false;
        for i in 0..stub.len().saturating_sub(ne_cond.len() + 32) {
            if stub[i..i + 3] != ne_cond {
                continue;
            }
            let window = &stub[i..i + 32];
            let push_at = window
                .windows(push_flags.len())
                .position(|w| w == push_flags)
                .expect("JmpIf must push saved VM flags before popfq");
            assert_eq!(window[push_at + push_flags.len()], 0x9D, "JmpIf must popfq before semantic jcc");
            assert_eq!(
                window[push_at + push_flags.len() + 1],
                0x0F,
                "JmpIf NE must use near jcc rel32"
            );
            assert_eq!(
                window[push_at + push_flags.len() + 2],
                0x85,
                "JmpIf NE must use native jne rel32 (0F 85) on restored flags"
            );
            found = true;
            break;
        }
        assert!(found, "JmpIf NE (cond 2) handler must exist in stub");
    }

    #[test]
    fn test_h_cmp_preserves_zf_in_flag_mask() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let mask = [0x48u8, 0x25, 0xC1, 0x08, 0x00, 0x00];
        assert!(
            stub.windows(mask.len()).any(|w| w == mask),
            "h_cmp must mask flags with 0x8C1 (ZF|SF|CF|OF), not 0x881"
        );
    }

    #[test]
    fn test_jmpif_taken_uses_add_rsi_rbx() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let taken_add = [0x48u8, 0x01, 0xDE];
        assert!(
            stub.windows(taken_add.len()).any(|w| w == taken_add),
            "jmpif_taken must add target offset in rbx to bytecode base in rsi"
        );
    }

    #[test]
    fn test_three_digit_printer_uses_rcx_buffer() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        // three_digit path must store via rcx (buffer from lea rcx,[rbp-0xF0]), not wrong disp32
        let bad_hundreds = [0x88u8, 0x85, 0xF0, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(bad_hundreds.len()).any(|w| w == bad_hundreds),
            "three_digit must not use mov [rbp+disp32], al with F0 FF FF FF (-0x10)"
        );
        assert!(stub.windows(2).any(|w| w == [0x88u8, 0x01]));
        assert!(stub.windows(3).any(|w| w == [0x88u8, 0x41, 0x01]));
        assert!(stub.windows(3).any(|w| w == [0x88u8, 0x51, 0x02]));
        assert!(stub.windows(4).any(|w| w == [0xC6u8, 0x41, 0x03, 0x0A]));
    }

    #[test]
    fn test_pack_preserves_overlay_data() {
        let pe_data = test_pe::create_pe64_with_overlay();
        let original_data = pe_data.clone();
        
        let marker_offset = pe_data.len() - 100;
        let original_marker = original_data[marker_offset..marker_offset + 10].to_vec();
        
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let original_size = pe.data.len();
        
        pack_pe(&mut pe, None);
        
        let preserved_marker = &pe.data[marker_offset..marker_offset + 10];
        assert_eq!(
            &original_marker[..], preserved_marker,
            "Overlay data should not be modified"
        );
        
        for i in 0..original_size {
            if i >= marker_offset && i < marker_offset + 10 {
                continue;
            }
            let original = original_data[i];
            let packed = pe.data[i];
            
            if packed != original {
                let in_section_table = i >= pe.sections_offset 
                    && i < pe.sections_offset + (20 * 40);
                let in_optional_header = i >= pe.optional_header_offset 
                    && i < pe.optional_header_offset + 240;
                let in_coff_header = i >= pe.pe_header_offset + 4
                    && i < pe.pe_header_offset + 24;
                assert!(in_section_table || in_optional_header || in_coff_header, 
                    "Only headers should be modified, but byte at {:#x} changed from {:#x} to {:#x}", 
                    i, original, packed);
            }
        }
    }

    #[test]
    fn test_find_printf_literal_in_rdata() {
        let pe_data = test_pe::create_pe64_with_overlay();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let sec = pe.get_section(".data").unwrap();
        let off = sec.pointer_to_raw_data as usize;
        let msg = b"Hello, World!\n";
        while pe.data.len() < off + msg.len() {
            pe.data.push(0);
        }
        pe.data[off..off + msg.len()].copy_from_slice(msg);
        let found = super::find_string_literal_in_pe(&pe);
        assert_eq!(found.as_deref(), Some(&b"Hello, World!\n"[..]));
    }

    #[test]
    fn test_module_next_advances_rcx_not_rbx() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let advance_rcx = [0x48u8, 0x8B, 0x09];
        let advance_rbx = [0x48u8, 0x8B, 0x1B];
        assert!(
            stub.windows(advance_rcx.len()).any(|w| w == advance_rcx),
            "module_next must advance list with mov rcx, [rcx]"
        );
        assert!(
            !stub.windows(advance_rbx.len()).any(|w| w == advance_rbx),
            "module_next must not dereference uninitialized rbx"
        );
    }

    #[test]
    fn test_handler_targets_for_push_and_native_call() {
        let (stub, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let pat = [0x48u8, 0x8D, 0x1D];
        let mut table_base = 0usize;
        for i in 0..stub.len().saturating_sub(7) {
            if stub[i..i + 3] == pat {
                let disp = i32::from_le_bytes([stub[i + 3], stub[i + 4], stub[i + 5], stub[i + 6]]);
                table_base = (i as i64 + 7 + disp as i64) as usize;
                break;
            }
        }
        let table_end = table_base + 1024;
        let map = OpcodeMap::from_seed(0);
        let load_imm_wire = map.encode(OpCode::LoadImm) as usize;
        let load_imm_off = i32::from_le_bytes(
            stub[table_base + load_imm_wire * 4..table_base + load_imm_wire * 4 + 4]
                .try_into()
                .unwrap(),
        );
        let load_imm_target = (table_base as i64 + load_imm_off as i64) as usize;
        assert!(load_imm_off > 0);
        assert!(load_imm_target >= table_end);
        assert_eq!(stub[load_imm_target], 0x0F);
        assert_eq!(stub[load_imm_target + 1], 0xB6);

        let nc_wire = map.encode(OpCode::NativeCall) as usize;
        let nc_off = i32::from_le_bytes(
            stub[table_base + nc_wire * 4..table_base + nc_wire * 4 + 4]
                .try_into()
                .unwrap(),
        );
        let nc_target = (table_base as i64 + nc_off as i64) as usize;
        assert!(nc_off > 0);
        assert!(nc_target >= table_end);
        assert_eq!(stub[nc_target], 0x48);
        assert_eq!(stub[nc_target + 1], 0x8B);
    }

    #[test]
    fn test_pack_puts_thunk_emits_iat_native_call() {
        let pe_data = test_pe::create_pe64_with_puts_thunk_call();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let imports = pe.parse_imports().unwrap();
        let puts = imports.entries().iter().find(|e| e.name == "puts").unwrap();
        let text = pe.get_section(".text").unwrap();
        let packed = pack_pe(&mut pe, Some(text.virtual_address + 0x20));
        let bc = packed.bytecode;
        let map = packed.opcode_map;
        let ids = native_call_ids_in_bytecode_with_map(&bc, &map);
        assert!(
            ids.iter().any(|id| *id == native_call_iat_ptr_id(puts.iat_rva)),
            "expected IAT puts native_call with ptr flag, got {:?}",
            ids
        );
        assert!(bc.len() < 300, "puts thunk pack should stay small, got {} bytes", bc.len());
    }

    #[test]
    fn test_l4a_seed_shuffle_changes_wire_bytes_same_ir() {
        use crate::ir::Instruction;

        let pe_data = test_pe::create_minimal_pe64();
        let mut pe_a = PEFile::from_bytes(pe_data.clone()).unwrap();
        let mut pe_b = PEFile::from_bytes(pe_data).unwrap();
        let packed_a = pack_pe_seed(&mut pe_a, None, 0xAAAA_AAAA);
        let packed_b = pack_pe_seed(&mut pe_b, None, 0xBBBB_BBBB);
        assert_ne!(packed_a.bytecode, packed_b.bytecode);
        let ir_a = ir_pretty(&packed_a);
        let ir_b = ir_pretty(&packed_b);
        assert!(ir_a.contains("load_imm"));
        assert!(ir_b.contains("load_imm"));
        assert!(ir_a.contains("exit"));
        assert!(ir_b.contains("exit"));
    }

    #[test]
    fn test_l4b_add_handler_polymorphism_changes_stub_not_ir() {
        use crate::ir::Instruction;
        use crate::pe::vm_stub::create_vm_interpreter_stub;

        fn seed_for_add_variant(target: u8) -> u64 {
            for seed in 0..512u64 {
                if OpcodeMap::from_seed(seed).add_handler_variant() == target {
                    return seed;
                }
            }
            panic!("no seed for Add variant {target}");
        }

        let seed_a = seed_for_add_variant(0);
        let seed_b = seed_for_add_variant(1);
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe_a = PEFile::from_bytes(pe_data.clone()).unwrap();
        let mut pe_b = PEFile::from_bytes(pe_data).unwrap();
        let packed_a = pack_pe_seed(&mut pe_a, None, seed_a);
        let packed_b = pack_pe_seed(&mut pe_b, None, seed_b);

        let (stub_a, _) = create_vm_interpreter_stub(0, 0, &packed_a.opcode_map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let (stub_b, _) = create_vm_interpreter_stub(0, 0, &packed_b.opcode_map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        assert_ne!(stub_a, stub_b, "different Add variants must change stub bytes");

        let ir_a = ir_pretty(&packed_a);
        let ir_b = ir_pretty(&packed_b);
        assert_eq!(ir_a, ir_b, "logical IR must match across Add handler variants");
        assert!(ir_a.contains("exit"));
    }

    #[test]
    fn test_l4a_embedded_map_roundtrip_in_section() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let packed = pack_pe_seed(&mut pe, None, 0x1234_5678_9ABC_DEF0);
        let map = extract_opcode_map_from_packed(&pe).unwrap();
        assert_eq!(map.seed(), 0x1234_5678_9ABC_DEF0);
        assert_eq!(map.wire_table(), packed.opcode_map.wire_table());
    }

    #[test]
    fn test_pack_does_not_lift_forward_crt_call() {
        let pe_data = test_pe::create_pe64_with_forward_crt_call();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let packed = pack_pe(&mut pe, Some(text.virtual_address + 0x20));
        let bc = packed.bytecode;
        let map = packed.opcode_map;
        assert!(
            bc.len() < 400,
            "forward CRT must not be lifted into bytecode, got {} bytes",
            bc.len()
        );
    }

    #[test]
    fn test_l4e_block_maps_differ_for_same_semantic_opcode() {
        let seed = 0x14E0_2026u64;
        let map0 = BlockMapPlan::block_opcode_map(seed, 0);
        let map1 = BlockMapPlan::block_opcode_map(seed, 1);
        assert_ne!(
            map0.encode(OpCode::LoadImm),
            map1.encode(OpCode::LoadImm),
            "same semantic load_imm must encode to different wire bytes in different blocks"
        );
    }

    #[test]
    fn test_l4e_packed_bytecode_emits_block_map_refresh() {
        let pe_data = test_pe::create_pe64_with_countdown_loop();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x20;
        let packed = pack_pe_seed(&mut pe, Some(main_rva), 0x14E0_2026);
        assert!(
            packed.bytecode.contains(&META_WIRE_BYTE),
            "packed main must emit L4e block-map refresh meta ops"
        );
        assert!(packed.block_map_plan.entries.len() >= 2);
        let block_plan = extract_block_map_from_packed(&pe).unwrap();
        assert_eq!(block_plan.entries.len(), packed.block_map_plan.entries.len());
        let insns = disasm_packed(&packed);
        assert!(
            insns.iter().any(|i| {
                i.operands
                    .iter()
                    .any(|o| matches!(o, crate::ir::Operand::Unknown(v) if v == b"set_block_map"))
            }),
            "IR disassembly must surface set_block_map refresh ops"
        );
    }

    #[test]
    fn test_default_pack_full_virt_no_run_native() {
        let pe_data = test_pe::create_minimal_pe64();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let packed = pack_pe(&mut pe, None);
        assert!(
            packed.partial_plan.full_virt,
            "default pack must stay full VM (L4b-compatible)"
        );
        let run_wire = packed.opcode_map.encode(OpCode::RunNative);
        let _ = run_wire;
        assert!(
            !packed_contains_op(&packed, OpCode::RunNative),
            "default pack must not emit run_native"
        );
    }

    #[test]
    fn test_l4d_partial_virt_emits_run_native_for_native_bb() {
        use crate::ir::Instruction;
        use crate::vm::OpCode;

        let pe_data = test_pe::create_pe64_with_countdown_loop();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x20;
        let packed = pack_pe_partial(&mut pe, Some(main_rva), 0x14D0_2026);
        assert!(
            !packed.partial_plan.full_virt,
            "countdown loop fixture should use partial virt"
        );
        assert!(
            packed_contains_op(&packed, OpCode::RunNative),
            "partial pack must emit run_native, got plan {:?}",
            packed.partial_plan.blocks
        );
        let ir = ir_pretty(&packed);
        assert!(ir.contains("run_native"), "IR must show run_native:\n{ir}");
        let plan = extract_partial_plan_from_packed(&pe).unwrap();
        assert_eq!(plan.decode_key, packed.partial_plan.decode_key);

        // Documented Windows verify seed: --partial --seed 0x14D02026
        let sync = packed.native_sync.clone();
        assert!(
            sync.iter().any(|(off, _)| *off == -4),
            "countdown loop counter [rbp-4] must sync across run_native"
        );
        let (stub, _) = create_vm_interpreter_stub(0, 0, &packed.opcode_map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &sync);
        assert!(
            stub.windows(7).any(|w| w == [0x48, 0x89, 0xAD, 0xE8, 0xFE, 0xFF, 0xFF]),
            "run_native handler must persist VM frame at [rbp-0x118]"
        );
        assert!(
            stub.windows(3).any(|w| w == [0x48, 0x89, 0x05]),
            "prologue must store native frame ptr in .knvest native_frame_ptr"
        );
        assert_run_native_stub_uses_native_rsp(&stub);
        assert_run_native_pre_sync_order(&stub);
        for sled in collect_run_native_sleds(&packed.bytecode, &packed.native_sleds, &packed) {
            assert_run_native_sled_straight_line(&sled);
        }
    }

    /// In-repo evidence for Windows L4d debugging: first sled + handler contract.
    #[test]
    fn test_l4d_run_native_evidence_countdown_fixture() {
        let seed = 0x14D0_2026;
        let pe_data = test_pe::create_pe64_with_countdown_loop();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x20;
        let packed = pack_pe_partial(&mut pe, Some(main_rva), seed);
        let sleds = collect_run_native_sleds(&packed.bytecode, &packed.native_sleds, &packed);
        assert!(!sleds.is_empty(), "partial countdown must emit run_native sleds");
        assert_eq!(
            sleds[0],
            vec![0x83, 0x6D, 0xFC, 0x01, 0xC3],
            "first run_native sled bytes (sub dword [rbp-4],1; ret)"
        );
        let sync = packed.native_sync.clone();
        let (stub, _) = create_vm_interpreter_stub(0, 0, &packed.opcode_map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &sync);
        assert_run_native_stub_uses_native_rsp(&stub);
        // Handler contract: prologue caches native_frame_ptr; invoke lea r14 + mov rbp,r14 before sync.
    }

    fn assert_run_native_pre_sync_order(stub: &[u8]) {
        let invoke_prologue = [0x48u8, 0x8B, 0x06, 0x49, 0x89, 0xC3];
        let run_site = stub
            .windows(invoke_prologue.len())
            .position(|w| w == invoke_prologue)
            .expect("h_run_native invoke prologue");
        let bail_site = stub[run_site + 1..]
            .windows(invoke_prologue.len())
            .position(|w| w == invoke_prologue)
            .map(|p| run_site + 1 + p)
            .expect("h_bail_native invoke prologue");
        let run_body = &stub[run_site..bail_site];
        let call_at = run_body
            .windows(3)
            .position(|w| w == [0x41, 0xFF, 0xD2])
            .expect("call r10");
        let before_call = &run_body[..call_at];
        let sync_at = before_call
            .windows(3)
            .position(|w| w == [0x89, 0x45, 0xFC])
            .expect("pre-sync mov [rbp-4], eax");
        let prefix = &before_call[..sync_at];
        let rbp_at = prefix
            .windows(3)
            .rposition(|w| w == [0x4C, 0x89, 0xF5])
            .expect("mov rbp,r14 before first pre-sync store");
        let between = &prefix[rbp_at + 3..];
        assert!(
            between.is_empty()
                || between.starts_with(&[0x41, 0x8B, 0x47])
                || between.starts_with(&[0x41, 0x8B, 0x87]),
            "only r15 spill load may appear between mov rbp,r14 and first pre-sync store"
        );
        assert!(
            prefix.windows(3).any(|w| w == [0x49, 0x89, 0xEF]),
            "must mov r15,rbp before native frame switch"
        );
    }

    fn collect_run_native_sleds(
        bytecode: &[u8],
        native_sleds: &[u8],
        packed: &PackResult,
    ) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for ins in disasm_packed(packed) {
            if ins.opcode != OpCode::RunNative {
                continue;
            }
            let mut ops: Vec<u64> = ins
                .operands
                .iter()
                .filter_map(|o| match o {
                    crate::ir::Operand::Immediate(v) => Some(*v),
                    _ => None,
                })
                .collect();
            if ops.is_empty() {
                continue;
            }
            let off = ops[0] as usize;
            if off < native_sleds.len() {
                let tail = &native_sleds[off..];
                let end = tail
                    .iter()
                    .position(|&b| b == 0xC3)
                    .map(|p| p + 1)
                    .unwrap_or(tail.len());
                out.push(tail[..end].to_vec());
            }
        }
        let _ = bytecode;
        out
    }

    fn assert_run_native_stub_uses_native_rsp(stub: &[u8]) {
        let call_r10 = [0x41u8, 0xFF, 0xD2];
        let call_at = stub
            .windows(call_r10.len())
            .position(|w| w == call_r10)
            .expect("run_native handler must call r10");
        let prefix = &stub[..call_at];
        assert!(
            prefix.windows(3).any(|w| w == [0x4C, 0x89, 0xF5]),
            "run_native must mov rbp,r14 before sled call (direct lea r14 from native_stack_top)"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x48, 0x89, 0xCD]),
            "run_native must not mov rbp,rcx (rcx may hold VM counter)"
        );
        assert!(
            prefix.windows(3).any(|w| w == [0x4C, 0x8D, 0x35]),
            "run_native must lea r14,[rip+native_stack_top] before native rbp switch"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x4C, 0x8B, 0x35]),
            "run_native must not indirect-load native frame in handler"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x49, 0x89, 0xE5]),
            "run_native must not use r13 as VM spill base"
        );
        assert!(
            prefix.windows(3).any(|w| w == [0x49, 0x89, 0xEF]),
            "run_native must mov r15,rbp before native rbp switch"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x49, 0x89, 0xFD]),
            "run_native must not emit mov r13,rdi (wrong mov r15,rbp encoding)"
        );
        assert!(
            prefix.windows(7).any(|w| w == [0x48, 0x8D, 0xA5, 0x80, 0x00, 0x00, 0x00]),
            "run_native must lea rsp,[rbp+0x80] (call stack above [rbp-4] locals)"
        );
        assert!(
            !prefix.windows(4).any(|w| w == [0x48, 0x8D, 0x61, 0x80]),
            "run_native must not lea rsp,[rcx+0x80] (rcx may hold stale VM reg during sync)"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x89, 0x41, 0xFC]),
            "pre-sync must not store via [rcx-4] (rcx may hold VM counter)"
        );
        assert!(
            prefix.windows(4).any(|w| w == [0x48, 0x83, 0xE4, 0xF0]),
            "run_native must and rsp,-16 before sled call"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x48, 0x89, 0xCC]),
            "run_native must not mov rsp,rcx (shadow overlaps loop counter at [rbp-4])"
        );
    }

    fn assert_run_native_sled_straight_line(sled: &[u8]) {
        assert!(sled.ends_with(&[0xC3]), "sled must end with ret, got {sled:02x?}");
        let body = &sled[..sled.len() - 1];
        assert!(!body.contains(&0xE8), "sled must not contain call rel32: {sled:02x?}");
        assert!(
            !body.windows(2).any(|w| w == [0xFF, 0x25] || w == [0xFF, 0x15]),
            "sled must not contain indirect call: {sled:02x?}"
        );
        assert!(
            !body.contains(&0xEB) && !body.contains(&0xE9),
            "sled must not branch: {sled:02x?}"
        );
        for i in 0..body.len().saturating_sub(1) {
            if body[i] == 0x0F {
                let b = body[i + 1];
                assert!(
                    !(0x80..=0x8F).contains(&b),
                    "sled must not contain near jcc: {sled:02x?}"
                );
            }
        }
    }

    #[test]
    fn test_l4d_minimal_call_then_native_dec_partial() {
        use crate::ir::Instruction;
        use crate::vm::OpCode;

        let seed = 0x14D0_2026;
        let pe_data = test_pe::create_pe64_call_then_native_dec();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x20;
        let packed = pack_pe_partial(&mut pe, Some(main_rva), seed);
        assert!(
            packed_contains_op(&packed, OpCode::RunNative),
            "minimal call→native fixture must emit run_native"
        );
        let ir = ir_pretty(&packed);
        assert!(ir.contains("run_native"), "IR must show run_native:\n{ir}");
        let sleds = collect_run_native_sleds(&packed.bytecode, &packed.native_sleds, &packed);
        assert!(!sleds.is_empty(), "expected at least one native sled");
        assert!(
            sleds.iter().any(|s| s.starts_with(&[0x83, 0x6D])),
            "expected decrement sled sub [rbp+disp], got {:?}",
            sleds
        );
        let sync = packed.native_sync.clone();
        let (stub, _) = create_vm_interpreter_stub(0, 0, &packed.opcode_map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &sync);
        assert_run_native_stub_uses_native_rsp(&stub);
        for sled in &sleds {
            assert_run_native_sled_straight_line(sled);
        }
    }

    #[test]
    fn test_l4d_unknown_emits_bail_native_in_partial_mode() {
        use crate::vm::OpCode;
        use super::super::lifter::{X64Instruction, X64InstrKind, lift_to_vm_bytecode_for_main};
        use super::super::partial::{NativeSledBuilder, PartialVirtPlan};
        use super::super::cfg::{build_basic_blocks, disassemble_main_window};

        let pe_data = test_pe::create_pe64_with_countdown_loop();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_off = pe.rva_to_file_offset(text.virtual_address).unwrap() + 0x20;
        let text_end = pe.rva_to_file_offset(text.virtual_address).unwrap()
            + text.size_of_raw_data as usize;
        let mut instrs = disassemble_main_window(&pe.data, main_off, text_end);
        let loop_idx = instrs
            .iter()
            .position(|i| matches!(i.kind, X64InstrKind::CmpMemImm { .. }))
            .unwrap_or(0);
        instrs.insert(
            loop_idx + 1,
            X64Instruction {
                offset: instrs[loop_idx].offset + instrs[loop_idx].bytes.len(),
                bytes: vec![0x0F, 0x0B],
                kind: X64InstrKind::Unknown,
            },
        );
        let blocks = build_basic_blocks(&instrs, main_off);
        let plan = PartialVirtPlan::from_seed(0x14D0_2026, &blocks, main_off, &pe, true, &instrs).unwrap();
        let map = OpcodeMap::from_seed(0x14D0_2026);
        let mut sled = NativeSledBuilder::new();
        set_active_map(&map);
        let (bc, _) = lift_to_vm_bytecode_for_main(
            &instrs,
            text.virtual_address + 0x20,
            main_off,
            &pe,
            None,
            &pe.parse_imports().unwrap(),
            &map,
            Some(&plan),
            &crate::vm::BlockMapPlan::default(),
            &mut sled,
        );
        clear_active_map();
        assert!(
            bytecode_contains_semantic(&bc, map.seed(), &BlockMapPlan::default(), OpCode::BailNative),
            "Unknown in VM BB must emit bail_native in partial mode"
        );
        assert!(!sled.sleds.is_empty(), "bail_native needs a native sled");
    }

    #[test]
    fn test_l4d_prologue_frame_setup_bb_cannot_run_native() {
        use super::super::lifter::{X64Instruction, X64InstrKind, X64Reg};
        use super::super::cfg::BasicBlock;
        use super::super::partial::bb_can_run_native;

        let instrs = vec![
            X64Instruction {
                offset: 0x100,
                bytes: vec![0x48, 0x89, 0xE5],
                kind: X64InstrKind::MovRegReg {
                    dst: X64Reg::Rbp,
                    src: X64Reg::Rsp,
                },
            },
            X64Instruction {
                offset: 0x103,
                bytes: vec![0x48, 0x83, 0xEC, 0x20],
                kind: X64InstrKind::SubRegImm {
                    reg: X64Reg::Rsp,
                    imm: 0x20,
                },
            },
            X64Instruction {
                offset: 0x107,
                bytes: vec![0xC7, 0x45, 0xFC, 0x03, 0x00, 0x00, 0x00],
                kind: X64InstrKind::MovMemImm {
                    base: X64Reg::Rbp,
                    offset: -4,
                    imm: 3,
                },
            },
        ];
        let bb = BasicBlock {
            id: 0,
            start: 0x100,
            end: 0x10E,
            leader_idx: 0,
            tail_idx: 2,
            has_back_edge: false,
            native_eligible: true,
            is_loop_header: false,
        };
        let block_refs = vec![&bb];
        assert!(
            !bb_can_run_native(&instrs, &bb, &block_refs, 0x100),
            "prologue mov rbp,rsp / sub rsp must not become run_native sled"
        );
    }

    #[test]
    fn test_l4d_seed_14d02026_no_run_native_before_loop() {
        use crate::ir::Instruction;
        use crate::vm::OpCode;

        let seed = 0x14D0_2026;
        let pe_data = test_pe::create_pe64_with_countdown_loop();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x20;
        let main_off = pe.rva_to_file_offset(main_rva).unwrap();
        let text_end = pe.rva_to_file_offset(text.virtual_address).unwrap()
            + text.size_of_raw_data as usize;
        let instrs = super::super::cfg::disassemble_main_window(&pe.data, main_off, text_end);
        let blocks = super::super::cfg::build_basic_blocks(&instrs, main_off);
        let loop_start = blocks
            .iter()
            .filter(|b| b.is_loop_header)
            .map(|b| b.start)
            .min()
            .expect("loop header in countdown fixture");

        let packed = pack_pe_partial(&mut pe, Some(main_rva), seed);
        let sleds = collect_run_native_sleds(&packed.bytecode, &packed.native_sleds, &packed);
        assert!(!sleds.is_empty(), "partial countdown must emit run_native sleds");
        assert_eq!(
            sleds[0],
            vec![0x83, 0x6D, 0xFC, 0x01, 0xC3],
            "first run_native sled must be sub dword [rbp-4],1; ret"
        );

        for ins in disasm_packed(&packed) {
            if ins.opcode != OpCode::RunNative {
                continue;
            }
            let orig_rva = ins
                .operands
                .get(1)
                .and_then(|o| match o {
                    crate::ir::Operand::Immediate(v) => Some(*v as u32),
                    _ => None,
                })
                .unwrap_or(0);
            assert!(
                orig_rva >= loop_start as u32,
                "run_native orig_rva {orig_rva:#x} must not precede loop head {loop_start:#x}:\n{}",
                ir_pretty(&packed)
            );
        }

        for entry in &packed.partial_plan.blocks {
            if entry.virtualized {
                continue;
            }
            assert!(
                entry.start_rva >= loop_start as u32,
                "plan-native BB {} at {:#x} must not precede loop head {:#x}",
                entry.id,
                entry.start_rva,
                loop_start
            );
        }
    }

    #[test]
    fn test_l4d_native_sleds_must_not_touch_host_rbp_rsp() {
        use crate::ir::Instruction;
        use crate::vm::OpCode;

        let seed = 0x14D0_2026;
        let pe_data = test_pe::create_pe64_with_countdown_loop();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x20;
        let packed = pack_pe_partial(&mut pe, Some(main_rva), seed);
        let sleds = collect_run_native_sleds(&packed.bytecode, &packed.native_sleds, &packed);
        for sled in &sleds {
            let body = &sled[..sled.len().saturating_sub(1)];
            assert!(
                !body.windows(3).any(|w| w == [0x48, 0x89, 0xE5]),
                "sled must not contain mov rbp,rsp (clobbers VM/native frame): {sled:02x?}"
            );
            assert!(
                !body.windows(4).any(|w| w == [0x48, 0x89, 0xE1]),
                "sled must not contain mov rcx,rsp: {sled:02x?}"
            );
            assert!(
                !body.windows(4).any(|w| w == [0x48, 0x89, 0xEC]),
                "sled must not contain mov rsp,rbp: {sled:02x?}"
            );
            assert!(
                !body.windows(4).any(|w| w == [0x48, 0x89, 0xCC]),
                "sled must not contain mov rsp,rsp: {sled:02x?}"
            );
            assert!(
                !body.windows(4).any(|w| w.starts_with(&[0x48, 0x83, 0xEC])
                    || w.starts_with(&[0x48, 0x83, 0xC4])
                    || w.starts_with(&[0x48, 0x81, 0xEC])
                    || w.starts_with(&[0x48, 0x81, 0xC4])),
                "sled must not adjust host rsp: {sled:02x?}"
            );
        }
        let insns = disasm_packed(&packed);
        let first_rn = insns.iter().position(|i| i.opcode == OpCode::RunNative);
        let first_nc = insns.iter().position(|i| i.opcode == OpCode::NativeCall);
        if let (Some(rn), Some(nc)) = (first_rn, first_nc) {
            assert!(
                rn > nc,
                "run_native must not precede first native_call (printf) in bytecode:\n{}",
                ir_pretty(&packed)
            );
        }
    }

    #[test]
    fn test_l4d_stub_has_native_sled_handlers() {
        let map = OpcodeMap::from_seed(0xDEAD_BEEF);
        let (stub, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let call_r10 = [0x41u8, 0xFF, 0xD2];
        assert!(
            stub.windows(call_r10.len()).any(|w| w == call_r10),
            "L4d native sled invoke must call r10 (not rax) to avoid IAT clash"
        );
    }

    #[test]
    fn test_packed_native_sync_matches_lift_stack_map_for_counter() {
        let seed = 0x14D0_2026;
        let pe_data = test_pe::create_pe64_call_then_native_dec();
        let mut pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let main_rva = text.virtual_address + 0x20;
        let main_off = pe.rva_to_file_offset(main_rva).unwrap();
        let text_end = pe.rva_to_file_offset(text.virtual_address).unwrap()
            + text.size_of_raw_data as usize;
        let imports = pe.parse_imports().unwrap();
        let mut all_instrs = Vec::new();
        let cfg = super::super::cfg::collect_cfg_entries(
            &pe,
            main_off,
            main_off,
            pe.rva_to_file_offset(text.virtual_address).unwrap(),
            text_end,
            &imports,
            false,
        )
        .unwrap();
        for entry in cfg {
            let instrs = super::super::cfg::disassemble_cfg_function(
                &pe.data[entry..entry + super::super::cfg::MAX_FUNCTION_BYTES.min(pe.data.len() - entry)],
                entry,
            );
            all_instrs.extend(instrs);
        }
        all_instrs.sort_by_key(|i| i.offset);
        let blocks = build_basic_blocks(&all_instrs, main_off);
        let plan = PartialVirtPlan::from_seed(seed, &blocks, main_off, &pe, true, &all_instrs).unwrap();
        let map = OpcodeMap::from_seed(seed);
        let mut sled = NativeSledBuilder::new();
        set_active_map(&map);
        let (_, lift_map) = lift_to_vm_bytecode_for_main(
            &all_instrs,
            main_rva,
            main_off,
            &pe,
            None,
            &imports,
            &map,
            Some(&plan),
            &crate::vm::BlockMapPlan::default(),
            &mut sled,
        );
        clear_active_map();
        let packed = pack_pe_partial(&mut pe, Some(main_rva), seed);
        let prebuild = prebuild_stack_map(&all_instrs);
        if prebuild.get(&-4) != lift_map.get(&-4) {
            assert_ne!(
                prebuild.get(&-4),
                packed.native_sync.iter().find(|(o, _)| *o == -4).map(|(_, r)| r),
                "packed sync must follow lift map, not prebuild file order"
            );
        }
        let sync_reg = packed
            .native_sync
            .iter()
            .find(|(off, _)| *off == -4)
            .map(|(_, reg)| *reg)
            .expect("counter [rbp-4] sync pair");
        assert_eq!(
            lift_map.get(&-4),
            Some(&sync_reg),
            "native_sync must use lifter stack_map for [rbp-4]"
        );
    }
}
