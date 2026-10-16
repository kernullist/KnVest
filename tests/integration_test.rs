use std::fs;
use std::path::PathBuf;
use knvest::OpcodeMap;
use knvest::DispatchMode;

#[test]
fn test_pack_and_ir_workflow() {
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_output");
    fs::create_dir_all(&test_dir).unwrap();

    let minimal_pe = knvest::test_pe::create_minimal_pe64();
    let input_path = test_dir.join("test_input.exe");
    fs::write(&input_path, &minimal_pe).unwrap();

    let output_path = test_dir.join("test_output.exe");
    
    let result = knvest::pack_executable(&input_path, &output_path, None, Some(0x1234), false, DispatchMode::Table, 0, knvest::IsaMode::Reg, false);
    assert!(result.is_ok(), "Packing should succeed");

    assert!(output_path.exists(), "Packed file should exist");

    let packed_pe = knvest::PEFile::from_file(&output_path);
    assert!(packed_pe.is_ok(), "Packed file should be valid PE");

    let pe = packed_pe.unwrap();
    let opcode_map = knvest::extract_opcode_map(&pe).expect("Should extract opcode map");
    let bytecode_result = knvest::extract_bytecode(&pe);
    assert!(bytecode_result.is_ok(), "Should extract bytecode");

    let bytecode = bytecode_result.unwrap();
    assert!(!bytecode.is_empty(), "Bytecode should not be empty");

    let layout = knvest::extract_layout_plan(&pe).expect("Should extract layout");
    let block_plan = knvest::extract_block_map_plan(&pe).ok();
    let instructions = knvest::disassemble_with_layout(
        &bytecode,
        &opcode_map,
        block_plan.as_ref(),
        DispatchMode::Table,
        &layout,
    );
    assert!(!instructions.is_empty(), "Should have instructions");

    fs::remove_dir_all(&test_dir).ok();
}

#[test]
fn test_ir_display() {
    let map = OpcodeMap::from_seed(42);
    let mut bytecode = vec![map.encode(knvest::OpCode::LoadImm), 0];
    bytecode.extend_from_slice(&42u64.to_le_bytes());
    bytecode.push(map.encode(knvest::OpCode::Exit));
    bytecode.push(0);

    let instructions = knvest::disassemble(&bytecode, &map, DispatchMode::Table);
    let output = knvest::pretty_print(&instructions);
    
    assert!(output.contains("load_imm"), "Output should contain load_imm");
    assert!(output.contains("exit"), "Output should contain exit");
    assert!(output.contains("0x2a"), "Output should contain hex value 42");
}

#[test]
fn test_l4a_different_seeds_different_opcode_streams() {
    let minimal_pe = knvest::test_pe::create_minimal_pe64();
    let pe_a = knvest::PEFile::from_bytes(minimal_pe.clone()).unwrap();
    let pe_b = knvest::PEFile::from_bytes(minimal_pe.clone()).unwrap();
    let mut pe_a = pe_a;
    let mut pe_b = pe_b;
    let packed_a = knvest::pe::packer::pack_function(&mut pe_a, None, Some(1), false, DispatchMode::Table, 0, knvest::IsaMode::Reg, false).unwrap();
    let packed_b = knvest::pe::packer::pack_function(&mut pe_b, None, Some(2), false, DispatchMode::Table, 0, knvest::IsaMode::Reg, false).unwrap();
    assert_ne!(packed_a.bytecode, packed_b.bytecode);
    let ir_a = knvest::pretty_print(&knvest::disassemble_with_layout(
        &packed_a.bytecode,
        &packed_a.opcode_map,
        Some(&packed_a.block_map_plan),
        packed_a.dispatch_mode,
        &packed_a.layout_plan,
    ));
    let ir_b = knvest::pretty_print(&knvest::disassemble_with_layout(
        &packed_b.bytecode,
        &packed_b.opcode_map,
        Some(&packed_b.block_map_plan),
        packed_b.dispatch_mode,
        &packed_b.layout_plan,
    ));
    assert!(ir_a.contains("load_imm"));
    assert!(ir_b.contains("load_imm"));
}

#[test]
fn test_l5c_layout_seed_diversification() {
    let minimal_pe = knvest::test_pe::create_minimal_pe64();
    let pe_a = knvest::PEFile::from_bytes(minimal_pe.clone()).unwrap();
    let pe_b = knvest::PEFile::from_bytes(minimal_pe.clone()).unwrap();
    let mut pe_a = pe_a;
    let mut pe_b = pe_b;
    let packed_a = knvest::pe::packer::pack_function(
        &mut pe_a,
        None,
        Some(0x1111_1111),
        false,
        DispatchMode::Table,
        0,
        knvest::IsaMode::Reg,
        false,
    )
    .unwrap();
    let packed_b = knvest::pe::packer::pack_function(
        &mut pe_b,
        None,
        Some(0x2222_2222),
        false,
        DispatchMode::Table,
        0,
        knvest::IsaMode::Reg,
        false,
    )
    .unwrap();
    assert_ne!(
        packed_a.bytecode,
        packed_b.bytecode,
        "different layout seeds must change wire bytecode"
    );
    assert_ne!(
        packed_a.layout_plan.layout_key,
        packed_b.layout_plan.layout_key
    );
    let ir_a = knvest::pretty_print(&knvest::disassemble_with_layout(
        &packed_a.bytecode,
        &packed_a.opcode_map,
        Some(&packed_a.block_map_plan),
        packed_a.dispatch_mode,
        &packed_a.layout_plan,
    ));
    let ir_b = knvest::pretty_print(&knvest::disassemble_with_layout(
        &packed_b.bytecode,
        &packed_b.opcode_map,
        Some(&packed_b.block_map_plan),
        packed_b.dispatch_mode,
        &packed_b.layout_plan,
    ));
    assert!(ir_a.contains("load_imm"));
    assert!(ir_b.contains("load_imm"));
    assert!(ir_a.contains("exit"));
    assert!(ir_b.contains("exit"));
}

#[test]
fn test_l4c_threaded_pack_and_ir() {
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_output_threaded");
    fs::create_dir_all(&test_dir).unwrap();

    let minimal_pe = knvest::test_pe::create_minimal_pe64();
    let input_path = test_dir.join("test_input.exe");
    fs::write(&input_path, &minimal_pe).unwrap();

    let output_path = test_dir.join("test_output.exe");
    let result = knvest::pack_executable(
        &input_path,
        &output_path,
        None,
        Some(0x5678),
        false,
        DispatchMode::Threaded,
        0,
        knvest::IsaMode::Reg,
        false,
    );
    assert!(result.is_ok(), "Threaded packing should succeed");

    let pe = knvest::PEFile::from_file(&output_path).unwrap();
    let meta = knvest::pe::packer::extract_pack_metadata_from_packed(&pe).unwrap();
    assert_eq!(meta.dispatch_mode, DispatchMode::Threaded);

    let bytecode = knvest::extract_bytecode(&pe).unwrap();
    let layout = knvest::extract_layout_plan(&pe).unwrap();
    let block_plan = knvest::extract_block_map_plan(&pe).ok();
    let instructions = knvest::disassemble_with_layout(
        &bytecode,
        &meta.opcode_map,
        block_plan.as_ref(),
        DispatchMode::Threaded,
        &layout,
    );
    assert!(!instructions.is_empty());

    fs::remove_dir_all(&test_dir).ok();
}

#[test]
fn test_advancement_plan_remaining_items_end_to_end() {
    use knvest::pe::lifter::{
        alloc_stack_spill_reg_seeded, disassemble_x64_simple, emit_sign_extend_bits,
        emit_u32_zext, lift_to_vm_bytecode, validate_strict_lift, X64InstrKind, X64Instruction,
    };
    use knvest::pe::mba::{
        clear_mba_context, emit_load_imm_unfolded, emit_opaque_branch_guard,
        emit_opaque_zero_perturbation, set_mba_context,
    };
    use knvest::pe::vm_stub::{
        create_vm_interpreter_stub, create_vm_interpreter_stub_with_exit_mode, StubExitMode,
    };
    use knvest::vm::{BytecodeCipher, VirtualMachine};
    use knvest::{OpCode, OpcodeMap};

    // 1. Section 2.5: Opaque predicates & zero perturbation preserve VM semantics
    let mut bc_opaque = Vec::new();
    bc_opaque.push(OpCode::LoadImm as u8);
    bc_opaque.push(0);
    bc_opaque.extend_from_slice(&12345u64.to_le_bytes());
    emit_opaque_branch_guard(&mut bc_opaque, 0xCAFE_BABE_1234_5678, 1);
    emit_opaque_zero_perturbation(&mut bc_opaque, 0, 0xCAFE_BABE_1234_5678, 2);
    bc_opaque.push(OpCode::Exit as u8);
    bc_opaque.push(0);
    let mut vm_opaque = VirtualMachine::new(bc_opaque);
    vm_opaque.run().unwrap();
    assert_eq!(vm_opaque.get_register(0).unwrap(), 12345);

    // 2. Section 3 Phase 1 & 4.2.2: movzx / movsx / movsxd / emit_u32_zext
    // movzx eax, bl (0F B6 C3); movsx ecx, bl (0F BE CB); movsxd rdx, ecx (48 63 D1); ret (C3)
    let raw_ext = [
        0x48, 0xC7, 0xC3, 0x80, 0x00, 0x00, 0x00, // mov rbx, 0x80
        0x0F, 0xB6, 0xC3,                         // movzx eax, bl -> 0x80
        0x0F, 0xBE, 0xCB,                         // movsx ecx, bl -> 0xFFFFFFFFFFFFFF80
        0x48, 0x63, 0xD1,                         // movsxd rdx, ecx -> copy r1 to r2
        0xC3,
    ];
    let dec_ext = disassemble_x64_simple(&raw_ext, 16);
    assert!(dec_ext.iter().any(|i| matches!(i.kind, X64InstrKind::MovzxReg { bits: 8, .. })));
    assert!(dec_ext.iter().any(|i| matches!(i.kind, X64InstrKind::MovsxReg { bits: 8, .. })));
    assert!(dec_ext.iter().any(|i| matches!(i.kind, X64InstrKind::Movsxd { .. })));
    let mut bc_ext = lift_to_vm_bytecode(&dec_ext, 0x1000);
    // Replace trailing Ret with Exit(0) so VM halts cleanly at top level
    if let Some(last) = bc_ext.last_mut() {
        if *last == OpCode::Ret as u8 {
            *last = OpCode::Exit as u8;
            bc_ext.push(0);
        }
    }
    let mut vm_ext = VirtualMachine::new(bc_ext);
    vm_ext.run().unwrap();
    assert_eq!(vm_ext.get_register(0).unwrap(), 0x80);
    assert_eq!(vm_ext.get_register(1).unwrap(), 0xFFFF_FFFF_FFFF_FF80);
    assert_eq!(vm_ext.get_register(2).unwrap(), 0xFFFF_FFFF_FFFF_FF80);

    // Check emit_u32_zext and emit_sign_extend_bits directly
    let mut bc_zext = Vec::new();
    bc_zext.push(OpCode::LoadImm as u8);
    bc_zext.push(0);
    bc_zext.extend_from_slice(&0xDEAD_BEEF_1122_3344u64.to_le_bytes());
    emit_u32_zext(&mut bc_zext, 0);
    emit_sign_extend_bits(&mut bc_zext, 1, 0, 16, 0x1234);
    bc_zext.push(OpCode::Exit as u8);
    bc_zext.push(0);
    let mut vm_zext = VirtualMachine::new(bc_zext);
    vm_zext.run().unwrap();
    assert_eq!(vm_zext.get_register(0).unwrap(), 0x1122_3344);
    assert_eq!(vm_zext.get_register(1).unwrap(), 0x3344);

    // 3. Section 2.2 & 3 Phase 2: LoadImm and Cmp handler variants in OpcodeMap
    let mut load_imm_variants = std::collections::HashSet::new();
    let mut cmp_variants = std::collections::HashSet::new();
    for s in 1..64u64 {
        let m = OpcodeMap::from_seed(s.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        load_imm_variants.insert(m.handler_variant(OpCode::LoadImm));
        cmp_variants.insert(m.handler_variant(OpCode::Cmp));
    }
    assert!(load_imm_variants.len() >= 2, "LoadImm must have multiple handler variants");
    assert!(cmp_variants.len() >= 2, "Cmp must have multiple handler variants");

    // 4. Section 3 Phase 3: Automatic LoadImm unfolding under --mba 2
    set_mba_context(2, 0x7777_8888);
    let mut bc_mba2 = lift_to_vm_bytecode(&dec_ext[..1], 0x1000);
    clear_mba_context();
    bc_mba2.push(OpCode::Exit as u8);
    bc_mba2.push(0);
    assert!(bc_mba2.len() > 12, "--mba 2 must unfold MovRegImm into multi-instruction sequence");
    let mut vm_mba2 = VirtualMachine::new(bc_mba2);
    vm_mba2.run().unwrap();
    assert_eq!(vm_mba2.get_register(3).unwrap(), 0x80);

    // Also verify emit_load_imm_unfolded directly
    let mut bc_unfold = Vec::new();
    emit_load_imm_unfolded(&mut bc_unfold, 2, 0x1234_5678_9ABC_DEF0, 0x42);
    bc_unfold.push(OpCode::Exit as u8);
    bc_unfold.push(2);
    let mut vm_unfold = VirtualMachine::new(bc_unfold);
    vm_unfold.run().unwrap();
    assert_eq!(vm_unfold.get_register(2).unwrap(), 0x1234_5678_9ABC_DEF0);

    // 5. Section 4.1 & 4.3: vm_stub immediate stack API string wipe + 5th/6th stack args + ReturnToCaller
    let (stub_ret, _, _, _) = create_vm_interpreter_stub_with_exit_mode(
        0,
        0,
        &OpcodeMap::from_seed(0x42),
        DispatchMode::Table,
        0,
        knvest::IsaMode::Reg,
        &knvest::BytecodeLayout::identity(),
        &[],
        &knvest::BlockMapPlan::default(),
        &[],
        &[],
        &knvest::NestedVmPlan::disabled(),
        StubExitMode::ReturnToCaller,
    );
    // Wipe pattern: mov [rbp-0x560], rax (48 89 85 A0 FA FF FF)
    let wipe_pattern = [0x48u8, 0x89, 0x85, 0xA0, 0xFA, 0xFF, 0xFF];
    assert!(
        stub_ret.windows(wipe_pattern.len()).filter(|w| *w == wipe_pattern).count() >= 3,
        "vm_stub must wipe decoded stack API string buffer after each GetProcAddress call"
    );
    // 5th/6th stack arg marshaling in nc_iat_call: mov [rsp+0x20], rax (48 89 44 24 20) and mov [rsp+0x28], rax (48 89 44 24 28)
    assert!(stub_ret.windows(5).any(|w| w == [0x48, 0x89, 0x44, 0x24, 0x20]));
    assert!(stub_ret.windows(5).any(|w| w == [0x48, 0x89, 0x44, 0x24, 0x28]));
    // ReturnToCaller saves/restores caller [rbp+0] and [rbp+8] into [rbp-0x518] and [rbp-0x520]
    assert!(stub_ret.windows(7).any(|w| w == [0x48, 0x89, 0x85, 0xE8, 0xFA, 0xFF, 0xFF]));
    assert!(stub_ret.windows(7).any(|w| w == [0x48, 0x8B, 0x85, 0xE8, 0xFA, 0xFF, 0xFF]));

    // 6. Section 4.2.3 & 4.3: --strict and --return-mode via pack_executable_with_full_options
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_output_full_options");
    fs::create_dir_all(&test_dir).unwrap();
    let input_exe = test_dir.join("in.exe");
    let output_exe = test_dir.join("out.exe");
    let sidecar_file = test_dir.join("custom.knvmap");
    fs::write(&input_exe, knvest::test_pe::create_minimal_pe64()).unwrap();
    knvest::pack_executable_with_full_options(
        &input_exe,
        &output_exe,
        None,
        Some(0x1357_2468),
        false,
        DispatchMode::Table,
        2,
        knvest::IsaMode::Reg,
        false,
        true,
        Some(&sidecar_file),
        true,
        true,
    )
    .expect("packing with strict=true, return_mode=true, strip_meta=true, sidecar should succeed");
    assert!(sidecar_file.exists(), "custom sidecar file must be emitted");
    let loaded_sc = knvest::pe::packer::SidecarMap::load_from_path(&sidecar_file).unwrap();
    let packed_pe = knvest::PEFile::from_file(&output_exe).unwrap();
    let extracted_bc =
        knvest::pe::packer::extract_bytecode_from_packed_with_sidecar(&packed_pe, Some(&loaded_sc))
            .unwrap();
    assert!(!extracted_bc.is_empty());
    fs::remove_dir_all(&test_dir).ok();

    // Also verify validate_strict_lift rejects Unknown when not in a native BB
    let unknown_instrs = vec![X64Instruction {
        offset: 0x1000,
        bytes: vec![0x0F, 0x0B], // ud2
        kind: X64InstrKind::Unknown,
    }];
    assert!(validate_strict_lift(&unknown_instrs, 0x1000, None).is_err());

    // 8. Section 4.4: BytecodeCipher end-to-end with VirtualMachine::with_cipher_decrypted & alloc_stack_spill_reg_seeded
    let cipher = BytecodeCipher::from_seed(0x9988_7766);
    let map_cipher = OpcodeMap::from_seed(0x9988_7766);
    let mut raw_bc = Vec::new();
    raw_bc.push(map_cipher.encode(OpCode::LoadImm));
    raw_bc.push(cipher.map_reg(16));
    raw_bc.extend_from_slice(&999u64.to_le_bytes());
    raw_bc.push(map_cipher.encode(OpCode::Exit));
    raw_bc.push(0);
    let enc_bc = cipher.encrypt(&raw_bc);
    let mut vm_cipher = VirtualMachine::with_cipher_decrypted(
        &enc_bc,
        &cipher,
        map_cipher,
    );
    vm_cipher.run().unwrap();
    assert_eq!(vm_cipher.get_logical_register(16, &cipher).unwrap(), 999);

    let mut next_spill = 16u8;
    let seeded_reg = alloc_stack_spill_reg_seeded(&mut next_spill, 0x9988_7766);
    assert!((16..32).contains(&seeded_reg));
    let _ = create_vm_interpreter_stub;
}
