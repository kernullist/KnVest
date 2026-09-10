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
    
    let result = knvest::pack_executable(&input_path, &output_path, None, Some(0x1234), false, DispatchMode::Table, 0);
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
    let packed_a = knvest::pe::packer::pack_function(&mut pe_a, None, Some(1), false, DispatchMode::Table, 0).unwrap();
    let packed_b = knvest::pe::packer::pack_function(&mut pe_b, None, Some(2), false, DispatchMode::Table, 0).unwrap();
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
    )
    .unwrap();
    let packed_b = knvest::pe::packer::pack_function(
        &mut pe_b,
        None,
        Some(0x2222_2222),
        false,
        DispatchMode::Table,
        0,
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
