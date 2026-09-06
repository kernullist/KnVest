use std::fs;
use std::path::PathBuf;
use knvest::OpcodeMap;

#[test]
fn test_pack_and_ir_workflow() {
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_output");
    fs::create_dir_all(&test_dir).unwrap();

    let minimal_pe = knvest::test_pe::create_minimal_pe64();
    let input_path = test_dir.join("test_input.exe");
    fs::write(&input_path, &minimal_pe).unwrap();

    let output_path = test_dir.join("test_output.exe");
    
    let result = knvest::pack_executable(&input_path, &output_path, None, Some(0x1234), false);
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

    let instructions = knvest::disassemble(&bytecode, &opcode_map);
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

    let instructions = knvest::disassemble(&bytecode, &map);
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
    let packed_a = knvest::pe::packer::pack_function(&mut pe_a, None, Some(1), false).unwrap();
    let packed_b = knvest::pe::packer::pack_function(&mut pe_b, None, Some(2), false).unwrap();
    assert_ne!(packed_a.bytecode, packed_b.bytecode);
    let ir_a = knvest::pretty_print(&knvest::disassemble(&packed_a.bytecode, &packed_a.opcode_map));
    let ir_b = knvest::pretty_print(&knvest::disassemble(&packed_b.bytecode, &packed_b.opcode_map));
    assert!(ir_a.contains("load_imm"));
    assert!(ir_b.contains("load_imm"));
}
