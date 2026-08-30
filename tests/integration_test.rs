use std::fs;
use std::path::PathBuf;

#[test]
fn test_pack_and_ir_workflow() {
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_output");
    fs::create_dir_all(&test_dir).unwrap();

    let minimal_pe = knvest::test_pe::create_minimal_pe64();
    let input_path = test_dir.join("test_input.exe");
    fs::write(&input_path, &minimal_pe).unwrap();

    let output_path = test_dir.join("test_output.exe");
    
    let result = knvest::pack_executable(&input_path, &output_path, None);
    assert!(result.is_ok(), "Packing should succeed");

    assert!(output_path.exists(), "Packed file should exist");

    let packed_pe = knvest::PEFile::from_file(&output_path);
    assert!(packed_pe.is_ok(), "Packed file should be valid PE");

    let bytecode_result = knvest::extract_bytecode(&packed_pe.unwrap());
    assert!(bytecode_result.is_ok(), "Should extract bytecode");

    let bytecode = bytecode_result.unwrap();
    assert!(!bytecode.is_empty(), "Bytecode should not be empty");

    let instructions = knvest::disassemble(&bytecode);
    assert!(!instructions.is_empty(), "Should have instructions");

    fs::remove_dir_all(&test_dir).ok();
}

#[test]
fn test_ir_display() {
    let mut bytecode = vec![knvest::OpCode::LoadImm as u8, 0];
    bytecode.extend_from_slice(&42u64.to_le_bytes());
    bytecode.push(knvest::OpCode::Exit as u8);
    bytecode.push(0);

    let instructions = knvest::disassemble(&bytecode);
    let output = knvest::pretty_print(&instructions);
    
    assert!(output.contains("load_imm"), "Output should contain load_imm");
    assert!(output.contains("exit"), "Output should contain exit");
    assert!(output.contains("0x2a"), "Output should contain hex value 42");
}
