use super::cfg::{build_basic_blocks_with_image, resolve_switches};
use super::lifter::{
    disassemble_x64_simple, lift_to_vm_bytecode, X64InstrKind, X64Instruction, X64Reg,
};
use super::packer::{
    extract_bytecode_from_packed, extract_pack_metadata_from_packed, pack_functions_l8,
    scrub_embedded_metadata_in_pe,
};
use super::test_pe;
use super::vm_stub::{create_vm_interpreter_stub_l8, StubExitMode};
use super::PEFile;
use crate::ir::Instruction;
use crate::vm::l8::{
    apply_rolling_wire_mask, encode_direct_call, encode_jmp_reg, encode_xmm, XMM_ADDSD, XMM_UCOMISD,
};
use crate::vm::{
    BlockMapPlan, BytecodeLayout, DispatchMode, IsaMode, NestedVmPlan, OpCode, OpcodeMap,
    VirtualMachine,
};

fn insn(offset: usize, len: usize, kind: X64InstrKind) -> X64Instruction {
    X64Instruction {
        offset,
        bytes: vec![0x90; len],
        kind,
    }
}

#[test]
fn l8_rolling_pack_is_idempotent_and_vm_executes_ciphertext() {
    let seed = 0x4C38_0001u64;
    let mut plain_pe = PEFile::from_bytes(test_pe::create_minimal_pe64()).unwrap();
    let plain = pack_functions_l8(
        &mut plain_pe,
        &[],
        Some(seed),
        false,
        DispatchMode::Table,
        0,
        IsaMode::Reg,
        false,
        false,
        false,
        false,
    )
    .unwrap();
    let mut roll_pe = PEFile::from_bytes(test_pe::create_minimal_pe64()).unwrap();
    let rolled = pack_functions_l8(
        &mut roll_pe,
        &[],
        Some(seed),
        false,
        DispatchMode::Table,
        0,
        IsaMode::Reg,
        false,
        false,
        false,
        true,
    )
    .unwrap();
    assert!(rolled.rolling_cipher);
    assert_ne!(plain.bytecode, rolled.bytecode);
    let meta = extract_pack_metadata_from_packed(&roll_pe).unwrap();
    assert!(meta.rolling_cipher);
    assert_eq!(meta.seed(), seed);

    let starts = crate::vm::layout::enumerate_raw_instructions_masked(
        &rolled.bytecode,
        &rolled.opcode_map,
        &rolled.block_map_plan,
        &rolled.layout_plan,
        rolled.dispatch_mode,
        IsaMode::Reg,
        Some(seed),
    )
    .into_iter()
    .map(|insn| insn.start)
    .collect::<Vec<_>>();
    let mut decoded = rolled.bytecode.clone();
    apply_rolling_wire_mask(&mut decoded, seed, &starts);
    assert_eq!(decoded, plain.bytecode);

    let extracted = extract_bytecode_from_packed(&roll_pe).unwrap();
    assert!(!extracted.is_empty());
    assert_eq!(extracted[0], rolled.bytecode[0]);
    let sidecar = super::packer::SidecarMap::from_packed_pe(&roll_pe).unwrap();
    assert!(sidecar.pack_meta.rolling_cipher);
    assert!(sidecar.bytecode_len as usize >= rolled.bytecode.len());

    let ir = Instruction::disassemble_with_rolling(
        &rolled.bytecode,
        &rolled.opcode_map,
        Some(&rolled.block_map_plan),
        rolled.dispatch_mode,
        &rolled.layout_plan,
        IsaMode::Reg,
        true,
        seed,
    );
    let text = Instruction::pretty_print(&ir);
    assert!(
        ir.len() > 2,
        "rolling IR should decode the lifted function:\n{text}"
    );
    assert!(!text.contains("unknown") || ir.iter().any(|i| i.opcode == OpCode::Exit));
}

#[test]
fn l8_vm_fetch_decrypts_loadimm_and_runs_xmm_jmp_direct() {
    let seed = 0x0BAD_F00Du64;
    let map = OpcodeMap::from_seed(seed);
    let mut bc = vec![map.encode(OpCode::LoadImm), 0];
    bc.extend_from_slice(&42u64.to_le_bytes());
    let exit_at = bc.len();
    bc.push(map.encode(OpCode::Exit));
    bc.push(0);
    apply_rolling_wire_mask(&mut bc, seed, &[0, exit_at]);
    let mut vm = VirtualMachine::with_opcode_map(bc, map).with_rolling_cipher(seed);
    vm.run().unwrap();
    assert_eq!(vm.get_register(0).unwrap(), 42);

    let mut xmm_bc = vec![encode_xmm(XMM_ADDSD, 0, 1)];
    // NativeCall wire + imm
    let mut program = vec![OpCode::NativeCall as u8];
    program.extend_from_slice(&xmm_bc[0].to_le_bytes());
    let _ = xmm_bc;
    program.push(OpCode::Exit as u8);
    program.push(0);
    let mut vm = VirtualMachine::new(program);
    vm.set_xmm(0, 1.5f64.to_bits()).unwrap();
    vm.set_xmm(1, 2.5f64.to_bits()).unwrap();
    vm.run().unwrap();
    assert_eq!(f64::from_bits(vm.get_xmm(0).unwrap()), 4.0);

    let mut cmp = vec![OpCode::NativeCall as u8];
    cmp.extend_from_slice(&encode_xmm(XMM_UCOMISD, 0, 1).to_le_bytes());
    cmp.push(OpCode::JmpIf as u8);
    cmp.push(9); // JB: CF=1
    let patch = cmp.len();
    cmp.extend_from_slice(&0u64.to_le_bytes());
    cmp.push(OpCode::LoadImm as u8);
    cmp.push(0);
    cmp.extend_from_slice(&0u64.to_le_bytes());
    cmp.extend_from_slice(&[OpCode::Exit as u8, 0]);
    let taken = cmp.len() as u64;
    cmp[patch..patch + 8].copy_from_slice(&taken.to_le_bytes());
    cmp.push(OpCode::LoadImm as u8);
    cmp.push(0);
    cmp.extend_from_slice(&1u64.to_le_bytes());
    cmp.extend_from_slice(&[OpCode::Exit as u8, 0]);
    let mut vm = VirtualMachine::new(cmp);
    vm.set_xmm(0, 1.0f64.to_bits()).unwrap();
    vm.set_xmm(1, 2.0f64.to_bits()).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.get_register(0).unwrap(), 1, "ucomisd dest < src sets CF");

    let mut jump = vec![OpCode::LoadImm as u8, 0];
    jump.extend_from_slice(&0u64.to_le_bytes());
    jump.push(OpCode::NativeCall as u8);
    jump.extend_from_slice(&encode_jmp_reg(0).to_le_bytes());
    jump.push(OpCode::LoadImm as u8);
    jump.push(1);
    jump.extend_from_slice(&1u64.to_le_bytes());
    jump.extend_from_slice(&[OpCode::Exit as u8, 1]);
    let target = jump.len() as u64;
    jump[2..10].copy_from_slice(&target.to_le_bytes());
    jump.push(OpCode::LoadImm as u8);
    jump.push(1);
    jump.extend_from_slice(&9u64.to_le_bytes());
    jump.extend_from_slice(&[OpCode::Exit as u8, 1]);
    let mut vm = VirtualMachine::new(jump);
    vm.run().unwrap();
    assert_eq!(vm.get_register(1).unwrap(), 9);

    let mut call = vec![OpCode::NativeCall as u8];
    call.extend_from_slice(&encode_direct_call(0x1400).to_le_bytes());
    call.extend_from_slice(&[OpCode::Exit as u8, 0]);
    let mut vm = VirtualMachine::new(call);
    vm.run().unwrap();
    assert_eq!(vm.direct_calls, vec![0x1400]);
    assert_eq!(vm.get_register(0).unwrap(), 0);
}

#[test]
fn l8_stub_emits_rolling_decrypt_and_sse_opcodes() {
    let map = OpcodeMap::from_seed(1);
    let (rolling, _, _, _) = create_vm_interpreter_stub_l8(
        0,
        0,
        &map,
        DispatchMode::Table,
        0,
        IsaMode::Reg,
        &BytecodeLayout::identity(),
        &[],
        &BlockMapPlan::default(),
        &[],
        &[],
        &NestedVmPlan::disabled(),
        StubExitMode::ExitProcess,
        true,
    );
    let (plain, _, _, _) = create_vm_interpreter_stub_l8(
        0,
        0,
        &map,
        DispatchMode::Table,
        0,
        IsaMode::Reg,
        &BytecodeLayout::identity(),
        &[],
        &BlockMapPlan::default(),
        &[],
        &[],
        &NestedVmPlan::disabled(),
        StubExitMode::ExitProcess,
        false,
    );
    // imul ecx, ecx, 0x9E3779B9
    let key = [0x69u8, 0xC9, 0xB9, 0x79, 0x37, 0x9E];
    assert!(rolling.windows(key.len()).any(|w| w == key));
    assert!(!plain.windows(key.len()).any(|w| w == key));
    assert!(
        plain.windows(4).any(|w| w == [0xF2, 0x0F, 0x58, 0xC8]),
        "addsd"
    );
    assert!(
        plain
            .windows(5)
            .any(|w| w == [0xF2, 0x48, 0x0F, 0x2A, 0xC8]),
        "cvtsi2sd"
    );
    assert!(
        plain
            .windows(5)
            .any(|w| w == [0xF2, 0x48, 0x0F, 0x2C, 0xC0]),
        "cvttsd2si"
    );
    assert!(
        plain.windows(4).any(|w| w == [0xF3, 0x0F, 0x7E, 0xC8]),
        "movq"
    );
    assert!(
        plain.windows(4).any(|w| w == [0x66, 0x0F, 0x6E, 0xC8]),
        "movd"
    );
    assert!(plain.windows(3).any(|w| w == [0x0F, 0x2F, 0xC8]), "comiss");
    assert!(
        plain.windows(4).any(|w| w == [0x66, 0x0F, 0x2F, 0xC8]),
        "comisd"
    );
    assert!(
        plain
            .windows(5)
            .any(|w| w == [0xF3, 0x48, 0x0F, 0x2A, 0xC8]),
        "cvtsi2ss"
    );
    assert!(
        plain
            .windows(5)
            .any(|w| w == [0xF3, 0x48, 0x0F, 0x2C, 0xC0]),
        "cvttss2si"
    );
    assert!(
        plain.windows(4).any(|w| w == [0xF3, 0x0F, 0x5A, 0xC8]),
        "cvtss2sd"
    );
    assert!(
        plain.windows(4).any(|w| w == [0xF2, 0x0F, 0x5A, 0xC8]),
        "cvtsd2ss"
    );
}

#[test]
fn l8_lifter_jmp_reg_and_sse_and_switch_cfg() {
    let jmp = disassemble_x64_simple(&[0xFF, 0xE0], 2);
    assert!(matches!(
        jmp[0].kind,
        X64InstrKind::JmpReg { reg: X64Reg::Rax }
    ));
    let lifted = lift_to_vm_bytecode(&jmp, 0);
    let id = encode_jmp_reg(0);
    assert!(
        lifted.windows(8).any(|w| w == id.to_le_bytes()),
        "jmp rax should lift to native_call jmp_reg"
    );

    let addsd = disassemble_x64_simple(&[0xF2, 0x0F, 0x58, 0xC1], 2);
    assert!(matches!(addsd[0].kind, X64InstrKind::Xmm { .. }));
    let lifted = lift_to_vm_bytecode(&addsd, 0);
    let id = encode_xmm(XMM_ADDSD, 0, 1);
    assert!(lifted.windows(8).any(|w| w == id.to_le_bytes()));

    let cvt = disassemble_x64_simple(&[0xF2, 0x48, 0x0F, 0x2A, 0xC0], 2);
    assert!(matches!(cvt[0].kind, X64InstrKind::Xmm { .. }));
    let ucomi = disassemble_x64_simple(&[0x0F, 0x2E, 0xC1], 2);
    assert!(matches!(ucomi[0].kind, X64InstrKind::Xmm { .. }));

    let samples: &[(&[u8], u8, u8, u8)] = &[
        (&[0xF3, 0x0F, 0x7E, 0xC1], crate::vm::l8::XMM_MOVQ_XX, 0, 1),
        (&[0x66, 0x0F, 0x6E, 0xC0], crate::vm::l8::XMM_MOVD_XM, 0, 0),
        (&[0x0F, 0x2F, 0xC1], crate::vm::l8::XMM_COMISS, 0, 1),
        (&[0x66, 0x0F, 0x2F, 0xC1], crate::vm::l8::XMM_COMISD, 0, 1),
        (
            &[0xF3, 0x48, 0x0F, 0x2A, 0xC0],
            crate::vm::l8::XMM_CVTSI2SS,
            0,
            0,
        ),
        (
            &[0xF3, 0x48, 0x0F, 0x2C, 0xC0],
            crate::vm::l8::XMM_CVTTSS2SI,
            0,
            0,
        ),
        (&[0xF3, 0x0F, 0x5A, 0xC1], crate::vm::l8::XMM_CVTSS2SD, 0, 1),
        (&[0xF2, 0x0F, 0x5A, 0xC1], crate::vm::l8::XMM_CVTSD2SS, 0, 1),
    ];
    for (bytes, subop, dst, src) in samples {
        let decoded = disassemble_x64_simple(bytes, 2);
        assert!(
            matches!(decoded[0].kind, X64InstrKind::Xmm { .. }),
            "classify {:?}",
            decoded[0].kind
        );
        let lifted = lift_to_vm_bytecode(&decoded, 0);
        let id = encode_xmm(*subop, *dst, *src);
        assert!(
            lifted.windows(8).any(|w| w == id.to_le_bytes()),
            "lift {bytes:02x?} missing {id:#x}"
        );
    }

    let instrs = vec![
        insn(0, 2, X64InstrKind::Ja { target_offset: 100 }),
        insn(
            2,
            3,
            X64InstrKind::CmpRegImm {
                reg: X64Reg::Rcx,
                imm: 1,
            },
        ),
        insn(
            6,
            7,
            X64InstrKind::LeaRipRel {
                dst: X64Reg::Rax,
                offset: 15,
            },
        ),
        insn(
            13,
            4,
            X64InstrKind::MovRegScaledMem {
                dst: X64Reg::Rdx,
                base: Some(X64Reg::Rax),
                index: X64Reg::Rcx,
                scale: 4,
                disp: 0,
                sign_extend32: true,
                width: 32,
                high_byte: false,
            },
        ),
        insn(
            17,
            3,
            X64InstrKind::AddRegReg {
                dst: X64Reg::Rdx,
                src: X64Reg::Rax,
            },
        ),
        insn(20, 2, X64InstrKind::JmpReg { reg: X64Reg::Rdx }),
        insn(32, 1, X64InstrKind::Nop),
        insn(36, 1, X64InstrKind::Nop),
    ];
    let mut image = vec![0u8; 40];
    image[28..32].copy_from_slice(&4i32.to_le_bytes());
    image[32..36].copy_from_slice(&8i32.to_le_bytes());
    let switches = resolve_switches(&instrs, &image);
    assert_eq!(switches.len(), 1);
    assert_eq!(switches[0].case_targets, vec![32, 36]);
    assert_eq!(switches[0].default_target, Some(102));
    let blocks = build_basic_blocks_with_image(&instrs, 0, Some(&image));
    assert!(blocks.iter().any(|b| b.start == 32));
    assert!(blocks.iter().any(|b| b.start == 36));
}

#[test]
fn l8_multi_rva_installs_trampolines_and_return_to_caller() {
    let mut single = PEFile::from_bytes(test_pe::create_minimal_pe64()).unwrap();
    let one = pack_functions_l8(
        &mut single,
        &[0x1000],
        Some(0x4C38_0002),
        false,
        DispatchMode::Table,
        0,
        IsaMode::Reg,
        false,
        false,
        false,
        false,
    )
    .unwrap();
    assert!(one.function_entries.is_empty());
    assert_eq!(
        single.data[0x400], 0x55,
        "a single RVA must not patch a trampoline"
    );

    let mut bytes = test_pe::create_minimal_pe64();
    let second = [
        0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83,
        0xC4, 0x20, 0x5D, 0xC3,
    ];
    bytes[0x430..0x430 + second.len()].copy_from_slice(&second);
    let mut pe = PEFile::from_bytes(bytes).unwrap();
    let packed = pack_functions_l8(
        &mut pe,
        &[0x1000, 0x1030],
        Some(0x4C38_0003),
        false,
        DispatchMode::Table,
        0,
        IsaMode::Reg,
        false,
        false,
        false,
        false,
    )
    .unwrap();
    assert_eq!(packed.function_entries.len(), 2);
    assert!(!packed.function_entries[0].return_to_caller);
    assert!(packed.function_entries[1].return_to_caller);
    assert_eq!(packed.function_entries[0].bytecode_entry, 0);
    assert_eq!(packed.function_entries[1].bytecode_entry, 0);
    assert_eq!(pe.data[0x400], 0xE9);
    assert_eq!(pe.data[0x430], 0xE9);
    let section = pe.get_section(".knvest").unwrap();
    let start = section.pointer_to_raw_data as usize;
    let end = start + section.size_of_raw_data as usize;
    let blob = &pe.data[start..end];
    assert_eq!(blob.windows(4).filter(|w| *w == b"VMBC").count(), 2);
    let ret_seq = [0x0Fu8, 0xB6, 0x0E, 0x48, 0x8B, 0x44, 0xCD, 0x80, 0xC9, 0xC3];
    assert!(blob.windows(ret_seq.len()).any(|w| w == ret_seq));

    scrub_embedded_metadata_in_pe(&mut pe, packed.seed).unwrap();
    let section = pe.get_section(".knvest").unwrap();
    let start = section.pointer_to_raw_data as usize;
    let end = start + section.size_of_raw_data as usize;
    let blob = &pe.data[start..end];
    assert_eq!(
        blob.windows(4).filter(|w| *w == b"VMBC").count(),
        0,
        "strip-meta must scrub every VMBC marker in a multi-RVA image"
    );
}
