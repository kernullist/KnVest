pub mod block_map;
pub mod layout;
pub mod opcode;
pub mod opcode_map;
pub mod machine;
pub mod dispatch;
pub mod virt_isa;
pub mod isa_mode;
pub mod nested_vm;
pub mod l8;
pub mod l9;
pub mod l10;
pub mod l11;
pub mod l12;
pub mod l13;

pub use opcode::OpCode;
pub use l8::{
    encode_direct_call, encode_jmp_reg, encode_xmm, format_native_micro, rolling_wire_key32,
    rolling_wire_mask, NATIVE_CALL_DIRECT_BASE, NATIVE_CALL_JMP_REG_BASE, NATIVE_CALL_XMM_BASE,
};
pub use l9::{decode_madd, encode_madd, fuse_madd, reg_slot_key, NATIVE_CALL_MADD_BASE};
pub use l10::{apply_imm_cipher, imm_cipher_key64, imm_cipher_mask};
pub use l11::{apply_reg_index_mask, reg_index_key32, reg_index_mask};
pub use l12::{call_slot_key64, call_slot_mask};
pub use l13::{data_slot_key64, data_slot_mask};
pub use dispatch::{DispatchMode, THREAD_TARGET_SIZE};
pub use block_map::{
    BlockMapEntry, BlockMapPlan, ENTRY_PRED_BB, HandlerRedirectPlan, KNV6_MAGIC, META_OPERAND_LEN,
    META_WIRE_BYTE,
    collect_handler_redirect_plan, emit_block_map_refresh, meta_instruction_len,
};
pub use opcode_map::{
    OpcodeMap, PackMetadata, active_decode, active_encode, active_opcode_map_or, clear_active_map,
    random_seed, set_active_map, ADD_HANDLER_VARIANT_COUNT, AND_HANDLER_VARIANT_COUNT,
    SUB_HANDLER_VARIANT_COUNT, XOR_HANDLER_VARIANT_COUNT, CANONICAL_OPCODES, KNV4_HEADER_SIZE,
    KNV4_MAGIC,
};
pub use virt_isa::{
    format_ir_header as virt_isa_ir_header, emit_sub_reg_reg, seed_for_handler_variant,
    seed_for_sub_split, sub_lift_split_enabled, VIRT_ISA_SPLIT_TEMP,
};
pub use isa_mode::{
    clear_isa_mode, current_isa_mode, format_ir_header as isa_ir_header, is_stack_alu_op,
    operand_len_for, set_isa_mode, IsaMode,
};
pub use layout::{BytecodeCipher, BytecodeLayout, KNV7_MAGIC, KNV7_HEADER_SIZE};
pub use nested_vm::{NestedVmPlan, OUTER_DECODE_TABLE_SIZE, collect_outer_maps};
pub use machine::{VirtualMachine, VMError, VMResult};
