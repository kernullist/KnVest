pub mod block_map;
pub mod layout;
pub mod opcode;
pub mod opcode_map;
pub mod machine;
pub mod dispatch;
pub mod virt_isa;

pub use opcode::OpCode;
pub use dispatch::{DispatchMode, THREAD_TARGET_SIZE};
pub use block_map::{
    BlockMapEntry, BlockMapPlan, ENTRY_PRED_BB, HandlerRedirectPlan, KNV6_MAGIC, META_OPERAND_LEN,
    META_WIRE_BYTE,
    collect_handler_redirect_plan, emit_block_map_refresh, meta_instruction_len,
};
pub use opcode_map::{
    OpcodeMap, PackMetadata, active_decode, active_encode, clear_active_map, random_seed,
    set_active_map, ADD_HANDLER_VARIANT_COUNT, AND_HANDLER_VARIANT_COUNT,
    SUB_HANDLER_VARIANT_COUNT, XOR_HANDLER_VARIANT_COUNT, CANONICAL_OPCODES, KNV4_HEADER_SIZE,
    KNV4_MAGIC,
};
pub use virt_isa::{
    format_ir_header as virt_isa_ir_header, emit_sub_reg_reg, seed_for_handler_variant,
    seed_for_sub_split, sub_lift_split_enabled, VIRT_ISA_SPLIT_TEMP,
};
pub use layout::{BytecodeLayout, KNV7_MAGIC, KNV7_HEADER_SIZE};
pub use machine::{VirtualMachine, VMError, VMResult};
