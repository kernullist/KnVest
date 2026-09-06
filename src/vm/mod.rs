pub mod opcode;
pub mod opcode_map;
pub mod machine;
pub mod dispatch;

pub use opcode::OpCode;
pub use dispatch::{DispatchMode, THREAD_TARGET_SIZE};
pub use opcode_map::{
    OpcodeMap, PackMetadata, active_decode, active_encode, clear_active_map, random_seed,
    set_active_map, ADD_HANDLER_VARIANT_COUNT, CANONICAL_OPCODES, KNV4_HEADER_SIZE, KNV4_MAGIC,
};
pub use machine::{VirtualMachine, VMError, VMResult};
