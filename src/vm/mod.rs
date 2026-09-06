pub mod opcode;
pub mod opcode_map;
pub mod machine;

pub use opcode::OpCode;
pub use opcode_map::{
    OpcodeMap, active_decode, active_encode, clear_active_map, random_seed, set_active_map,
    CANONICAL_OPCODES, KNV4_HEADER_SIZE, KNV4_MAGIC,
};
pub use machine::{VirtualMachine, VMError, VMResult};
