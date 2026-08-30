pub mod opcode;
pub mod machine;

pub use opcode::OpCode;
pub use machine::{VirtualMachine, VMError, VMResult};
