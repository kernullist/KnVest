pub mod parser;
pub mod packer;
pub mod test_pe;
pub mod lifter;
pub mod vm_stub;
pub mod imports;
pub mod cfg;
pub mod thunk;
pub mod partial;
pub mod threaded;
pub mod layout_pass;
pub mod mba;

pub use parser::{PEFile, PEError};
pub use packer::{
    pack_function, scrub_embedded_metadata_in_pe, extract_bytecode_from_packed_with_sidecar,
    SidecarMap, KNVM_MAGIC,
};
pub use vm_stub::{StubExitMode, create_vm_interpreter_stub_with_exit_mode};
pub use lifter::{LiftPolicy, validate_strict_lift};
