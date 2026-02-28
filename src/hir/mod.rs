pub mod analysis;
pub mod codec;
pub mod lower;
pub mod types;

pub const HIR_VERSION: u32 = 1;
pub const MIR_VERSION: u32 = 0;

pub use codec::{decode, encode, DecodeError, HIR_MAGIC};
pub use lower::{hir_node_count, lower_to_hir};
pub use types::*;
