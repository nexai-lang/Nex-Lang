pub mod analysis;
pub mod codec;
pub mod lower;
pub mod types;

pub const HIR_VERSION_MIN: u32 = 0;
pub const HIR_VERSION: u32 = 1;
pub const HIR_VERSION_MAX: u32 = HIR_VERSION;

pub use codec::{decode, encode, DecodeError, HIR_MAGIC};
pub use lower::{hir_node_count, lower_to_hir};
pub use types::*;
