pub mod check;
pub mod codec;
pub mod lower;
pub mod types;

pub const MIR_VERSION_MIN: u16 = 0;
pub const MIR_VERSION_V1: u16 = 1;
pub const MIR_VERSION_MAX: u16 = MIR_VERSION_V1;

pub use check::{check, CheckError, DiagnosticCode};
pub use codec::{decode, encode, DecodeError, MIR_MAGIC};
pub use lower::lower_to_mir;
pub use types::*;
