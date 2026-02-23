// src/runtime/event_sink.rs
//
// Step 3: Fan-out sink interface.
// Sinks are fed *after* canonical binary write+hash succeeds.
//
// Fail-fast semantics:
// - Sink errors must propagate to caller (audit integrity).

use std::io;

use super::event::EventHeader;

/// Fan-out sink interface.
///
/// Determinism requirements:
/// - Sink output must be deterministic given the same (header, payload) bytes.
/// - Avoid dynamically ordered maps; manual formatting or stable structs only.
///
/// Error semantics:
/// - Any IO error is returned and must be treated as fatal at call sites.
pub trait EventSink: Send {
    fn on_event(&mut self, header: &EventHeader, payload: &[u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}