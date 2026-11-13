//! Core types for WindowsSystemGuard: records and the crash-consistent ring file.

pub mod record;
pub mod ring;

pub use record::{BootId, Record, RecordKind};
pub use ring::{Ring, RingError, RingReader, MAX_PAYLOAD};
