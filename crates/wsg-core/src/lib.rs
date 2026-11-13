//! Core types for WindowsSystemGuard: records and the crash-consistent ring file.

pub mod archive;
pub mod clock;
pub mod record;
pub mod ring;
pub mod sample;

pub use clock::{mono_ns, new_boot_id, now_utc_ns};
pub use record::{BootId, Record, RecordKind};
pub use ring::{Ring, RingError, RingReader, MAX_PAYLOAD};
pub use sample::{
    CpuStats, DecodeError, DiskStats, GpuStats, MemStats, NetStats, ProcStat, Reading, Sample,
    SensorSet, SAMPLE_SCHEMA_VERSION,
};
