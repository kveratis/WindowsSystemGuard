//! Core types for WindowsSystemGuard: records and the crash-consistent ring file.

pub mod archive;
pub mod clock;
pub mod record;
pub mod ring;
pub mod sample;
pub mod stats;
pub mod volume;
pub mod writer;

pub use clock::{mono_ns, new_boot_id, now_utc_ns};
pub use record::{BootId, Record, RecordKind};
pub use ring::{Ring, MARKER_CLEAN, RingError, RingReader, MAX_PAYLOAD};
pub use stats::{HelperStats, WriterStats};
pub use volume::{resolve_volume_path, volume_guid_for};
pub use writer::{NewRecord, RingFileSink, RingSink, SubmitResult, TieredWriter};
pub use sample::{
    CpuStats, DecodeError, DiskStats, GpuStats, MemStats, NetStats, ProcStat, Reading, Sample,
    SensorSet, SAMPLE_SCHEMA_VERSION,
};
