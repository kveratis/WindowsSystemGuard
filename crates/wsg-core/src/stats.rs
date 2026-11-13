//! Health counters reported by the writer and the isolation helpers.

use serde::{Deserialize, Serialize};

/// State of the tiered writer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WriterStats {
    /// Records lost: rejected by a full queue or evicted from the in-memory buffer.
    pub dropped: u64,
    /// Records are currently not reaching the primary sink.
    pub fallback_active: bool,
    /// Times a primary append or flush missed its deadline.
    pub primary_stalls: u64,
    /// The latest record reached neither sink and is held only in memory.
    pub memory_only: bool,
}

/// State of an isolated helper (sensor or GPU query process).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HelperStats {
    pub restarts: u32,
    pub abandoned: bool,
    pub last_stall_utc_ns: Option<i64>,
}
