//! One collection cycle's readings and its versioned wire encoding.

use serde::{Deserialize, Serialize};

// Stays 1: disks/net became `Reading<Vec<_>>` before any data had been written.
pub const SAMPLE_SCHEMA_VERSION: u8 = 1;

/// A reading that is either a value (with its age) or explicitly unavailable, never a silent zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Reading<T> {
    Value { v: T, age_ms: u32 },
    Unavailable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CpuStats {
    pub total_pct: f32,
    pub dpc_pct: f32,
    pub interrupt_pct: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemStats {
    pub commit_bytes: u64,
    pub available_bytes: u64,
    pub nonpaged_pool_bytes: u64,
    pub paged_pool_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskStats {
    pub disk_id: String,
    pub queue_len: f32,
    pub read_latency_ms: f32,
    pub write_latency_ms: f32,
    pub bytes_per_sec: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetStats {
    pub adapter: String,
    pub bytes_per_sec: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcStat {
    pub pid: u32,
    pub name: String,
    pub cpu_pct: f32,
    pub working_set_bytes: u64,
    pub io_bytes_per_sec: u64,
    pub handles: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpuStats {
    pub util_pct: f32,
    pub mem_used_bytes: u64,
    pub temp_c: f32,
    pub power_w: f32,
    pub clock_mhz: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensorSet {
    pub cpu_temp_c: Option<f32>,
    pub per_core_clock_mhz: Vec<f32>,
    pub voltages: Vec<(String, f32)>,
    pub fans_rpm: Vec<(String, u32)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    pub cpu: Reading<CpuStats>,
    pub mem: Reading<MemStats>,
    pub disks: Reading<Vec<DiskStats>>,
    pub net: Reading<Vec<NetStats>>,
    pub procs: Vec<ProcStat>,
    pub gpu: Reading<GpuStats>,
    pub sensors: Reading<SensorSet>,
    pub wsl_vm_running: Reading<bool>,
    pub cycle_ms: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unknown sample schema version {0}")]
    UnknownSchema(u8),
    #[error("corrupt sample payload")]
    Corrupt,
}

impl Sample {
    /// Schema-version byte followed by the postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![SAMPLE_SCHEMA_VERSION];
        out.extend(postcard::to_stdvec(self).expect("sample serialization is infallible"));
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Sample, DecodeError> {
        match bytes.split_first() {
            None => Err(DecodeError::Corrupt),
            Some((&v, _)) if v != SAMPLE_SCHEMA_VERSION => Err(DecodeError::UnknownSchema(v)),
            Some((_, rest)) => postcard::from_bytes(rest).map_err(|_| DecodeError::Corrupt),
        }
    }
}
