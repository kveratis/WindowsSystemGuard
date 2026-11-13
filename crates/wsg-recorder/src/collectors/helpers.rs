//! Collectors backed by an isolated helper process (see `supervisor`).

use std::time::Duration;

use wsg_core::sample::{GpuStats, Reading, SensorSet};
use wsg_core::stats::HelperStats;

use super::{CollectOutcome, Collector, SampleFragment};
use crate::supervisor::{HelperSpec, HelperSupervisor};

const GPU_FIELDS: [&str; 5] = ["util_pct", "mem_used_bytes", "temp_c", "power_w", "clock_mhz"];

/// Maps a `wsg-gpu-helper` line; any null or missing field makes the whole reading unavailable.
pub fn gpu_from_json(r: Reading<serde_json::Value>) -> Reading<GpuStats> {
    let (v, age_ms) = match r {
        Reading::Value { v, age_ms } => (v, age_ms),
        Reading::Unavailable { reason } => return Reading::Unavailable { reason },
    };
    let missing: Vec<&str> = GPU_FIELDS.into_iter().filter(|f| !v[*f].is_number()).collect();
    if !missing.is_empty() {
        return Reading::Unavailable { reason: format!("unsupported: {}", missing.join(",")) };
    }
    let f = |k: &str| v[k].as_f64().unwrap() as f32;
    Reading::Value {
        v: GpuStats {
            util_pct: f("util_pct"),
            mem_used_bytes: v["mem_used_bytes"].as_f64().unwrap() as u64,
            temp_c: f("temp_c"),
            power_w: f("power_w"),
            clock_mhz: f("clock_mhz"),
        },
        age_ms,
    }
}

/// Maps a `wsg-sensor-helper` line, whose fields are the JSON form of `SensorSet`.
pub fn sensors_from_json(r: Reading<serde_json::Value>) -> Reading<SensorSet> {
    match r {
        Reading::Value { v, age_ms } => match serde_json::from_value(v) {
            Ok(v) => Reading::Value { v, age_ms },
            Err(e) => Reading::Unavailable { reason: format!("malformed sensor line: {e}") },
        },
        Reading::Unavailable { reason } => Reading::Unavailable { reason },
    }
}

pub struct GpuCollector(HelperSupervisor);

impl GpuCollector {
    pub fn new(spec: HelperSpec) -> Self {
        Self(HelperSupervisor::spawn(spec))
    }
    pub fn stats(&self) -> HelperStats {
        self.0.stats()
    }
}

impl Collector for GpuCollector {
    fn name(&self) -> &'static str {
        "gpu"
    }
    fn collect(&mut self, _budget: Duration) -> CollectOutcome {
        CollectOutcome::Ok(SampleFragment::Gpu(gpu_from_json(self.0.poll())))
    }
}

pub struct SensorCollector(HelperSupervisor);

impl SensorCollector {
    pub fn new(spec: HelperSpec) -> Self {
        Self(HelperSupervisor::spawn(spec))
    }
    pub fn stats(&self) -> HelperStats {
        self.0.stats()
    }
}

impl Collector for SensorCollector {
    fn name(&self) -> &'static str {
        "sensors"
    }
    fn collect(&mut self, _budget: Duration) -> CollectOutcome {
        CollectOutcome::Ok(SampleFragment::Sensors(sensors_from_json(self.0.poll())))
    }
}
