//! In-process collectors. Each produces one `SampleFragment` per call; `assemble` merges them.

use std::time::{Duration, Instant};
use wsg_core::sample::{
    CpuStats, DiskStats, GpuStats, MemStats, NetStats, ProcStat, Reading, Sample, SensorSet,
};

mod counters;
mod heartbeat;
mod helpers;
mod processes;
mod wsl;

pub use counters::{CounterCollector, CounterError};
pub use heartbeat::HeartbeatCollector;
pub use helpers::{gpu_from_json, sensors_from_json, GpuCollector, SensorCollector};
pub use processes::ProcessCollector;
pub use wsl::WslCollector;

pub enum SampleFragment {
    Cpu(Reading<CpuStats>),
    Mem(Reading<MemStats>),
    Disks(Vec<DiskStats>),
    Net(Vec<NetStats>),
    /// The collector tried and failed; `assemble` records its reason.
    DisksUnavailable(String),
    NetUnavailable(String),
    Procs(Vec<ProcStat>),
    Wsl(Reading<bool>),
    Gpu(Reading<GpuStats>),
    Sensors(Reading<SensorSet>),
    /// Liveness proof; ignored by `assemble` (written as its own heartbeat record).
    Heartbeat { counter: u64, mono_ns: u64 },
    /// A collector that covers several `Sample` fields (e.g. PDH) returns its parts here.
    Multi(Vec<SampleFragment>),
}

pub enum CollectOutcome {
    Ok(SampleFragment),
    Unavailable(String),
    TimedOut,
}

pub trait Collector: Send {
    fn name(&self) -> &'static str;
    fn collect(&mut self, budget: Duration) -> CollectOutcome;
    /// True for collectors that already run on their own worker thread (see `cycle::Threaded`).
    fn is_threaded(&self) -> bool {
        false
    }
}

/// Runs a collector and converts a result that arrived after `budget` into `TimedOut`.
// shortcut: runs on the caller's thread, so a blocking call is not cancelled, only reported late;
// upgrade to a worker thread with a channel timeout if a collector can hang.
pub fn run_with_budget(c: &mut dyn Collector, budget: Duration) -> CollectOutcome {
    let t = Instant::now();
    let out = c.collect(budget);
    if t.elapsed() > budget {
        CollectOutcome::TimedOut
    } else {
        out
    }
}

pub(crate) fn value<T>(v: T) -> Reading<T> {
    Reading::Value { v, age_ms: 0 }
}

/// Merges fragments into a `Sample`; if two fragments target the same field the last one wins.
pub fn assemble(frags: Vec<SampleFragment>, cycle_ms: u32) -> Sample {
    assemble_with_failures(frags, cycle_ms, &[])
}

/// Like `assemble`, and every field no fragment filled says why: the failed collectors
/// (`name: reason`) are appended to its reason, so a PDH error is told apart from a timeout.
// shortcut: a collector's failure is not tied to the field it feeds, so each missing field
// lists all failures of the cycle; tie them if one cycle often has several unrelated failures.
pub fn assemble_with_failures(frags: Vec<SampleFragment>, cycle_ms: u32, failures: &[(&str, String)]) -> Sample {
    let why = if failures.is_empty() {
        "no collector result".to_string()
    } else {
        let list: Vec<String> = failures.iter().map(|(n, r)| format!("{n}: {r}")).collect();
        format!("no collector result ({})", list.join("; "))
    };
    fn unavailable<T>(why: &str) -> Reading<T> {
        Reading::Unavailable { reason: why.to_string() }
    }
    let mut s = Sample {
        cpu: unavailable(&why),
        mem: unavailable(&why),
        disks: unavailable(&why),
        net: unavailable(&why),
        procs: vec![],
        gpu: unavailable(&why),
        sensors: unavailable(&why),
        wsl_vm_running: unavailable(&why),
        cycle_ms,
    };
    fn apply(s: &mut Sample, f: SampleFragment) {
        match f {
            SampleFragment::Cpu(r) => s.cpu = r,
            SampleFragment::Mem(r) => s.mem = r,
            SampleFragment::Disks(v) => s.disks = value(v),
            SampleFragment::DisksUnavailable(reason) => s.disks = Reading::Unavailable { reason },
            SampleFragment::Net(v) => s.net = value(v),
            SampleFragment::NetUnavailable(reason) => s.net = Reading::Unavailable { reason },
            SampleFragment::Procs(v) => s.procs = v,
            SampleFragment::Wsl(r) => s.wsl_vm_running = r,
            SampleFragment::Gpu(r) => s.gpu = r,
            SampleFragment::Sensors(r) => s.sensors = r,
            SampleFragment::Heartbeat { .. } => {}
            SampleFragment::Multi(v) => v.into_iter().for_each(|f| apply(s, f)),
        }
    }
    frags.into_iter().for_each(|f| apply(&mut s, f));
    s
}
