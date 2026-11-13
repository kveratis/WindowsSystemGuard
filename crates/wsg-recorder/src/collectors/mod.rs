//! In-process collectors. Each produces one `SampleFragment` per call; `assemble` merges them.

use std::time::{Duration, Instant};
use wsg_core::sample::{CpuStats, DiskStats, MemStats, NetStats, ProcStat, Reading, Sample};

mod counters;
mod heartbeat;
mod processes;
mod wsl;

pub use counters::{CounterCollector, CounterError};
pub use heartbeat::HeartbeatCollector;
pub use processes::ProcessCollector;
pub use wsl::WslCollector;

pub enum SampleFragment {
    Cpu(Reading<CpuStats>),
    Mem(Reading<MemStats>),
    Disks(Vec<DiskStats>),
    Net(Vec<NetStats>),
    Procs(Vec<ProcStat>),
    Wsl(Reading<bool>),
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

pub fn assemble(frags: Vec<SampleFragment>, cycle_ms: u32) -> Sample {
    fn missing<T>() -> Reading<T> {
        Reading::Unavailable { reason: "no collector result".into() }
    }
    let mut s = Sample {
        cpu: missing(),
        mem: missing(),
        disks: vec![],
        net: vec![],
        procs: vec![],
        gpu: missing(),
        sensors: missing(),
        wsl_vm_running: missing(),
        cycle_ms,
    };
    fn apply(s: &mut Sample, f: SampleFragment) {
        match f {
            SampleFragment::Cpu(r) => s.cpu = r,
            SampleFragment::Mem(r) => s.mem = r,
            SampleFragment::Disks(v) => s.disks = v,
            SampleFragment::Net(v) => s.net = v,
            SampleFragment::Procs(v) => s.procs = v,
            SampleFragment::Wsl(r) => s.wsl_vm_running = r,
            SampleFragment::Heartbeat { .. } => {}
            SampleFragment::Multi(v) => v.into_iter().for_each(|f| apply(s, f)),
        }
    }
    frags.into_iter().for_each(|f| apply(&mut s, f));
    s
}
