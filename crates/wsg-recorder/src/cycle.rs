//! One sampling cycle: collect with per-collector and total deadlines, then write a heartbeat
//! and a sample record.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use wsg_core::stats::HelperStats;
use wsg_core::{BootId, NewRecord, RecordKind, TieredWriter};

use crate::collectors::{assemble_with_failures, CollectOutcome, Collector, SampleFragment};

pub trait Clock {
    fn utc_ns(&self) -> i64;
    fn mono_ns(&self) -> u64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn utc_ns(&self) -> i64 {
        wsg_core::now_utc_ns()
    }
    fn mono_ns(&self) -> u64 {
        wsg_core::mono_ns()
    }
}

/// Runs a collector on its own thread so a call that never returns costs a timeout, not the
/// cycle. While a call is outstanding, further calls report `TimedOut` without starting another.
pub struct Threaded {
    name: &'static str,
    req: Sender<Duration>,
    res: Receiver<(CollectOutcome, Option<HelperStats>)>,
    busy: bool,
    stats: Option<HelperStats>,
}

impl Threaded {
    pub fn new(mut inner: Box<dyn Collector>) -> Threaded {
        let name = inner.name();
        let (req, req_rx) = mpsc::channel::<Duration>();
        let (res_tx, res) = mpsc::channel();
        std::thread::spawn(move || {
            for budget in req_rx {
                let out = inner.collect(budget);
                if res_tx.send((out, inner.helper_stats())).is_err() {
                    break;
                }
            }
        });
        Threaded { name, req, res, busy: false, stats: None }
    }
}

impl Collector for Threaded {
    fn name(&self) -> &'static str {
        self.name
    }

    fn collect(&mut self, budget: Duration) -> CollectOutcome {
        if self.busy {
            // The late result belongs to an earlier cycle and is dropped.
            if self.res.try_recv().is_err() {
                return CollectOutcome::TimedOut;
            }
            self.busy = false;
            // `try_recv` consumed the late pair; its outcome is stale but its stats are not.
        }
        if self.req.send(budget).is_err() {
            return CollectOutcome::Unavailable("collector thread exited".into());
        }
        match self.res.recv_timeout(budget) {
            Ok((o, stats)) => {
                self.stats = stats;
                o
            }
            Err(RecvTimeoutError::Timeout) => {
                self.busy = true;
                CollectOutcome::TimedOut
            }
            Err(RecvTimeoutError::Disconnected) => CollectOutcome::Unavailable("collector thread exited".into()),
        }
    }

    fn is_threaded(&self) -> bool {
        true
    }

    fn helper_stats(&self) -> Option<HelperStats> {
        self.stats.clone()
    }
}

static HEARTBEATS: AtomicU64 = AtomicU64::new(0);

/// Cycles started by this process.
pub fn cycles() -> u64 {
    HEARTBEATS.load(Ordering::Relaxed)
}

fn record(kind: RecordKind, boot: BootId, clock: &dyn Clock, payload: Vec<u8>) -> NewRecord {
    NewRecord { kind, boot, utc_ns: clock.utc_ns(), mono_ns: clock.mono_ns(), payload }
}

/// Writes the heartbeat first, so it exists even if every collector stalls, then runs the
/// collectors in order. Each gets at most `per_collector_budget` and nothing starts after
/// `interval` has elapsed, so the cycle never outlasts its interval by more than one write.
pub fn run_cycle(
    collectors: &mut [Box<dyn Collector>],
    writer: &TieredWriter,
    boot: BootId,
    clock: &dyn Clock,
    interval: Duration,
    per_collector_budget: Duration,
) {
    let start = Instant::now();
    let n = HEARTBEATS.fetch_add(1, Ordering::Relaxed) + 1;
    let mut hb = n.to_le_bytes().to_vec();
    hb.extend(clock.mono_ns().to_le_bytes());
    writer.submit(record(RecordKind::Heartbeat, boot, clock, hb));

    let mut frags: Vec<SampleFragment> = Vec::new();
    let mut failures: Vec<(&str, String)> = Vec::new();
    for c in collectors.iter_mut() {
        if !c.is_threaded() {
            let inner = std::mem::replace(c, Box::new(Placeholder));
            *c = Box::new(Threaded::new(inner));
        }
        let Some(left) = interval.checked_sub(start.elapsed()).filter(|d| !d.is_zero()) else {
            failures.push((c.name(), "skipped, cycle deadline passed".into()));
            continue;
        };
        match c.collect(per_collector_budget.min(left)) {
            CollectOutcome::Ok(f) => frags.push(f),
            CollectOutcome::Unavailable(r) => failures.push((c.name(), r)),
            CollectOutcome::TimedOut => failures.push((c.name(), "timed out".into())),
        }
    }
    let ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
    let sample = assemble_with_failures(frags, ms, &failures);
    writer.submit(record(RecordKind::Sample, boot, clock, sample.encode()));
}

/// Stands in for a collector that has just been moved onto a worker thread.
struct Placeholder;
impl Collector for Placeholder {
    fn name(&self) -> &'static str {
        "placeholder"
    }
    fn collect(&mut self, _: Duration) -> CollectOutcome {
        CollectOutcome::Unavailable("moved to worker".into())
    }
}
