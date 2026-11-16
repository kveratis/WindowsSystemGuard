//! The honest incident timeline: what the recorder saw last, what the operating system says
//! about the restart, and what neither can prove.

use std::time::Duration;

use wsg_core::{BootId, Record, RecordKind, MARKER_CLEAN};
use wsg_events::EventRecord;

use crate::gap::RECORDER_SERVICE;

/// One point in time as each clock saw it. `mono_ns` and `seq` are known only for recorder records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    pub utc_ns: i64,
    pub mono_ns: Option<u64>,
    pub seq: Option<u64>,
}

impl Stamp {
    fn of(r: &Record) -> Stamp {
        Stamp { utc_ns: r.utc_ns, mono_ns: Some(r.mono_ns), seq: Some(r.seq) }
    }
    fn at(utc_ns: i64) -> Stamp {
        Stamp { utc_ns, mono_ns: None, seq: None }
    }
}

/// Each field says one thing and no more. None of them is "the moment of the freeze".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IncidentTimeline {
    /// Newest sample or heartbeat in the rings: the last cycle the recorder started.
    pub last_sample_taken: Option<Stamp>,
    /// Newest complete sample record in the rings. It trails `last_sample_taken` when the machine
    /// stopped partway through a cycle. Neither proves the bytes reached the disk surface.
    pub last_sample_persisted: Option<Stamp>,
    /// Where heartbeats stopped or slowed for good, so the freeze began at or after this. It is
    /// accurate to about one heartbeat interval and says nothing about the cause.
    pub freeze_onset_estimate: Option<Stamp>,
    /// When the power button was held to force a shutdown (Kernel-Power 41 `PowerButtonTimestamp`);
    /// `None` if the machine was reset another way or the field is empty.
    pub forced_power_off: Option<Stamp>,
    /// The first unclean-shutdown report (Kernel-Power 41 or EventLog 6008) logged after the last
    /// sample. It is logged during the next boot, so it bounds the restart, not the freeze.
    pub next_boot: Option<Stamp>,
    pub ring_ended_cleanly: bool,
    /// The ring has no clean marker but the operating system shut down normally or the service was
    /// reported crashed, so the recorder, not the machine, most likely stopped.
    pub recorder_crash_suspected: bool,
}

/// Heartbeats this many intervals apart count as slow.
const SLOW_FACTOR: u32 = 3;
/// Offset from the Windows FILETIME epoch (1601) to the Unix epoch, in 100 ns ticks.
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

/// Builds the timeline of the newest boot in `records` (the merged rings, see `wsg_core::merge_rings`).
/// Records are ordered by `(mono_ns, seq)` within the boot, so a wall clock that moves backwards
/// does not reorder them. `events` are the System-log events around the restart.
pub fn build_timeline(records: &[Record], events: &[EventRecord], heartbeat_interval: Duration) -> IncidentTimeline {
    let Some(boot) = newest_boot(records) else {
        return IncidentTimeline::default();
    };
    let mut recs: Vec<&Record> = records.iter().filter(|r| r.boot == boot).collect();
    recs.sort_by_key(|r| (r.mono_ns, r.seq));

    let newest = |kinds: &[RecordKind]| recs.iter().rev().find(|r| kinds.contains(&r.kind)).map(|r| Stamp::of(r));
    let last_taken = newest(&[RecordKind::Sample, RecordKind::Heartbeat]);
    let last_persisted = newest(&[RecordKind::Sample]);
    let clean = recs.iter().any(|r| r.kind == RecordKind::Marker && r.payload == MARKER_CLEAN);

    let mut t = IncidentTimeline {
        last_sample_taken: last_taken,
        last_sample_persisted: last_persisted,
        ring_ended_cleanly: clean,
        ..Default::default()
    };
    if clean {
        return t;
    }
    t.freeze_onset_estimate = onset(&recs, heartbeat_interval);

    let after = last_taken.map_or(i64::MIN, |s| s.utc_ns);
    let later: Vec<&EventRecord> = events.iter().filter(|e| e.utc_ns >= after).collect();
    let unclean_reports: Vec<&&EventRecord> = later.iter().filter(|e| is_unclean_report(e)).collect();
    t.next_boot = unclean_reports.iter().map(|e| e.utc_ns).min().map(Stamp::at);
    t.forced_power_off = unclean_reports
        .iter()
        .filter(|e| e.provider == "Microsoft-Windows-Kernel-Power" && e.event_id == 41)
        .filter_map(|e| e.payload.get("PowerButtonTimestamp"))
        .filter_map(|v| v.trim().parse::<i64>().ok())
        .filter(|ft| *ft > FILETIME_UNIX_EPOCH)
        .map(|ft| (ft - FILETIME_UNIX_EPOCH) * 100)
        .min()
        .map(Stamp::at);
    // No unclean report but the OS shut down normally or the service crashed: the recorder died.
    t.recorder_crash_suspected = unclean_reports.is_empty() && later.iter().any(|e| is_clean_os_shutdown(e) || is_recorder_crash(e));
    t
}

/// The boot whose earliest record is newest by wall clock. A boot's own records are ordered by
/// the monotonic clock, but monotonic time restarts every boot, so it cannot rank boots.
fn newest_boot(records: &[Record]) -> Option<BootId> {
    let mut first: Vec<(BootId, i64)> = Vec::new();
    for r in records {
        match first.iter_mut().find(|(b, _)| *b == r.boot) {
            Some((_, t)) => *t = (*t).min(r.utc_ns),
            None => first.push((r.boot, r.utc_ns)),
        }
    }
    first.into_iter().max_by_key(|(_, t)| *t).map(|(b, _)| b)
}

/// Walks back from the last heartbeat across trailing slow gaps; the heartbeat before the first
/// slow gap of that run is the last one at normal pace. Falls back to the last sample when the
/// ring holds no heartbeat.
fn onset(recs: &[&Record], interval: Duration) -> Option<Stamp> {
    let hb: Vec<&&Record> = recs.iter().filter(|r| r.kind == RecordKind::Heartbeat).collect();
    if hb.is_empty() {
        return recs.iter().rev().find(|r| r.kind == RecordKind::Sample).map(|r| Stamp::of(r));
    }
    let slow = (interval * SLOW_FACTOR).as_nanos() as u64;
    let mut i = hb.len() - 1;
    while i > 0 && hb[i].mono_ns - hb[i - 1].mono_ns > slow {
        i -= 1;
    }
    Some(Stamp::of(hb[i]))
}

/// Kernel-Power 41 (restart without a clean shutdown) and EventLog 6008 (previous shutdown unexpected).
fn is_unclean_report(e: &EventRecord) -> bool {
    matches!((e.provider.as_str(), e.event_id), ("Microsoft-Windows-Kernel-Power", 41) | ("EventLog", 6008))
}

/// EventLog 6006: the event log service stopped, which happens only during a normal shutdown.
fn is_clean_os_shutdown(e: &EventRecord) -> bool {
    e.provider == "EventLog" && e.event_id == 6006
}

/// Service Control Manager 7034 or 7031 naming the recorder: the service terminated unexpectedly.
fn is_recorder_crash(e: &EventRecord) -> bool {
    e.provider == "Service Control Manager"
        && matches!(e.event_id, 7034 | 7031)
        && e.payload.values().any(|v| v.eq_ignore_ascii_case(RECORDER_SERVICE))
}
