use std::collections::BTreeMap;
use std::time::Duration;

use wsg_analysis::{build_timeline, classify_gap, GapKind};
use wsg_core::{BootId, Record, RecordKind, MARKER_CLEAN};
use wsg_events::EventRecord;

const SEC: i64 = 1_000_000_000;
const BOOT: BootId = BootId([1; 16]);
const INTERVAL: Duration = Duration::from_secs(1);

fn rec(seq: u64, t_s: i64, kind: RecordKind) -> Record {
    Record { seq, boot: BOOT, utc_ns: t_s * SEC, mono_ns: (t_s * SEC) as u64, kind, payload: vec![] }
}

fn ev(provider: &str, id: u16, t_s: i64, data: &[(&str, &str)]) -> EventRecord {
    EventRecord {
        channel: "System".into(),
        provider: provider.into(),
        event_id: id,
        version: 0,
        level: 2,
        utc_ns: t_s * SEC,
        record_id: 1,
        payload: data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>(),
        rendered_message: None,
        raw_xml: String::new(),
    }
}

/// Heartbeat and sample once a second from t=0 to t=`last`.
fn run(last: i64) -> Vec<Record> {
    (0..=last)
        .flat_map(|t| [rec(2 * t as u64 + 1, t, RecordKind::Heartbeat), rec(2 * t as u64 + 2, t, RecordKind::Sample)])
        .collect()
}

#[test]
fn heartbeat_gap_with_kernel_power_41_is_freeze() {
    let events = [ev("Microsoft-Windows-Kernel-Power", 41, 500, &[])];
    assert_eq!(classify_gap(100 * SEC, 400 * SEC, &events), GapKind::Freeze);
    assert_eq!(classify_gap(100 * SEC, 400 * SEC, &[]), GapKind::Freeze);
}

#[test]
fn gap_spanning_sleep_events_is_sleep_not_freeze() {
    for e in [
        ev("Microsoft-Windows-Kernel-Power", 42, 101, &[]),
        ev("Microsoft-Windows-Kernel-Power", 506, 150, &[]),
        ev("Microsoft-Windows-Kernel-Power", 507, 399, &[]),
        ev("Microsoft-Windows-Kernel-Power", 105, 399, &[]),
        ev("Microsoft-Windows-Power-Troubleshooter", 1, 401, &[]),
    ] {
        assert_eq!(classify_gap(100 * SEC, 400 * SEC, &[e.clone()]), GapKind::Sleep, "{} {}", e.provider, e.event_id);
    }
    let far = ev("Microsoft-Windows-Kernel-Power", 42, 5000, &[]);
    assert_eq!(classify_gap(100 * SEC, 400 * SEC, &[far]), GapKind::Freeze, "a sleep elsewhere does not explain this gap");
}

#[test]
fn gap_with_recorder_service_restart_is_recorder_stopped() {
    let stop = ev("Service Control Manager", 7036, 200, &[("param1", "WindowsSystemGuard"), ("param2", "stopped")]);
    let start = ev("Service Control Manager", 7036, 210, &[("param1", "WindowsSystemGuard"), ("param2", "running")]);
    assert_eq!(classify_gap(100 * SEC, 400 * SEC, &[stop, start]), GapKind::RecorderStopped);
    let other = ev("Service Control Manager", 7036, 200, &[("param1", "Spooler"), ("param2", "stopped")]);
    assert_eq!(classify_gap(100 * SEC, 400 * SEC, &[other]), GapKind::Freeze);
    let both = [
        ev("Service Control Manager", 7036, 200, &[("param1", "WindowsSystemGuard")]),
        ev("Microsoft-Windows-Kernel-Power", 42, 101, &[]),
    ];
    assert_eq!(classify_gap(100 * SEC, 400 * SEC, &both), GapKind::Sleep, "sleep also stops the service");
}

#[test]
fn wall_clock_going_backwards_does_not_reorder_records() {
    let mut r = run(10);
    // The wall clock is stepped back an hour after t=5; the monotonic clock keeps counting.
    for x in r.iter_mut().filter(|x| x.mono_ns > 5 * SEC as u64) {
        x.utc_ns -= 3600 * SEC;
    }
    r.reverse();
    let t = build_timeline(&r, &[], INTERVAL);
    assert_eq!(t.last_sample_taken.unwrap().mono_ns, Some(10 * SEC as u64), "newest by monotonic clock");
    assert_eq!(t.last_sample_taken.unwrap().utc_ns, 10 * SEC - 3600 * SEC, "its own wall time, as recorded");
    assert_eq!(t.freeze_onset_estimate.unwrap().mono_ns, Some(10 * SEC as u64));
}

#[test]
fn forced_power_off_and_next_boot_come_from_event_41_and_6008() {
    let power_button_ft = 116_444_736_000_000_000i64 + 12 * SEC / 100;
    let events = [
        ev("Microsoft-Windows-Kernel-Power", 41, 300, &[("PowerButtonTimestamp", &power_button_ft.to_string())]),
        ev("EventLog", 6008, 290, &[]),
        ev("Microsoft-Windows-Kernel-Power", 41, 1, &[("PowerButtonTimestamp", "0")]), // an old, unrelated one
    ];
    let t = build_timeline(&run(10), &events, INTERVAL);
    assert_eq!(t.next_boot.unwrap().utc_ns, 290 * SEC, "earliest report after the last sample");
    assert_eq!(t.forced_power_off.unwrap().utc_ns, 12 * SEC);
    assert!(!t.ring_ended_cleanly && !t.recorder_crash_suspected);
    assert_eq!(t.freeze_onset_estimate.unwrap().utc_ns, 10 * SEC);

    let no_button = [ev("Microsoft-Windows-Kernel-Power", 41, 300, &[("PowerButtonTimestamp", "0")])];
    assert_eq!(build_timeline(&run(10), &no_button, INTERVAL).forced_power_off, None);
}

#[test]
fn last_persisted_differs_from_last_taken_when_writer_lagged() {
    // The cycle at t=11 wrote its heartbeat, then the machine stopped before its sample.
    let mut r = run(10);
    r.push(rec(100, 11, RecordKind::Heartbeat));
    let t = build_timeline(&r, &[], INTERVAL);
    assert_eq!(t.last_sample_taken.unwrap().utc_ns, 11 * SEC);
    assert_eq!(t.last_sample_persisted.unwrap().utc_ns, 10 * SEC);
    assert_ne!(t.last_sample_taken, t.last_sample_persisted);
}

#[test]
fn clean_marker_means_no_incident() {
    let mut r = run(10);
    let mut m = rec(100, 10, RecordKind::Marker);
    m.payload = MARKER_CLEAN.to_vec();
    r.push(m);
    let t = build_timeline(&r, &[ev("Microsoft-Windows-Kernel-Power", 41, 300, &[])], INTERVAL);
    assert!(t.ring_ended_cleanly);
    assert_eq!((t.freeze_onset_estimate, t.next_boot, t.forced_power_off), (None, None, None));
    assert!(!t.recorder_crash_suspected);
    assert!(t.last_sample_taken.is_some(), "the last samples are still reported");
}

#[test]
fn trailing_slow_heartbeats_move_onset_back_to_the_last_normal_one() {
    let mut r: Vec<Record> = (0..=10).map(|t| rec(t as u64 + 1, t, RecordKind::Heartbeat)).collect();
    for (i, t) in [15, 22, 31].into_iter().enumerate() {
        r.push(rec(20 + i as u64, t, RecordKind::Heartbeat));
    }
    let t = build_timeline(&r, &[], INTERVAL);
    assert_eq!(t.freeze_onset_estimate.unwrap().utc_ns, 10 * SEC, "stalling began after the heartbeat at t=10");
    assert_eq!(t.last_sample_taken.unwrap().utc_ns, 31 * SEC);
}

#[test]
fn missing_clean_marker_with_normal_os_shutdown_suspects_the_recorder() {
    let shutdown = [ev("EventLog", 6006, 20, &[])];
    assert!(build_timeline(&run(10), &shutdown, INTERVAL).recorder_crash_suspected);
    let crash = [ev("Service Control Manager", 7034, 12, &[("param1", "WindowsSystemGuard")])];
    assert!(build_timeline(&run(10), &crash, INTERVAL).recorder_crash_suspected);
    let freeze = [ev("EventLog", 6006, 20, &[]), ev("EventLog", 6008, 25, &[])];
    assert!(!build_timeline(&run(10), &freeze, INTERVAL).recorder_crash_suspected, "OS reported an unclean shutdown");
    assert!(!build_timeline(&run(10), &[], INTERVAL).recorder_crash_suspected, "no events, no claim");
}

#[test]
fn only_the_newest_boot_is_described_and_empty_input_is_empty() {
    let mut old: Vec<Record> = run(5);
    let mut new_boot: Vec<Record> = run(5);
    for r in &mut new_boot {
        r.boot = BootId([2; 16]);
        r.utc_ns += 1000 * SEC;
    }
    old.extend(new_boot);
    let t = build_timeline(&old, &[], INTERVAL);
    assert_eq!(t.last_sample_taken.unwrap().utc_ns, 1005 * SEC);
    assert_eq!(build_timeline(&[], &[], INTERVAL), Default::default());
}
