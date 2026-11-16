//! Why did the heartbeat stop for a while: sleep, the recorder itself, or a freeze?

use wsg_events::EventRecord;

/// Slack around the gap for events logged just before it began or just after it ended.
const SLACK_NS: i64 = 30 * 1_000_000_000;
/// The service name the recorder is installed under.
pub const RECORDER_SERVICE: &str = "WindowsSystemGuard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapKind {
    Sleep,
    Freeze,
    RecorderStopped,
}

/// Classifies a gap between two heartbeats. Sleep wins over a recorder stop, because a sleeping
/// machine also stops the service's clock. With neither explanation the gap is a `Freeze`, which
/// means only that nothing explains the missing heartbeats, not that the machine froze.
pub fn classify_gap(gap_start_utc_ns: i64, gap_end_utc_ns: i64, events: &[EventRecord]) -> GapKind {
    let (lo, hi) = (gap_start_utc_ns.saturating_sub(SLACK_NS), gap_end_utc_ns.saturating_add(SLACK_NS));
    let inside: Vec<&EventRecord> = events.iter().filter(|e| e.utc_ns >= lo && e.utc_ns <= hi).collect();
    if inside.iter().any(|e| is_sleep_event(e)) {
        GapKind::Sleep
    } else if inside.iter().any(|e| is_recorder_service_event(e)) {
        GapKind::RecorderStopped
    } else {
        GapKind::Freeze
    }
}

/// Kernel-Power 42 (entering sleep), 506 and 507 (connected standby enter and exit) and
/// Power-Troubleshooter 1 (woke from sleep). Kernel-Power 105 is left out on purpose: it reports a
/// power-source change, which also happens while the machine stays awake.
fn is_sleep_event(e: &EventRecord) -> bool {
    matches!(
        (e.provider.as_str(), e.event_id),
        ("Microsoft-Windows-Kernel-Power", 42 | 506 | 507) | ("Microsoft-Windows-Power-Troubleshooter", 1)
    )
}

/// A Service Control Manager event about the recorder: 7036 (state change), 7034 (crashed),
/// 7031 (crashed, restart scheduled), 7040 (start type changed).
fn is_recorder_service_event(e: &EventRecord) -> bool {
    e.provider == "Service Control Manager"
        && matches!(e.event_id, 7036 | 7034 | 7031 | 7040)
        && e.payload.values().any(|v| v.eq_ignore_ascii_case(RECORDER_SERVICE))
}
