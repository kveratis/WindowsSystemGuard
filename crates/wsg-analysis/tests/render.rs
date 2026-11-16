use std::collections::BTreeMap;

use wsg_analysis::{render_postmortem, Divergence, HardwareContext, IncidentTimeline, PostMortemInput, Presence, Stamp};
use wsg_core::{HelperStats, WriterStats};
use wsg_events::updates::{InstallLoop, UpdateEvent, UpdateKind};
use wsg_events::{group, EventRecord};

const SEC: i64 = 1_000_000_000;

fn stamp(t: i64, seq: u64) -> Stamp {
    Stamp { utc_ns: 1_794_000_000 * SEC + t * SEC, mono_ns: Some(t as u64), seq: Some(seq) }
}

fn ev(provider: &str, id: u16, msg: Option<&str>) -> EventRecord {
    EventRecord {
        channel: "System".into(),
        provider: provider.into(),
        event_id: id,
        version: 0,
        level: 2,
        utc_ns: 1_794_000_000 * SEC,
        record_id: 1,
        payload: BTreeMap::from([("DeviceName".to_string(), r"\Device\Harddisk1".to_string())]),
        rendered_message: msg.map(str::to_string),
        raw_xml: String::new(),
    }
}

fn base() -> PostMortemInput {
    PostMortemInput { sensors_available: true, ..Default::default() }
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap()
}

#[test]
fn empty_evidence_says_cause_undetermined_first() {
    let r = render_postmortem(&base());
    assert!(first_line(&r).starts_with("Cause undetermined"), "{}", first_line(&r));
    assert!(first_line(&r).contains("no heartbeat gap"));
    assert!(r.contains("CHECKS OUTSIDE THE RECORDER"), "checklist is always printed");
    for needle in ["dump", "BIOS", "XMP/DOCP", "PSU", "memory test", "wsl --shutdown"] {
        assert!(r.contains(needle), "checklist mentions {needle}");
    }
    // A heartbeat that stopped is not a cause either.
    let mut with_gap = base();
    with_gap.timeline = IncidentTimeline { freeze_onset_estimate: Some(stamp(10, 20)), ..Default::default() };
    let r = render_postmortem(&with_gap);
    assert!(first_line(&r).starts_with("Cause undetermined") && first_line(&r).contains("not why"), "{}", first_line(&r));
}

#[test]
fn divergence_appears_with_evidence_seq_numbers() {
    let mut i = base();
    i.divergences = vec![Divergence {
        metric: "disk 0 C: read_latency_ms".into(),
        baseline_median: 2.0,
        incident_value: 80.0,
        ratio: 40.0,
        evidence_seqs: vec![1003, 1007],
    }];
    let r = render_postmortem(&i);
    assert!(!first_line(&r).contains("Cause undetermined"));
    assert!(first_line(&r).contains("leads, not a proven cause"));
    let l = r.lines().find(|l| l.contains("read_latency_ms")).expect("metric listed");
    assert!(l.contains("40.0x") && l.contains("1003, 1007"), "{l}");
}

#[test]
fn sensors_unavailable_is_stated() {
    let mut i = base();
    i.sensors_available = false;
    let r = render_postmortem(&i);
    assert!(r.contains("Temperature, voltage and fan data were not recorded"));
    assert!(r.contains("LibreHardwareMonitor or HWiNFO"));
    i.sensors_available = true;
    assert!(!render_postmortem(&i).contains("were not recorded"));
}

#[test]
fn install_loop_is_listed() {
    let mut i = base();
    i.install_loops = vec![InstallLoop {
        name: "9NRZT3Q9R3DL-Microsoft.WindowsAppRuntime.2".into(),
        count: 32,
        first_utc_ns: 1_794_000_000 * SEC,
        last_utc_ns: 1_794_086_400 * SEC,
    }];
    i.update_events = vec![UpdateEvent {
        utc_ns: 1_794_000_100 * SEC,
        kind: UpdateKind::Failed { code: "0x80073D02".into() },
        name: "9MV0B5HZVK9Z-Microsoft.GamingApp".into(),
        detail: String::new(),
    }];
    let r = render_postmortem(&i);
    assert!(r.contains("Microsoft.WindowsAppRuntime.2 installed 32 times"), "{r}");
    assert!(r.contains("failed (0x80073D02): 9MV0B5HZVK9Z-Microsoft.GamingApp"));
}

#[test]
fn never_mentions_expo() {
    let mut i = base();
    i.hardware = HardwareContext { motherboard: "Board".into(), xmp_docp_enabled: Some(true), ..Default::default() };
    i.divergences = vec![Divergence { metric: "m".into(), baseline_median: 1.0, incident_value: 9.0, ratio: 9.0, evidence_seqs: vec![1] }];
    for input in [base(), i] {
        let r = render_postmortem(&input).to_lowercase();
        assert!(!r.contains("expo"), "AM4 uses DDR4: XMP/DOCP only");
    }
}

#[test]
fn suppressed_noise_shown_as_counts_only() {
    let mut i = base();
    let suppressed = group(&[ev("Microsoft-Windows-DistributedCOM", 10016, Some("The application-specific permission settings do not grant"))]);
    assert_eq!(suppressed.len(), 1);
    i.suppressed_summary = vec![("DCOM 10016 (permission settings)".into(), 412)];
    let r = render_postmortem(&i);
    assert!(r.contains("DCOM 10016 (permission settings): 412 event(s)"));
    assert!(!r.contains("DistributedCOM") && !r.contains("application-specific"), "no suppressed group detail");
}

#[test]
fn surfaced_event_shows_message_or_payload_and_score() {
    let mut i = base();
    let with_msg = group(&[ev("Storport", 129, Some("Reset to device,\n\\Device\\RaidPort0, was issued."))]).remove(0);
    let no_msg = group(&[ev("Disk", 7, None)]).remove(0);
    i.surfaced_groups = vec![(with_msg, 9.8), (no_msg, 4.2)];
    let r = render_postmortem(&i);
    assert!(r.contains("[9.8] Storport event 129"));
    assert!(r.contains("Reset to device, \\Device\\RaidPort0, was issued."), "message flattened to one line");
    assert!(r.contains("no message text; DeviceName="));
}

#[test]
fn evidence_quality_reports_loss_stalls_and_helpers() {
    let mut i = base();
    i.writer_stats = Some(WriterStats { dropped: 17, fallback_active: true, primary_stalls: 3, memory_only: true });
    i.helper_stats = vec![("sensors".into(), HelperStats { restarts: 5, abandoned: true, last_stall_utc_ns: Some(1_794_000_000 * SEC) })];
    let r = render_postmortem(&i);
    for needle in ["lost before reaching a ring: 17", "fallback ring took over", "stalled 3 time", "held only in memory", "Helper sensors: 5 restart(s), given up on"] {
        assert!(r.contains(needle), "missing {needle}\n{r}");
    }
    assert!(render_postmortem(&base()).contains("Writer health was not available"));
}

#[test]
fn timeline_states_what_each_stamp_cannot_prove_and_presence_lists_caveats() {
    let mut i = base();
    i.timeline = IncidentTimeline {
        last_sample_taken: Some(stamp(11, 22)),
        last_sample_persisted: Some(stamp(10, 20)),
        freeze_onset_estimate: Some(stamp(10, 19)),
        recorder_crash_suspected: true,
        ..Default::default()
    };
    let key = wsg_events::group_key(&ev("Microsoft-Windows-Hyper-V-VmSwitch", 285, None));
    i.presence = vec![(key, Presence { incident: (3, 3), quiet: (2, 5), caveats: vec!["WSL state differs".into()] })];
    let r = render_postmortem(&i);
    assert!(r.contains("Last sample taken") && r.contains("Last sample persisted") && r.contains("record 22"));
    assert!(r.contains("Forced power-off: not recorded"));
    assert!(r.contains("not a cause"));
    assert!(r.contains("The recorder, not the machine, most likely stopped"));
    assert!(r.contains("Hyper-V-VmSwitch event 285: in 3 of 3 incident windows, 2 of 5 quiet windows"));
    assert!(r.contains("caveat: WSL state differs"));
}
