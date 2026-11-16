//! `wsg postmortem`: build and render the post-mortem of an archived incident.

use std::fs;
use std::path::Path;

use wsg_analysis::{
    build_timeline, diverged_metrics, render_postmortem, HardwareContext, PostMortemInput, Stamped,
};
use wsg_core::archive::{list_incidents, set_state, IncidentId, IncidentMeta, IncidentState};
use wsg_core::{Reading, RecordKind, RingReader, Sample};
use wsg_events::updates::{detect_install_loops, update_timeline_with_notes};
use wsg_events::{group, triage, IncidentWindow};

use crate::common::{collect_events, history_of, load_rules, split, NS};

/// Telemetry and events this far before the last sample are "just before the freeze".
const LOOKBACK_NS: i64 = 15 * 60 * NS;
/// How long after the last sample the restart reports are looked for.
const AFTER_NS: i64 = 24 * 3600 * NS;
const HISTORY_NS: i64 = 14 * 24 * 3600 * NS;
const DEFAULT_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// The recorder's cadence as it was recorded: the median gap between consecutive heartbeats of
/// the newest boot. The configured interval is not stored in the ring, and assuming the default
/// would make every gap of a slower cadence look like a stall.
fn heartbeat_interval(records: &[wsg_core::Record]) -> std::time::Duration {
    let Some(boot) = records.last().map(|r| r.boot) else { return DEFAULT_HEARTBEAT_INTERVAL };
    let mut monos: Vec<u64> = records.iter().filter(|r| r.boot == boot && r.kind == RecordKind::Heartbeat).map(|r| r.mono_ns).collect();
    monos.sort_unstable();
    let mut gaps: Vec<u64> = monos.windows(2).map(|w| w[1] - w[0]).filter(|g| *g > 0).collect();
    if gaps.is_empty() {
        return DEFAULT_HEARTBEAT_INTERVAL;
    }
    gaps.sort_unstable();
    std::time::Duration::from_nanos(gaps[gaps.len() / 2])
}

/// Renders the post-mortem for the archived ring in `archive_dir/<id>/`. With `live` false the
/// event logs and hardware are not read, which is faster and is what the tests use.
pub fn analyze(archive_dir: &Path, id: &IncidentId, data_dir: &Path, live: bool) -> Result<String, String> {
    let ring = archive_dir.join(&id.0).join("ring.bin");
    let reader = RingReader::open(&ring).map_err(|e| format!("cannot read {}: {e}", ring.display()))?;
    let records = reader.records();
    let mut input = PostMortemInput::default();
    let mut notes: Vec<String> = Vec::new();
    if reader.skipped_corrupt() > 0 {
        notes.push(format!("{} corrupt frame(s) in the archived ring were skipped", reader.skipped_corrupt()));
    }

    let interval = heartbeat_interval(&records);
    let mut timeline = build_timeline(&records, &[], interval);
    let last = timeline.last_sample_taken;

    // Samples of the newest boot: the last 15 minutes against everything earlier.
    let boot = records.last().map(|r| r.boot);
    let samples: Vec<(u64, u64, Sample)> = records
        .iter()
        .filter(|r| Some(r.boot) == boot && r.kind == RecordKind::Sample)
        .filter_map(|r| Sample::decode(&r.payload).ok().map(|s| (r.seq, r.mono_ns, s)))
        .collect();
    if let Some(&(_, last_mono, _)) = samples.last() {
        let cut = last_mono.saturating_sub(LOOKBACK_NS as u64);
        let (win, base): (Vec<_>, Vec<_>) = samples.iter().partition(|(_, m, _)| *m >= cut);
        let stamp = |v: Vec<&(u64, u64, Sample)>| v.into_iter().map(|(seq, _, s)| Stamped { seq: *seq, sample: s.clone() }).collect::<Vec<_>>();
        input.sensors_available = win.iter().any(|(_, _, s)| matches!(s.sensors, Reading::Value { .. }));
        input.divergences = diverged_metrics(&stamp(win), &stamp(base), 3.0);
    }

    if live {
        if let Some(last) = last {
            let events_after = collect_events(&["System"], last.utc_ns, last.utc_ns + AFTER_NS, 5);
            timeline = build_timeline(&records, &events_after.0, interval);
            notes.extend(events_after.1);

            let win = IncidentWindow { start_utc_ns: last.utc_ns - LOOKBACK_NS, end_utc_ns: last.utc_ns };
            let channels = crate::common::default_channels();
            let (before, n) = collect_events(channels, win.start_utc_ns, win.end_utc_ns, 3);
            notes.extend(n);
            let (prior, n) = collect_events(&["System", "Application"], win.start_utc_ns - HISTORY_NS, win.start_utc_ns, 3);
            notes.extend(n);
            let rules = load_rules(data_dir)?;
            let (surfaced, suppressed) = split(triage(group(&before), &rules, Some(&win), &history_of(&prior)));
            input.surfaced_groups = surfaced;
            input.suppressed_summary = suppressed;

            match update_timeline_with_notes(last.utc_ns - HISTORY_NS, last.utc_ns) {
                Ok((events, n)) => {
                    input.install_loops = detect_install_loops(&events, 5, std::time::Duration::from_secs(24 * 3600));
                    input.update_events = events;
                    notes.extend(n);
                }
                Err(e) => notes.push(format!("update timeline not read: {e}")),
            }
        }
        input.hardware = HardwareContext::collect();
    } else {
        notes.push("event logs and hardware were not read (--no-events)".into());
    }
    input.timeline = timeline;
    input.hardware.notes.extend(notes);
    Ok(render_postmortem(&input))
}

fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("txt.tmp");
    fs::write(&tmp, text).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot move {} into place: {e}", tmp.display()))
}

/// Analyzes one incident, writes `postmortem.txt` beside its ring and marks it `Analyzed`.
fn process(archive_dir: &Path, meta: &IncidentMeta, data_dir: &Path, live: bool) -> Result<String, String> {
    let text = analyze(archive_dir, &meta.id, data_dir, live)?;
    write_atomic(&archive_dir.join(&meta.id.0).join("postmortem.txt"), &text)?;
    set_state(archive_dir, &meta.id, IncidentState::Analyzed).map_err(|e| format!("cannot mark {} analyzed: {e}", meta.id.0))?;
    Ok(text)
}

/// `--auto`: every `Archived` incident. A second run finds none and changes nothing.
pub fn run_auto(archive_dir: &Path, data_dir: &Path, live: bool) -> Result<(), String> {
    let pending: Vec<IncidentMeta> = list_incidents(archive_dir).into_iter().filter(|m| m.state == IncidentState::Archived).collect();
    if pending.is_empty() {
        println!("No incidents waiting for analysis.");
        return Ok(());
    }
    let mut failed = 0;
    for m in &pending {
        match process(archive_dir, m, data_dir, live) {
            Ok(_) => println!("Analyzed {} -> {}", m.id.0, archive_dir.join(&m.id.0).join("postmortem.txt").display()),
            Err(e) => {
                failed += 1;
                eprintln!("wsg: {}: {e}", m.id.0);
            }
        }
    }
    if failed > 0 { Err(format!("{failed} of {} incidents could not be analyzed", pending.len())) } else { Ok(()) }
}

/// A named incident, or the newest one, re-rendered and printed.
pub fn run_one(archive_dir: &Path, data_dir: &Path, incident: Option<&str>, live: bool) -> Result<(), String> {
    let all = list_incidents(archive_dir);
    let meta = match incident {
        Some(id) => all.into_iter().find(|m| m.id.0 == id).ok_or_else(|| format!("no incident {id:?} in {}", archive_dir.display()))?,
        None => all.into_iter().last().ok_or_else(|| format!("no incidents in {}", archive_dir.display()))?,
    };
    let text = process(archive_dir, &meta, data_dir, live)?;
    print!("{text}");
    Ok(())
}

