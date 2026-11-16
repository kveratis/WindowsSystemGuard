//! The post-mortem as plain text. It says what the evidence shows, what it cannot show, and what
//! to check outside the recorder.

use std::fmt::Write;

use wsg_core::{HelperStats, WriterStats};
use wsg_events::updates::{InstallLoop, UpdateEvent, UpdateKind};
use wsg_events::{format_system_time, EventGroup, GroupKey};

use crate::baseline::Presence;
use crate::diverge::Divergence;
use crate::hardware::HardwareContext;
use crate::timeline::{IncidentTimeline, Stamp};

#[derive(Debug, Clone, Default)]
pub struct PostMortemInput {
    pub timeline: IncidentTimeline,
    pub divergences: Vec<Divergence>,
    /// Groups worth reading with their score, best first.
    pub surfaced_groups: Vec<(EventGroup, f32)>,
    /// Suppressed noise as (rule name, events); counts only.
    pub suppressed_summary: Vec<(String, u64)>,
    pub update_events: Vec<UpdateEvent>,
    pub install_loops: Vec<InstallLoop>,
    pub presence: Vec<(GroupKey, Presence)>,
    pub hardware: HardwareContext,
    pub writer_stats: Option<WriterStats>,
    /// Isolated helpers by name ("gpu", "sensors").
    pub helper_stats: Vec<(String, HelperStats)>,
    pub sensors_available: bool,
}

const MAX_GROUPS: usize = 20;
const MAX_UPDATES: usize = 15;

fn when(ns: i64) -> String {
    format_system_time(ns)
}

fn stamp(s: &Stamp) -> String {
    let mut out = when(s.utc_ns);
    if let Some(seq) = s.seq {
        let _ = write!(out, " (record {seq})");
    }
    out
}

fn line(out: &mut String, text: impl AsRef<str>) {
    out.push_str(text.as_ref());
    out.push('\n');
}

fn heading(out: &mut String, title: &str) {
    out.push('\n');
    line(out, title.to_uppercase());
    line(out, "-".repeat(title.len()));
}

/// One line, at most `max` characters.
fn short(s: &str, max: usize) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() <= max {
        one
    } else {
        format!("{}...", one.chars().take(max).collect::<String>())
    }
}

pub fn render_postmortem(i: &PostMortemInput) -> String {
    let mut o = String::new();
    let t = &i.timeline;

    if i.divergences.is_empty() {
        let mut head = String::from("Cause undetermined. No recorded metric diverged from its baseline");
        if t.freeze_onset_estimate.is_some() {
            head.push_str("; heartbeats stopped, which shows the machine stopped making progress, not why");
        } else {
            head.push_str(" and the recorder shows no heartbeat gap");
        }
        head.push('.');
        line(&mut o, head);
    } else {
        line(
            &mut o,
            format!(
                "{} metric(s) diverged from baseline before the last recorded sample. These are leads, not a proven cause.",
                i.divergences.len()
            ),
        );
    }

    heading(&mut o, "Timeline");
    if t.ring_ended_cleanly {
        line(&mut o, "The recorder ended cleanly (clean-shutdown marker present). This is not an unclean shutdown.");
    }
    let row = |o: &mut String, label: &str, s: &Option<Stamp>, note: &str| match s {
        Some(s) => line(o, format!("  {label}: {}. {note}", stamp(s))),
        None => line(o, format!("  {label}: not recorded.")),
    };
    row(&mut o, "Last sample taken", &t.last_sample_taken, "The last cycle the recorder started.");
    row(
        &mut o,
        "Last sample persisted",
        &t.last_sample_persisted,
        "The last complete sample in the ring; it can trail the line above if the machine stopped mid-cycle. Neither proves the bytes reached the disk surface.",
    );
    row(
        &mut o,
        "Freeze onset estimate",
        &t.freeze_onset_estimate,
        "Heartbeats stopped or slowed for good after this, to within about one interval. A heartbeat gap shows missing progress, not a cause.",
    );
    row(&mut o, "Forced power-off", &t.forced_power_off, "Time the power button was held, from Kernel-Power 41.");
    row(
        &mut o,
        "Next boot",
        &t.next_boot,
        "First unclean-shutdown report (Kernel-Power 41 or EventLog 6008). It is logged during the next boot, so it bounds the restart, not the freeze.",
    );
    if t.recorder_crash_suspected {
        line(
            &mut o,
            "  The ring has no clean marker, but Windows shut down normally or reported the recorder service crashed. The recorder, not the machine, most likely stopped.",
        );
    }

    heading(&mut o, "What changed before the freeze");
    if i.divergences.is_empty() {
        line(&mut o, "  Nothing recorded moved away from its baseline.");
    }
    for d in &i.divergences {
        let seqs: Vec<String> = d.evidence_seqs.iter().map(u64::to_string).collect();
        line(
            &mut o,
            format!(
                "  {}: {:.1}x baseline (baseline median {:.2}, worst in window {:.2}). Evidence records: {}",
                d.metric,
                d.ratio,
                d.baseline_median,
                d.incident_value,
                seqs.join(", ")
            ),
        );
    }

    heading(&mut o, "Surfaced events");
    if i.surfaced_groups.is_empty() {
        line(&mut o, "  None.");
    }
    for (g, score) in i.surfaced_groups.iter().take(MAX_GROUPS) {
        line(
            &mut o,
            format!(
                "  [{score:.1}] {} event {} (version {}): {} time(s), first {}, last {}",
                g.key.provider,
                g.key.event_id,
                g.key.version,
                g.count,
                when(g.first_utc_ns),
                when(g.last_utc_ns)
            ),
        );
        match &g.sample.rendered_message {
            Some(m) => line(&mut o, format!("      {}", short(m, 200))),
            None => {
                let fields: Vec<String> = g.sample.payload.iter().take(4).map(|(k, v)| format!("{k}={}", short(v, 60))).collect();
                if !fields.is_empty() {
                    line(&mut o, format!("      no message text; {}", fields.join(", ")));
                }
            }
        }
    }
    if i.surfaced_groups.len() > MAX_GROUPS {
        line(&mut o, format!("  ... and {} more not shown.", i.surfaced_groups.len() - MAX_GROUPS));
    }
    if !i.suppressed_summary.is_empty() {
        line(&mut o, "  Suppressed as known noise (counts only; the evidence is kept):");
        for (rule, n) in &i.suppressed_summary {
            line(&mut o, format!("    {rule}: {n} event(s)"));
        }
    }

    heading(&mut o, "Updates and install loops");
    if i.install_loops.is_empty() {
        line(&mut o, "  No package or driver was installed repeatedly.");
    }
    for l in &i.install_loops {
        line(
            &mut o,
            format!("  {} installed {} times between {} and {}", l.name, l.count, when(l.first_utc_ns), when(l.last_utc_ns)),
        );
    }
    let finished: Vec<&UpdateEvent> = i.update_events.iter().filter(|u| u.kind != UpdateKind::Started).collect();
    line(&mut o, format!("  {} update, hotfix and driver event(s) in the window; the latest:", finished.len()));
    for u in finished.iter().rev().take(MAX_UPDATES) {
        let what = match &u.kind {
            UpdateKind::Failed { code } => format!("failed ({code})"),
            UpdateKind::Succeeded => "installed".into(),
            UpdateKind::Hotfix => "hotfix".into(),
            UpdateKind::DriverInstall => "driver configured".into(),
            UpdateKind::Started => "started".into(),
        };
        line(&mut o, format!("    {} {what}: {}", when(u.utc_ns), short(&u.name, 80)));
    }

    if !i.presence.is_empty() {
        heading(&mut o, "Is it tied to freezes?");
        for (k, p) in &i.presence {
            line(
                &mut o,
                format!(
                    "  {} event {}: in {} of {} incident windows, {} of {} quiet windows",
                    k.provider, k.event_id, p.incident.0, p.incident.1, p.quiet.0, p.quiet.1
                ),
            );
            for c in &p.caveats {
                line(&mut o, format!("      caveat: {c}"));
            }
        }
    }

    heading(&mut o, "Hardware context");
    let h = &i.hardware;
    let or = |s: &str| if s.is_empty() { "unknown".to_string() } else { s.to_string() };
    line(&mut o, format!("  Motherboard: {}", or(&h.motherboard)));
    line(&mut o, format!("  BIOS version: {}", or(&h.bios_version)));
    line(&mut o, format!("  Chipset: {}", h.chipset.as_deref().unwrap_or("not reported by Windows")));
    line(&mut o, format!("  AGESA: {}", h.agesa.as_deref().unwrap_or("not reported by Windows; read it on the BIOS screen")));
    for d in &h.dimms {
        let gib = d.capacity_bytes as f64 / (1u64 << 30) as f64;
        let mhz = |v: Option<u32>| v.map_or("?".to_string(), |n| n.to_string());
        line(
            &mut o,
            format!("  Memory {}: {gib:.0} GiB {} rated {} MT/s, running at {} MT/s", d.slot, or(&d.part_number), mhz(d.rated_mhz), mhz(d.configured_mhz)),
        );
    }
    line(
        &mut o,
        match h.xmp_docp_enabled {
            Some(true) => "  XMP/DOCP: memory runs above the DDR4 standard's top speed, so a profile or overclock is active.".to_string(),
            _ => "  XMP/DOCP: Windows cannot report this. Compare the running speed above with the speed printed on the memory kit.".to_string(),
        },
    );
    if !h.recent_driver_changes.is_empty() {
        line(&mut o, "  Drivers updated in the last 14 days:");
        for c in h.recent_driver_changes.iter().rev().take(MAX_UPDATES) {
            line(&mut o, format!("    {c}"));
        }
    }
    for n in &h.notes {
        line(&mut o, format!("  note: {n}"));
    }

    heading(&mut o, "Evidence quality");
    match &i.writer_stats {
        Some(w) => {
            line(&mut o, format!("  Records lost before reaching a ring: {}.", w.dropped));
            if w.fallback_active {
                line(&mut o, "  The primary ring was not being written; the fallback ring took over.");
            }
            if w.primary_stalls > 0 {
                line(&mut o, format!("  The primary ring stalled {} time(s).", w.primary_stalls));
            }
            if w.memory_only {
                line(&mut o, "  The latest records reached neither ring and were held only in memory, so they are lost.");
            }
        }
        None => line(&mut o, "  Writer health was not available."),
    }
    for (name, s) in &i.helper_stats {
        let mut text = format!("  Helper {name}: {} restart(s)", s.restarts);
        if s.abandoned {
            text.push_str(", given up on (no data from it after that)");
        }
        if let Some(t) = s.last_stall_utc_ns {
            let _ = write!(text, ", last stall {}", when(t));
        }
        line(&mut o, text);
    }
    if !i.sensors_available {
        line(
            &mut o,
            "  Temperature, voltage and fan data were not recorded. Install and run LibreHardwareMonitor or HWiNFO to get thermal and power evidence.",
        );
    }
    line(&mut o, "  Samples are 2 to 5 seconds apart and cannot show a brief voltage or power excursion.");
    line(&mut o, "  The recorder runs in user mode; a hang of the whole kernel stops it too, so it can show that progress stopped but not why.");

    heading(&mut o, "Checks outside the recorder");
    for (n, c) in [
        "Dumps: set a complete or kernel memory dump, make sure the pagefile and free disk space allow it, and enable the keyboard crash trigger (CrashOnCtrlScroll). A freeze at high IRQL can defeat the keyboard trigger; if the board has an NMI or reset header, note it.",
        "BIOS: update to the newest BIOS and AGESA for the board and note the version.",
        "XMP/DOCP: confirm in the BIOS whether the memory profile is on, then retest with it off at the default speed.",
        "PSU: check the power supply and its cables; try a known good unit if the freezes continue.",
        "RAM: run a full memory test (MemTest86 or similar) for several passes.",
        "WSL: run `wsl --shutdown` for a few days and see whether the freezes stop. This is an experiment, not a fix, and the tool never requires it.",
    ]
    .iter()
    .enumerate()
    {
        line(&mut o, format!("  {}. {c}", n + 1));
    }
    o
}
