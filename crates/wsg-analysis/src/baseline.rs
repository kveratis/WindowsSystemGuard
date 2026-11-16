//! Is an event really tied to freezes? Count it in incident windows and in quiet ones, and say
//! how the two kinds of window differ, so the counts are not over-read.

use std::collections::HashSet;

use wsg_events::GroupKey;

/// What one stretch of time (an incident window or a freeze-free window) looked like.
#[derive(Debug, Clone, Default)]
pub struct WindowSummary {
    pub groups: HashSet<GroupKey>,
    pub uptime_s: u64,
    /// Whether the WSL VM was running; `None` when the recorder could not tell.
    pub wsl_vm_running: Option<bool>,
    pub config_changes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presence {
    /// (windows containing the group, windows)
    pub incident: (u32, u32),
    pub quiet: (u32, u32),
    /// Reasons the two counts may not be comparable.
    pub caveats: Vec<String>,
}

/// Windows that are fewer than this make any count anecdotal.
const MIN_WINDOWS: usize = 3;

pub fn compare(incident_windows: &[WindowSummary], quiet_windows: &[WindowSummary], key: &GroupKey) -> Presence {
    let count = |w: &[WindowSummary]| (w.iter().filter(|s| s.groups.contains(key)).count() as u32, w.len() as u32);
    let mut caveats = Vec::new();

    if incident_windows.len() < MIN_WINDOWS || quiet_windows.len() < MIN_WINDOWS {
        caveats.push(format!(
            "only {} incident and {} quiet windows; fewer than {MIN_WINDOWS} on either side is anecdote, not a pattern",
            incident_windows.len(),
            quiet_windows.len()
        ));
    }

    let (ia, qa) = (mean_uptime(incident_windows), mean_uptime(quiet_windows));
    if let (Some(i), Some(q)) = (ia, qa) {
        if i > q * 2.0 || q > i * 2.0 {
            caveats.push(format!(
                "uptime differs: incident windows averaged {} and quiet windows {}, so one side had far longer to log the event",
                hours(i),
                hours(q)
            ));
        }
    }

    let (iw, qw) = (wsl_counts(incident_windows), wsl_counts(quiet_windows));
    let share = |c: (u32, u32, u32)| if c.0 + c.1 == 0 { None } else { Some(c.0 as f64 / (c.0 + c.1) as f64) };
    if let (Some(i), Some(q)) = (share(iw), share(qw)) {
        if (i - q).abs() > 0.25 {
            caveats.push(format!(
                "WSL state differs: the VM was running in {} of {} incident windows but {} of {} quiet windows",
                iw.0,
                iw.0 + iw.1,
                qw.0,
                qw.0 + qw.1
            ));
        }
    }
    if iw.2 + qw.2 > 0 {
        caveats.push(format!("WSL state unknown in {} incident and {} quiet windows", iw.2, qw.2));
    }

    let mut changes: Vec<&str> = incident_windows
        .iter()
        .chain(quiet_windows)
        .flat_map(|w| w.config_changes.iter().map(String::as_str))
        .collect();
    changes.sort_unstable();
    changes.dedup();
    if !changes.is_empty() {
        caveats.push(format!("configuration changed during these windows: {}", changes.join("; ")));
    }

    Presence { incident: count(incident_windows), quiet: count(quiet_windows), caveats }
}

fn mean_uptime(w: &[WindowSummary]) -> Option<f64> {
    (!w.is_empty()).then(|| w.iter().map(|s| s.uptime_s as f64).sum::<f64>() / w.len() as f64)
}

fn hours(s: f64) -> String {
    format!("{:.1} h", s / 3600.0)
}

/// (running, not running, unknown)
fn wsl_counts(w: &[WindowSummary]) -> (u32, u32, u32) {
    w.iter().fold((0, 0, 0), |c, s| match s.wsl_vm_running {
        Some(true) => (c.0 + 1, c.1, c.2),
        Some(false) => (c.0, c.1 + 1, c.2),
        None => (c.0, c.1, c.2 + 1),
    })
}
