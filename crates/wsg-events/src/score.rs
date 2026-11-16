//! Severity scoring and the final suppress-or-surface decision.

use std::collections::HashMap;

use crate::group::{EventGroup, GroupKey};
use crate::noise::{Disposition, NoiseRules};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentWindow {
    pub start_utc_ns: i64,
    pub end_utc_ns: i64,
}

/// How many times each group was seen before the period being triaged.
#[derive(Debug, Clone, Default)]
pub struct History(pub HashMap<GroupKey, u64>);

impl History {
    fn prior(&self, k: &GroupKey) -> u64 {
        self.0.get(k).copied().unwrap_or(0)
    }
}

/// Seconds from the end of an incident at which the proximity bonus has halved.
const PROXIMITY_SCALE_S: f64 = 600.0;

/// Higher is more worth reading. Four parts: severity (a critical beats a warning), frequency
/// (log-scaled, so chatter scores low), novelty (never seen before scores highest) and proximity
/// to the end of the incident window.
pub fn score(g: &EventGroup, incident: Option<&IncidentWindow>, history: &History) -> f32 {
    let level = match g.sample.level {
        1 => 4.0,
        0 | 2 => 3.0,
        3 => 2.0,
        4 => 0.5,
        _ => 0.0,
    };
    let frequency = 2.0 / (1.0 + (g.count.max(1) as f64).ln());
    let prior = history.prior(&g.key);
    let novelty = if prior == 0 { 3.0 } else { 1.0 / (1.0 + (1.0 + prior as f64).ln()) };
    let proximity = incident.map_or(0.0, |w| 3.0 / (1.0 + distance_s(g, w) / PROXIMITY_SCALE_S));
    (level + frequency + novelty + proximity) as f32
}

/// Seconds between the group's nearest occurrence and the incident end. The first and last
/// occurrences count even when the capped timestamp list no longer holds them.
fn distance_s(g: &EventGroup, w: &IncidentWindow) -> f64 {
    let nearest = g
        .times_utc_ns
        .iter()
        .copied()
        .chain([g.first_utc_ns, g.last_utc_ns])
        .min_by_key(|t| t.abs_diff(w.end_utc_ns))
        .unwrap_or(g.last_utc_ns);
    nearest.abs_diff(w.end_utc_ns) as f64 / 1e9
}

fn in_window(g: &EventGroup, w: &IncidentWindow) -> bool {
    g.last_utc_ns >= w.start_utc_ns && g.first_utc_ns <= w.end_utc_ns
}

#[derive(Debug, Clone)]
pub struct Triaged {
    pub group: EventGroup,
    pub disposition: Disposition,
    pub score: f32,
}

/// Classifies and scores every group, highest score first. A rule never hides a group that is
/// new to `history` and occurs inside the incident window: a rare precursor is surfaced even if
/// a rule would normally call that provider and id noise.
pub fn triage(
    groups: Vec<EventGroup>,
    rules: &NoiseRules,
    incident: Option<&IncidentWindow>,
    history: &History,
) -> Vec<Triaged> {
    let mut out: Vec<Triaged> = groups
        .into_iter()
        .map(|g| {
            let novel_in_incident = incident.is_some_and(|w| in_window(&g, w)) && history.prior(&g.key) == 0;
            let disposition = if novel_in_incident { Disposition::Surfaced } else { rules.classify(&g) };
            let s = score(&g, incident, history);
            Triaged { group: g, disposition, score: s }
        })
        .collect();
    out.sort_by(|a, b| b.score.total_cmp(&a.score));
    out
}
