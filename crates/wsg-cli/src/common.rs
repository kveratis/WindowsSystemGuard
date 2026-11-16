//! Helpers the subcommands share.

use std::path::{Path, PathBuf};
use std::time::Duration;

use wsg_events::{
    group, inventory_channels, query, Disposition, EventGroup, EventRecord, GroupKey, History, NoiseRules, Triaged,
    DEFAULT_CHANNELS,
};

pub const NS: i64 = 1_000_000_000;

pub fn default_data_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into())).join("WindowsSystemGuard")
}

/// `90s`, `15m`, `12h` or `14d`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(|| format!("{s:?} needs a unit: s, m, h or d"))?;
    let (n, unit) = s.split_at(split);
    let n: u64 = n.parse().map_err(|_| format!("{s:?} does not start with a number"))?;
    let secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(format!("unknown unit {unit:?} in {s:?}: use s, m, h or d")),
    };
    Ok(Duration::from_secs(n * secs))
}

pub fn noise_path(data_dir: &Path) -> PathBuf {
    data_dir.join("noise.toml")
}

/// The built-in rules followed by the user's own, if any.
pub fn load_rules(data_dir: &Path) -> Result<NoiseRules, String> {
    let mut rules = NoiseRules::builtin();
    let p = noise_path(data_dir);
    if p.exists() {
        rules.rules.extend(NoiseRules::load(&p).map_err(|e| e.to_string())?.rules);
    }
    Ok(rules)
}

/// Events from every readable default channel, plus a note for each channel skipped or failing.
pub fn collect_events(channels: &[&str], from_ns: i64, to_ns: i64, max_level: u8) -> (Vec<EventRecord>, Vec<String>) {
    let (mut events, mut notes) = (Vec::new(), Vec::new());
    for c in inventory_channels(channels) {
        if !c.is_readable() {
            notes.push(format!("channel {} skipped: {:?}", c.name, c.state));
            continue;
        }
        match query(&c.name, from_ns, to_ns, max_level) {
            Ok(v) => events.extend(v),
            Err(e) => notes.push(format!("channel {} not read: {e}", c.name)),
        }
    }
    (events, notes)
}

pub fn default_channels() -> &'static [&'static str] {
    &DEFAULT_CHANNELS
}

/// How often each group occurred in `events`, for scoring novelty.
pub fn history_of(events: &[EventRecord]) -> History {
    History(group(events).into_iter().map(|g| (g.key, g.count)).collect::<std::collections::HashMap<GroupKey, u64>>())
}

/// Surfaced groups with scores, and suppressed event counts by rule.
pub fn split(triaged: Vec<Triaged>) -> (Vec<(EventGroup, f32)>, Vec<(String, u64)>) {
    let mut surfaced = Vec::new();
    let mut suppressed: Vec<(String, u64)> = Vec::new();
    for t in triaged {
        match t.disposition {
            Disposition::Surfaced => surfaced.push((t.group, t.score)),
            Disposition::Suppressed { rule } => match suppressed.iter_mut().find(|(r, _)| *r == rule) {
                Some((_, n)) => *n += t.group.count,
                None => suppressed.push((rule, t.group.count)),
            },
        }
    }
    (surfaced, suppressed)
}

pub fn now_ns() -> i64 {
    wsg_core::now_utc_ns()
}
