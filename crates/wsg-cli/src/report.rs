//! `wsg report`: triage of the event logs over a window, with no AI.

use std::path::Path;
use std::time::Duration;

use wsg_events::{format_system_time, group, triage, History};

use crate::common::{collect_events, default_channels, load_rules, now_ns, split};

fn one_line(s: &str, max: usize) -> String {
    let t = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > max { format!("{}...", t.chars().take(max).collect::<String>()) } else { t }
}

pub fn run(data_dir: &Path, since: Duration, max_level: u8, top: usize) -> Result<String, String> {
    let rules = load_rules(data_dir)?;
    let to = now_ns();
    let from = to - since.as_nanos() as i64;
    let (events, notes) = collect_events(default_channels(), from, to, max_level);
    let groups = group(&events);
    let total_groups = groups.len();
    let (surfaced, suppressed) = split(triage(groups, &rules, None, &History::default()));

    let mut o = String::new();
    o.push_str(&format!(
        "Triage of {} to {} (level {max_level} and worse)\n",
        format_system_time(from),
        format_system_time(to)
    ));
    o.push_str(&format!(
        "{} events in window, {total_groups} groups: {} surfaced, {} suppressed as known noise\n",
        events.len(),
        surfaced.len(),
        total_groups - surfaced.len()
    ));
    for n in &notes {
        o.push_str(&format!("note: {n}\n"));
    }
    o.push_str("Novelty is not scored here: there is no earlier period to compare against.\n\nSURFACED, most worth reading first\n");
    if surfaced.is_empty() {
        o.push_str("  None.\n");
    }
    for (g, score) in surfaced.iter().take(top) {
        o.push_str(&format!(
            "  [{score:.1}] {} event {}: {} time(s), first {}, last {}\n",
            g.key.provider,
            g.key.event_id,
            g.count,
            format_system_time(g.first_utc_ns),
            format_system_time(g.last_utc_ns)
        ));
        if let Some(m) = &g.sample.rendered_message {
            o.push_str(&format!("      {}\n", one_line(m, 200)));
        }
    }
    if surfaced.len() > top {
        o.push_str(&format!("  ... and {} more; raise --top to see them.\n", surfaced.len() - top));
    }
    if !suppressed.is_empty() {
        o.push_str("\nSUPPRESSED (counts only; `wsg noise list` shows the rules)\n");
        for (rule, n) in &suppressed {
            o.push_str(&format!("  {rule}: {n} event(s)\n"));
        }
    }
    Ok(o)
}
