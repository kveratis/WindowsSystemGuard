//! Which recorded metrics moved away from their usual level during an incident window.

use std::collections::{BTreeMap, BTreeSet};

use wsg_core::{Reading, Sample};

/// A decoded sample with the ring `seq` of the record it came from, so evidence can be cited.
#[derive(Debug, Clone)]
pub struct Stamped {
    pub seq: u64,
    pub sample: Sample,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Divergence {
    pub metric: String,
    pub baseline_median: f64,
    /// The most extreme value in the window (for growth metrics, the growth across it).
    pub incident_value: f64,
    pub ratio: f64,
    /// Records in the window whose value was itself at or beyond `min_ratio`, at most `MAX_EVIDENCE`.
    pub evidence_seqs: Vec<u64>,
}

/// Most evidence sequence numbers kept per metric.
pub const MAX_EVIDENCE: usize = 20;

#[derive(Clone, Copy)]
enum Direction {
    /// Higher is worse.
    Rise,
    /// Lower is worse (a fan slowing down).
    Drop,
    /// Either way is worse (a voltage).
    Both,
}

const MIB: f64 = 1024.0 * 1024.0;

/// Metrics whose level matters, with the direction that is worse and the smallest baseline worth
/// dividing by (so a baseline of 0.01 ms does not make 1 ms a hundredfold spike).
fn spec(metric: &str) -> (Direction, f64) {
    match metric {
        m if m.starts_with("sensor fan ") => (Direction::Drop, 1.0),
        m if m.starts_with("sensor voltage ") => (Direction::Both, 0.01),
        m if m.ends_with("io_bytes_per_sec") => (Direction::Rise, MIB),
        _ => (Direction::Rise, 1.0),
    }
}

fn ratio_of(v: f64, median: f64, dir: Direction, floor: f64) -> f64 {
    let base = median.max(floor);
    match dir {
        Direction::Rise => v / base,
        Direction::Drop if median <= 0.0 => 0.0,
        Direction::Drop => median / v.max(floor),
        Direction::Both => (v.max(floor) / base).max(base / v.max(floor)),
    }
}

/// One value per metric per sample. Unavailable readings contribute nothing, never a zero.
fn levels(s: &Sample) -> Vec<(String, f64)> {
    let mut out = Vec::new();
    if let Reading::Value { v, .. } = &s.cpu {
        out.push(("cpu dpc_pct".to_string(), v.dpc_pct as f64));
        out.push(("cpu interrupt_pct".to_string(), v.interrupt_pct as f64));
    }
    if let Reading::Value { v: disks, .. } = &s.disks {
        for d in disks {
            out.push((format!("disk {} read_latency_ms", d.disk_id), d.read_latency_ms as f64));
            out.push((format!("disk {} write_latency_ms", d.disk_id), d.write_latency_ms as f64));
            out.push((format!("disk {} queue_len", d.disk_id), d.queue_len as f64));
        }
    }
    // Per process name, summed over its instances. The list holds only the busiest processes, so
    // a process missing from a sample is "not in the top list", never a zero.
    let mut procs: BTreeMap<&str, (f64, f64)> = BTreeMap::new();
    for p in &s.procs {
        let e = procs.entry(p.name.as_str()).or_default();
        e.0 += p.cpu_pct as f64;
        e.1 += p.io_bytes_per_sec as f64;
    }
    for (name, (cpu, io)) in procs {
        out.push((format!("proc {name} cpu_pct"), cpu));
        out.push((format!("proc {name} io_bytes_per_sec"), io));
    }
    if let Reading::Value { v, .. } = &s.gpu {
        out.push(("gpu util_pct".to_string(), v.util_pct as f64));
        out.push(("gpu temp_c".to_string(), v.temp_c as f64));
    }
    if let Reading::Value { v, .. } = &s.sensors {
        if let Some(t) = v.cpu_temp_c {
            out.push(("sensor cpu_temp_c".to_string(), t as f64));
        }
        for (n, volts) in &v.voltages {
            out.push((format!("sensor voltage {n}"), *volts as f64));
        }
        for (n, rpm) in &v.fans_rpm {
            out.push((format!("sensor fan {n}"), *rpm as f64));
        }
    }
    out
}

/// Counters that only matter when they keep climbing; the metric is growth across a window.
fn counters(s: &Sample) -> Vec<(&'static str, f64, f64)> {
    match &s.mem {
        Reading::Value { v, .. } => vec![
            ("mem commit_bytes growth", v.commit_bytes as f64, 8.0 * MIB),
            ("mem nonpaged_pool_bytes growth", v.nonpaged_pool_bytes as f64, MIB / 4.0),
            ("mem paged_pool_bytes growth", v.paged_pool_bytes as f64, MIB / 4.0),
        ],
        Reading::Unavailable { .. } => vec![],
    }
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

/// Compares `window` with `baseline` and returns the metrics whose worst value in the window is at
/// least `min_ratio` times the baseline median, most diverged first. A metric with no baseline
/// readings is not reported, except a process absent from the baseline, which is reported against
/// a baseline of 0. Readings that are unavailable are skipped, never counted as zero.
pub fn diverged_metrics(window: &[Stamped], baseline: &[Stamped], min_ratio: f64) -> Vec<Divergence> {
    let mut out = level_divergences(window, baseline, min_ratio);
    out.extend(growth_divergences(window, baseline, min_ratio));
    out.sort_by(|a, b| b.ratio.total_cmp(&a.ratio).then_with(|| a.metric.cmp(&b.metric)));
    out
}

fn level_divergences(window: &[Stamped], baseline: &[Stamped], min_ratio: f64) -> Vec<Divergence> {
    let mut win: BTreeMap<String, Vec<(u64, f64)>> = BTreeMap::new();
    for s in window {
        for (m, v) in levels(&s.sample) {
            win.entry(m).or_default().push((s.seq, v));
        }
    }
    let mut base: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for s in baseline {
        for (m, v) in levels(&s.sample) {
            base.entry(m).or_default().push(v);
        }
    }
    // A process absent from the baseline is a finding only if the baseline recorded processes at
    // all; an empty baseline or one whose process list was unavailable shows nothing about it.
    let baseline_has_procs = baseline.iter().any(|s| !s.sample.procs.is_empty());
    let mut out = Vec::new();
    for (metric, vals) in win {
        let med = match base.get_mut(&metric) {
            Some(b) => median(b),
            None if metric.starts_with("proc ") && baseline_has_procs => 0.0,
            None => continue,
        };
        let (dir, floor) = spec(&metric);
        let ratios: Vec<(u64, f64, f64)> = vals.iter().map(|&(seq, v)| (seq, v, ratio_of(v, med, dir, floor))).collect();
        let Some(&(_, worst_v, worst)) = ratios.iter().max_by(|a, b| a.2.total_cmp(&b.2)) else { continue };
        if worst >= min_ratio {
            let evidence = ratios.iter().filter(|r| r.2 >= min_ratio).map(|r| r.0).take(MAX_EVIDENCE).collect();
            out.push(Divergence { metric, baseline_median: med, incident_value: worst_v, ratio: worst, evidence_seqs: evidence });
        }
    }
    out
}

/// Growth across the window against growth across equally long stretches of the baseline. Only
/// full-length stretches count: a shorter one would show less growth for the same rate. A baseline
/// shorter than the window therefore yields no growth comparison.
fn growth_divergences(window: &[Stamped], baseline: &[Stamped], min_ratio: f64) -> Vec<Divergence> {
    let span = window.len();
    if span < 2 {
        return vec![];
    }
    // metric -> (first, last) available value in a run of samples, with the seqs they came from.
    let growth_of = |run: &[Stamped]| -> BTreeMap<&'static str, (f64, u64, f64, u64, f64)> {
        let mut m: BTreeMap<&'static str, (f64, u64, f64, u64, f64)> = BTreeMap::new();
        for s in run {
            for (name, v, floor) in counters(&s.sample) {
                m.entry(name).and_modify(|e| { e.2 = v; e.3 = s.seq }).or_insert((v, s.seq, v, s.seq, floor));
            }
        }
        m
    };
    let mut base_growth: BTreeMap<&'static str, Vec<f64>> = BTreeMap::new();
    for chunk in baseline.chunks(span).filter(|c| c.len() == span) {
        for (name, (first, _, last, _, _)) in growth_of(chunk) {
            base_growth.entry(name).or_default().push(last - first);
        }
    }
    let mut out = Vec::new();
    for (name, (first, first_seq, last, last_seq, floor)) in growth_of(window) {
        if first_seq == last_seq {
            continue;
        }
        let Some(b) = base_growth.get_mut(name) else { continue };
        let med = median(b);
        let growth = last - first;
        let ratio = growth / med.max(floor);
        if ratio >= min_ratio {
            out.push(Divergence {
                metric: name.to_string(),
                baseline_median: med,
                incident_value: growth,
                ratio,
                evidence_seqs: BTreeSet::from([first_seq, last_seq]).into_iter().collect(),
            });
        }
    }
    out
}
