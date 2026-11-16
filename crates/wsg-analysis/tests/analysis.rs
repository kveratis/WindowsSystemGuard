use std::collections::HashSet;

use wsg_analysis::{compare, diverged_metrics, HardwareContext, Stamped, WindowSummary};
use wsg_core::{DiskStats, MemStats, ProcStat, Reading, Sample, SensorSet};
use wsg_events::GroupKey;

fn val<T>(v: T) -> Reading<T> {
    Reading::Value { v, age_ms: 0 }
}

fn unavailable<T>() -> Reading<T> {
    Reading::Unavailable { reason: "test".into() }
}

fn empty() -> Sample {
    Sample {
        cpu: unavailable(),
        mem: unavailable(),
        disks: unavailable(),
        net: unavailable(),
        procs: vec![],
        gpu: unavailable(),
        sensors: unavailable(),
        wsl_vm_running: unavailable(),
        cycle_ms: 1000,
    }
}

fn disk(read_ms: f32) -> DiskStats {
    DiskStats { disk_id: "0 C:".into(), queue_len: 0.5, read_latency_ms: read_ms, write_latency_ms: 1.0, bytes_per_sec: 0 }
}

fn series(seq0: u64, n: u64, f: impl Fn(u64) -> Sample) -> Vec<Stamped> {
    (0..n).map(|i| Stamped { seq: seq0 + i, sample: f(i) }).collect()
}

fn find<'a>(d: &'a [wsg_analysis::Divergence], metric: &str) -> Option<&'a wsg_analysis::Divergence> {
    d.iter().find(|x| x.metric == metric)
}

#[test]
fn disk_latency_spike_is_reported_with_evidence_seqs() {
    let baseline = series(1, 60, |_| Sample { disks: val(vec![disk(2.0)]), ..empty() });
    let window = series(1000, 10, |i| Sample { disks: val(vec![disk(if i == 3 || i == 7 { 80.0 } else { 2.0 })]), ..empty() });
    let d = diverged_metrics(&window, &baseline, 5.0);
    let m = find(&d, "disk 0 C: read_latency_ms").expect("spike reported");
    assert_eq!((m.baseline_median, m.incident_value), (2.0, 80.0));
    assert_eq!(m.ratio, 40.0);
    assert_eq!(m.evidence_seqs, [1003, 1007]);
    assert!(find(&d, "disk 0 C: write_latency_ms").is_none(), "unchanged metrics are not reported");
    assert_eq!(d[0].metric, "disk 0 C: read_latency_ms", "most diverged first");
}

#[test]
fn unavailable_readings_are_skipped_not_treated_as_zero() {
    // Half the baseline is unavailable. Counted as zero its median would be 0 and 5 ms would
    // look infinite; skipped, the median is 5.
    let baseline = series(1, 40, |i| Sample { disks: if i % 2 == 0 { val(vec![disk(5.0)]) } else { unavailable() }, ..empty() });
    let steady = series(500, 10, |_| Sample { disks: val(vec![disk(6.0)]), ..empty() });
    assert!(diverged_metrics(&steady, &baseline, 2.0).is_empty());
    // A window with nothing available says nothing.
    let none = series(600, 10, |_| empty());
    assert!(diverged_metrics(&none, &baseline, 1.0).is_empty());
    // And nothing to compare against says nothing either.
    assert!(diverged_metrics(&steady, &series(1, 10, |_| empty()), 1.0).is_empty());
}

#[test]
fn no_divergence_above_threshold_returns_empty() {
    let baseline = series(1, 60, |_| Sample { disks: val(vec![disk(2.0)]), ..empty() });
    let window = series(100, 10, |i| Sample { disks: val(vec![disk(2.0 + i as f32 * 0.1)]), ..empty() });
    assert!(diverged_metrics(&window, &baseline, 3.0).is_empty());
    assert!(diverged_metrics(&[], &baseline, 3.0).is_empty());
}

#[test]
fn commit_growth_is_compared_with_growth_over_equal_stretches() {
    let mem = |commit: u64| Sample {
        mem: val(MemStats { commit_bytes: commit, available_bytes: 1 << 30, nonpaged_pool_bytes: 1 << 20, paged_pool_bytes: 1 << 20 }),
        ..empty()
    };
    const GIB: u64 = 1 << 30;
    let baseline = series(1, 100, |i| mem(10 * GIB + i * 1024)); // flat
    let leak = series(500, 10, |i| mem(10 * GIB + i * GIB / 4)); // 2.25 GiB over the window
    let d = diverged_metrics(&leak, &baseline, 5.0);
    let g = find(&d, "mem commit_bytes growth").expect("growth reported");
    assert_eq!(g.evidence_seqs, [500, 509]);
    assert!(g.incident_value > 2.0 * GIB as f64);
    assert!(find(&d, "mem nonpaged_pool_bytes growth").is_none());
    assert!(diverged_metrics(&series(900, 10, |i| mem(10 * GIB + i * 1024)), &baseline, 5.0).is_empty());
}

#[test]
fn per_process_cpu_and_unseen_process_are_reported_and_fans_report_drops() {
    let proc = |name: &str, cpu: f32| ProcStat { pid: 1, name: name.into(), cpu_pct: cpu, working_set_bytes: 0, io_bytes_per_sec: 0, handles: 0 };
    let fan = |rpm: u32| Sensors(rpm);
    #[allow(non_snake_case)]
    fn Sensors(rpm: u32) -> Reading<SensorSet> {
        val(SensorSet { cpu_temp_c: Some(60.0), per_core_clock_mhz: vec![], voltages: vec![], fans_rpm: vec![("CPU".into(), rpm)] })
    }
    let baseline = series(1, 30, |_| Sample { procs: vec![proc("steady.exe", 3.0)], sensors: fan(1200), ..empty() });
    let window = series(100, 5, |i| Sample {
        procs: vec![proc("steady.exe", 3.0), proc("runaway.exe", 40.0 + i as f32)],
        sensors: fan(if i == 4 { 200 } else { 1200 }),
        ..empty()
    });
    let d = diverged_metrics(&window, &baseline, 3.0);
    let r = find(&d, "proc runaway.exe cpu_pct").expect("unseen process reported");
    assert_eq!(r.baseline_median, 0.0);
    assert!(find(&d, "proc steady.exe cpu_pct").is_none());
    let f = find(&d, "sensor fan CPU").expect("fan slowdown reported");
    assert_eq!((f.baseline_median, f.incident_value, f.evidence_seqs.clone()), (1200.0, 200.0, vec![104]));
}

fn key(id: u16) -> GroupKey {
    GroupKey { provider: "Microsoft-Windows-Hyper-V-VmSwitch".into(), event_id: id, version: 0, payload_sig: String::new() }
}

fn win(has: bool, uptime_s: u64, wsl: Option<bool>, changes: &[&str]) -> WindowSummary {
    WindowSummary {
        groups: if has { HashSet::from([key(285)]) } else { HashSet::new() },
        uptime_s,
        wsl_vm_running: wsl,
        config_changes: changes.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn presence_shows_n_of_n_and_m_of_k_with_caveats() {
    let hour = 3600;
    let incident = vec![win(true, 5 * hour, Some(true), &[]); 3];
    let mut quiet = vec![win(true, 5 * hour, Some(true), &[]); 2];
    quiet.extend(vec![win(false, 5 * hour, Some(true), &["driver updated"]); 3]);
    let p = compare(&incident, &quiet, &key(285));
    assert_eq!((p.incident, p.quiet), ((3, 3), (2, 5)));
    assert!(p.caveats.iter().any(|c| c.contains("driver updated")), "{:?}", p.caveats);
    assert!(!p.caveats.iter().any(|c| c.contains("uptime") || c.contains("WSL state differs")), "{:?}", p.caveats);
    let absent = compare(&incident, &quiet, &key(1));
    assert_eq!((absent.incident, absent.quiet), ((0, 3), (0, 5)));
}

#[test]
fn compare_flags_wsl_state_mismatch() {
    let hour = 3600;
    let incident = vec![win(true, 2 * hour, Some(true), &[]); 4];
    let quiet = vec![win(false, 20 * hour, Some(false), &[]); 4];
    let p = compare(&incident, &quiet, &key(285));
    assert!(p.caveats.iter().any(|c| c.contains("WSL state differs") && c.contains("4 of 4 incident") && c.contains("0 of 4 quiet")), "{:?}", p.caveats);
    assert!(p.caveats.iter().any(|c| c.contains("uptime differs")), "{:?}", p.caveats);
    let unknown = compare(&vec![win(true, hour, None, &[]); 3], &vec![win(false, hour, None, &[]); 3], &key(285));
    assert!(unknown.caveats.iter().any(|c| c.contains("unknown")));
    let few = compare(&[win(true, hour, Some(true), &[])], &[], &key(285));
    assert!(few.caveats.iter().any(|c| c.contains("anecdote")));
}

#[test]
fn hardware_context_collects_on_this_machine() {
    let h = HardwareContext::collect();
    eprintln!("{h:#?}");
    assert!(!h.motherboard.is_empty(), "notes: {:?}", h.notes);
    assert!(!h.bios_version.is_empty(), "notes: {:?}", h.notes);
    assert!(!h.dimms.is_empty());
    assert!(h.dimms.iter().all(|d| d.capacity_bytes > 0));
}
