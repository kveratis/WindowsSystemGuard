use std::time::Duration;
use wsg_core::sample::Reading;
use wsg_recorder::collectors::*;

struct Slow;
impl Collector for Slow {
    fn name(&self) -> &'static str {
        "slow"
    }
    fn collect(&mut self, _budget: Duration) -> CollectOutcome {
        std::thread::sleep(Duration::from_millis(100));
        CollectOutcome::Unavailable("late".into())
    }
}

fn frag(o: CollectOutcome) -> SampleFragment {
    match o {
        CollectOutcome::Ok(f) => f,
        CollectOutcome::Unavailable(r) => panic!("unavailable: {r}"),
        CollectOutcome::TimedOut => panic!("timed out"),
    }
}

#[test]
fn assemble_marks_missing_fragments_unavailable_not_zero() {
    let s = assemble(
        vec![SampleFragment::Heartbeat { counter: 1, mono_ns: 2 }],
        250,
    );
    assert_eq!(s.cycle_ms, 250);
    assert!(matches!(s.cpu, Reading::Unavailable { ref reason } if reason == "no collector result"));
    assert!(matches!(s.mem, Reading::Unavailable { .. }));
    assert!(matches!(s.gpu, Reading::Unavailable { .. }));
    assert!(matches!(s.sensors, Reading::Unavailable { .. }));
    assert!(matches!(s.wsl_vm_running, Reading::Unavailable { .. }));
    assert!(s.disks.is_empty() && s.net.is_empty() && s.procs.is_empty());
}

#[test]
fn process_collector_returns_at_most_top_n_and_includes_self() {
    let mut c = ProcessCollector::new(5);
    let b = Duration::from_secs(5);
    c.collect(b);
    std::thread::sleep(Duration::from_millis(200));
    let s = assemble(vec![frag(c.collect(b))], 1000);
    assert!(s.procs.len() <= 5 && !s.procs.is_empty());
    assert!(s.procs.iter().any(|p| p.pid == std::process::id()));
    eprintln!("enumeration_ms={}", c.last_enumeration_ms());
    assert!(c.last_enumeration_ms() < 5000);
}

#[test]
fn counter_collector_returns_values_on_this_machine() {
    let mut c = CounterCollector::new().expect("pdh");
    let b = Duration::from_secs(5);
    c.collect(b);
    std::thread::sleep(Duration::from_millis(500));
    let s = assemble(vec![frag(c.collect(b))], 1000);
    match s.cpu {
        Reading::Value { v, .. } => {
            assert!((0.0..=100.0).contains(&v.total_pct), "{}", v.total_pct)
        }
        Reading::Unavailable { reason } => panic!("cpu unavailable: {reason}"),
    }
    assert!(matches!(s.mem, Reading::Value { ref v, .. } if v.available_bytes > 0));
}

#[test]
fn collector_over_budget_returns_timed_out() {
    let mut c = Slow;
    assert!(matches!(
        run_with_budget(&mut c, Duration::from_millis(10)),
        CollectOutcome::TimedOut
    ));
}

#[test]
fn wsl_collector_reports_bool_or_unavailable() {
    let mut c = WslCollector::new();
    match c.collect(Duration::from_secs(5)) {
        CollectOutcome::Ok(SampleFragment::Wsl(Reading::Value { .. })) => {}
        CollectOutcome::Unavailable(_) => {}
        _ => panic!("unexpected outcome"),
    }
}
