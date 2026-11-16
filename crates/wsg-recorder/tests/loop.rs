//! Cycle loop and service lifecycle. The API under test is defined by these tests:
//! `cycle::{run_cycle, Clock}`, `service::Session`, `config::load`.

use std::path::Path;
use std::time::{Duration, Instant};

use wsg_core::archive::list_incidents;
use wsg_core::{new_boot_id, BootId, RecordKind, Ring, RingFileSink, RingReader, TieredWriter};
use wsg_recorder::collectors::{CollectOutcome, Collector};
use wsg_recorder::config;
use wsg_recorder::cycle::{run_cycle, Clock};
use wsg_recorder::service::Session;

struct FixedClock;
impl Clock for FixedClock {
    fn utc_ns(&self) -> i64 {
        1_700_000_000_000_000_000
    }
    fn mono_ns(&self) -> u64 {
        42
    }
}

/// Fails every call in a fixed way.
struct Failing(CollectOutcome);
impl Collector for Failing {
    fn name(&self) -> &'static str {
        "failing"
    }
    fn collect(&mut self, _budget: Duration) -> CollectOutcome {
        match &self.0 {
            CollectOutcome::Unavailable(r) => CollectOutcome::Unavailable(r.clone()),
            _ => CollectOutcome::TimedOut,
        }
    }
}

/// Blocks far longer than any cycle; it cannot be cancelled.
struct Hangs;
impl Collector for Hangs {
    fn name(&self) -> &'static str {
        "hangs"
    }
    fn collect(&mut self, _budget: Duration) -> CollectOutcome {
        std::thread::sleep(Duration::from_secs(10));
        CollectOutcome::TimedOut
    }
}

fn writer_on(ring: &Path, boot_dir: &Path) -> TieredWriter {
    let primary = Ring::create(ring, 1 << 20).unwrap();
    let fallback = Ring::create(&boot_dir.join("fallback.bin"), 1 << 20).unwrap();
    TieredWriter::new(
        Box::new(RingFileSink(primary)),
        Box::new(RingFileSink(fallback)),
        Duration::from_secs(1),
        64,
    )
}

fn kinds(ring: &Path) -> Vec<RecordKind> {
    RingReader::open(ring).unwrap().records().iter().map(|r| r.kind).collect()
}

#[test]
fn cycle_writes_heartbeat_even_if_all_collectors_time_out() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let boot = new_boot_id();
    let w = writer_on(&ring, d.path());
    let mut cs: Vec<Box<dyn Collector>> = vec![
        Box::new(Failing(CollectOutcome::TimedOut)),
        Box::new(Failing(CollectOutcome::Unavailable("no counters".into()))),
    ];
    run_cycle(&mut cs, &w, boot, &FixedClock, Duration::from_millis(500), Duration::from_millis(100));
    drop(w); // joins the dispatcher, so everything queued is flushed
    assert!(kinds(&ring).contains(&RecordKind::Heartbeat), "{:?}", kinds(&ring));
}

#[test]
fn cycle_respects_total_deadline() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let w = writer_on(&ring, d.path());
    let interval = Duration::from_millis(500);
    let mut cs: Vec<Box<dyn Collector>> = vec![Box::new(Hangs)];
    let t = Instant::now();
    run_cycle(&mut cs, &w, new_boot_id(), &FixedClock, interval, Duration::from_millis(100));
    assert!(t.elapsed() < interval, "cycle took {:?}", t.elapsed());
    drop(w);
    assert!(kinds(&ring).contains(&RecordKind::Heartbeat));
}

#[test]
fn start_archives_unclean_previous_ring() {
    let d = tempfile::tempdir().unwrap();
    let (ring, archive) = (d.path().join("ring.bin"), d.path().join("archive"));
    let old_boot = BootId([7; 16]);
    {
        // A previous session that never wrote the clean marker.
        let mut r = Ring::create(&ring, 1 << 20).unwrap();
        r.append(RecordKind::Heartbeat, old_boot, 1, 1, b"hb").unwrap();
        r.flush().unwrap();
    }
    let s = Session::start(&ring, &d.path().join("fb.bin"), &archive, new_boot_id()).unwrap();
    assert_eq!(list_incidents(&archive).len(), 1);
    assert!(
        RingReader::open(&ring).unwrap().records().iter().all(|r| r.boot != old_boot),
        "new ring must not contain the old session's records"
    );
    s.stop();
}

#[test]
fn stop_writes_clean_marker() {
    let d = tempfile::tempdir().unwrap();
    let (ring, archive) = (d.path().join("ring.bin"), d.path().join("archive"));
    let s = Session::start(&ring, &d.path().join("fb.bin"), &archive, new_boot_id()).unwrap();
    assert!(!RingReader::open(&ring).unwrap().ended_cleanly());
    s.stop();
    assert!(RingReader::open(&ring).unwrap().ended_cleanly());
    // A clean stop is not an incident on the next start.
    let s2 = Session::start(&ring, &d.path().join("fb.bin"), &archive, new_boot_id()).unwrap();
    assert!(list_incidents(&archive).is_empty());
    s2.stop();
}

#[test]
fn config_from_user_writable_path_is_rejected() {
    // A temp dir is writable by the current user, which the service must not trust.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("config.toml");
    std::fs::write(&p, "interval_ms = 1000\n").unwrap();
    let e = config::load(&p).unwrap_err();
    assert!(e.to_string().contains("writable"), "{e}");
}

fn heartbeat(boot: BootId) -> wsg_core::NewRecord {
    wsg_core::NewRecord { kind: RecordKind::Heartbeat, boot, utc_ns: 1, mono_ns: 1, payload: b"hb".to_vec() }
}

#[test]
fn start_with_primary_unavailable_still_records_to_fallback() {
    let d = tempfile::tempdir().unwrap();
    let (ring, fb) = (d.path().join("no-such-drive").join("ring.bin"), d.path().join("fb.bin"));
    let boot = new_boot_id();
    let s = Session::start(&ring, &fb, &d.path().join("archive"), boot).unwrap();
    assert!(s.primary_error().is_some());
    s.writer().submit(heartbeat(boot));
    s.stop();
    let r = RingReader::open(&fb).unwrap();
    assert!(r.records().iter().any(|r| r.kind == RecordKind::Heartbeat), "{:?}", r.records());
    assert!(r.ended_cleanly(), "marker reaches the fallback too");
}

#[test]
fn previous_fallback_records_are_preserved_not_truncated() {
    let d = tempfile::tempdir().unwrap();
    let (ring, fb, archive) = (d.path().join("ring.bin"), d.path().join("fb.bin"), d.path().join("archive"));
    let old = BootId([9; 16]);
    {
        let mut f = Ring::create(&fb, 1 << 16).unwrap();
        f.append(RecordKind::Heartbeat, old, 1, 1, b"last words").unwrap();
        f.flush().unwrap();
    }
    Session::start(&ring, &fb, &archive, new_boot_id()).unwrap().stop();
    let kept: Vec<_> = std::fs::read_dir(&archive)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("fallback-"))
        .collect();
    assert_eq!(kept.len(), 1);
    let recs = RingReader::open(&kept[0].path()).unwrap().records();
    assert!(recs.iter().any(|r| r.boot == old && r.payload == b"last words"));
}

#[test]
fn collector_failure_reasons_reach_the_sample() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let w = writer_on(&ring, d.path());
    let mut cs: Vec<Box<dyn Collector>> = vec![
        Box::new(Failing(CollectOutcome::Unavailable("PDH 0x800007D1".into()))),
        Box::new(Failing(CollectOutcome::TimedOut)),
    ];
    run_cycle(&mut cs, &w, new_boot_id(), &FixedClock, Duration::from_secs(1), Duration::from_millis(100));
    drop(w);
    let rec = RingReader::open(&ring).unwrap().records().into_iter().find(|r| r.kind == RecordKind::Sample).unwrap();
    let s = wsg_core::Sample::decode(&rec.payload).unwrap();
    let wsg_core::Reading::Unavailable { reason } = s.cpu else { panic!("cpu should be unavailable") };
    assert!(reason.contains("failing: PDH 0x800007D1") && reason.contains("failing: timed out"), "{reason}");
}

#[test]
fn same_ring_and_fallback_path_is_refused_without_touching_the_file() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    Ring::create(&ring, 1 << 20).unwrap();
    let before = std::fs::read(&ring).unwrap();
    let alias = d.path().join(".").join("RING.BIN");
    for fb in [ring.clone(), alias] {
        let r = Session::start(&ring, &fb, &d.path().join("archive"), new_boot_id());
        assert!(matches!(r, Err(wsg_recorder::service::ServiceError::SamePath(_))), "{fb:?}");
    }
    assert_eq!(std::fs::read(&ring).unwrap(), before, "ring left untouched");
}
