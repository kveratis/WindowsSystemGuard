use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use wsg_core::{
    resolve_volume_path, volume_guid_for, BootId, NewRecord, RecordKind, RingSink, SubmitResult,
    TieredWriter,
};

/// Fake sink: records appends, can hang (until released) or fail on demand. `hang_flush` hangs
/// only `flush`, the way a USB drive can accept writes but stall on the cache flush.
#[derive(Clone, Default)]
struct Fake {
    records: Arc<Mutex<Vec<NewRecord>>>,
    hang: Arc<AtomicBool>,
    hang_flush: Arc<AtomicBool>,
    fail: Arc<AtomicBool>,
    entered: Arc<AtomicUsize>,
    failures: Arc<AtomicUsize>,
}

impl Fake {
    fn hanging() -> Fake {
        let f = Fake::default();
        f.hang.store(true, Ordering::SeqCst);
        f
    }
    fn failing() -> Fake {
        let f = Fake::default();
        f.fail.store(true, Ordering::SeqCst);
        f
    }
    fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }
    fn ids(&self) -> Vec<u64> {
        self.records.lock().unwrap().iter().map(id_of).collect()
    }
    fn op(&self, flush: bool) -> io::Result<()> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        while self.hang.load(Ordering::SeqCst) || (flush && self.hang_flush.load(Ordering::SeqCst)) {
            thread::sleep(Duration::from_millis(1));
        }
        if self.fail.load(Ordering::SeqCst) {
            self.failures.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::other("fake failure"));
        }
        Ok(())
    }
}

impl RingSink for Fake {
    fn append(&mut self, rec: &NewRecord) -> io::Result<()> {
        self.op(false)?;
        self.records.lock().unwrap().push(rec.clone());
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.op(true)
    }
}

fn rec(kind: RecordKind, id: u64) -> NewRecord {
    NewRecord { kind, boot: BootId([7; 16]), utc_ns: id as i64, mono_ns: id, payload: id.to_le_bytes().to_vec() }
}

fn id_of(r: &NewRecord) -> u64 {
    u64::from_le_bytes(r.payload[..8].try_into().unwrap())
}

fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(2), "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(1));
    }
}

fn writer(p: &Fake, f: &Fake, deadline_ms: u64, cap: usize) -> TieredWriter {
    TieredWriter::new(Box::new(p.clone()), Box::new(f.clone()), Duration::from_millis(deadline_ms), cap)
}

#[test]
fn queue_full_drops_and_counts() {
    let (p, f) = (Fake::hanging(), Fake::default());
    let w = writer(&p, &f, 1000, 4);
    assert_eq!(w.submit(rec(RecordKind::Sample, 0)), SubmitResult::Queued);
    // The dispatcher is now waiting out the deadline on the hung primary, so the queue only fills.
    wait_until("primary entered", || p.entered.load(Ordering::SeqCst) == 1);
    let results: Vec<_> = (1..=7).map(|i| w.submit(rec(RecordKind::Sample, i))).collect();
    assert_eq!(results.iter().filter(|r| **r == SubmitResult::Queued).count(), 4);
    assert_eq!(results.iter().filter(|r| **r == SubmitResult::Dropped).count(), 3);
    assert_eq!(w.stats().dropped, 3);
    p.hang.store(false, Ordering::SeqCst);
}

#[test]
fn hung_primary_switches_to_fallback_within_deadline() {
    let (p, f) = (Fake::hanging(), Fake::default());
    let w = writer(&p, &f, 100, 16);
    let start = Instant::now();
    w.submit(rec(RecordKind::Sample, 0));
    wait_until("fallback write", || f.len() == 1);
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(100), "switched before the deadline: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(1000), "switch took {elapsed:?}");
    wait_until("fallback active", || w.stats().fallback_active);
    let s = w.stats();
    assert_eq!(s.primary_stalls, 1);
    assert!(!s.memory_only);
    p.hang.store(false, Ordering::SeqCst);
}

#[test]
fn primary_recovers_and_records_reconcile_in_seq_order() {
    let (p, f) = (Fake::hanging(), Fake::default());
    let w = writer(&p, &f, 100, 64);
    for i in 0..5 {
        w.submit(rec(RecordKind::Sample, i));
    }
    wait_until("fallback holds all stalled records", || f.len() >= 5);
    assert_eq!(f.ids(), vec![0, 1, 2, 3, 4]);
    p.hang.store(false, Ordering::SeqCst);
    for i in 5..8 {
        w.submit(rec(RecordKind::Sample, i));
    }
    wait_until("primary reconciled", || p.len() >= 8);
    wait_until("fallback deactivated", || !w.stats().fallback_active);
    assert_eq!(p.ids(), (0..8).collect::<Vec<_>>());
    assert_eq!(w.stats().primary_stalls, 1);
}

#[test]
fn both_sinks_failing_goes_memory_only() {
    let (p, f) = (Fake::failing(), Fake::failing());
    let w = writer(&p, &f, 100, 16);
    for i in 0..3 {
        w.submit(rec(RecordKind::Sample, i));
    }
    // All three records were refused by the fallback, so none is still in flight.
    wait_until("fallback refused all", || f.failures.load(Ordering::SeqCst) == 3);
    wait_until("memory only", || w.stats().memory_only);
    assert_eq!(w.stats().dropped, 0);
    // Fallback comes back: new records land there and memory-only mode ends.
    f.fail.store(false, Ordering::SeqCst);
    w.submit(rec(RecordKind::Sample, 3));
    wait_until("fallback write", || f.len() >= 4);
    // The memory-only records reach the fallback first, then the new one, with no duplicates.
    assert_eq!(f.ids(), vec![0, 1, 2, 3]);
    wait_until("memory only cleared", || !w.stats().memory_only);
    // Primary comes back: everything held in memory or fallback reaches it in order.
    p.fail.store(false, Ordering::SeqCst);
    w.submit(rec(RecordKind::Sample, 4));
    wait_until("primary reconciled", || p.len() >= 5);
    assert_eq!(p.ids(), vec![0, 1, 2, 3, 4]);
}

#[test]
fn missing_primary_at_start_uses_fallback_immediately() {
    let (p, f) = (Fake::failing(), Fake::default());
    let w = writer(&p, &f, 10_000, 16);
    let start = Instant::now();
    w.submit(rec(RecordKind::Sample, 0));
    wait_until("fallback write", || f.len() == 1);
    assert!(start.elapsed() < Duration::from_millis(1000));
    wait_until("fallback active", || w.stats().fallback_active);
    let s = w.stats();
    assert_eq!(s.primary_stalls, 0);
    assert!(!s.memory_only);
}

#[test]
fn heartbeat_records_still_written_during_primary_stall() {
    let (p, f) = (Fake::hanging(), Fake::default());
    let w = writer(&p, &f, 100, 16);
    w.submit(rec(RecordKind::Sample, 0));
    wait_until("stall", || w.stats().primary_stalls == 1);
    for i in 1..=3 {
        let start = Instant::now();
        assert_eq!(w.submit(rec(RecordKind::Heartbeat, i)), SubmitResult::Queued);
        assert!(start.elapsed() < Duration::from_millis(200), "submit blocked");
    }
    wait_until("heartbeats in fallback", || f.len() >= 4);
    assert_eq!(f.ids(), vec![0, 1, 2, 3]);
    let kinds: Vec<_> = f.records.lock().unwrap().iter().map(|r| r.kind).collect();
    assert_eq!(kinds[1..], [RecordKind::Heartbeat; 3]);
    // The hung primary is not retried per record, so it stalled exactly once.
    assert_eq!(w.stats().primary_stalls, 1);
    p.hang.store(false, Ordering::SeqCst);
}

#[test]
fn volume_guid_roundtrips_for_system_drive() {
    let guid = volume_guid_for(Path::new(r"C:\")).expect("C: has a volume GUID");
    assert!(guid.starts_with('{') && guid.ends_with('}'), "{guid}");
    let path = resolve_volume_path(&guid).expect("volume is mounted");
    assert!(path.to_string_lossy().to_uppercase().starts_with(r"C:\"), "{path:?}");
    assert_eq!(resolve_volume_path(guid.trim_matches(|c| c == '{' || c == '}')), Some(path));
    assert_eq!(resolve_volume_path("{00000000-0000-0000-0000-000000000000}"), None);
    assert_eq!(resolve_volume_path("not-a-guid"), None);
}

#[test]
fn flush_stall_saves_unflushed_records_to_fallback() {
    let (p, f) = (Fake::default(), Fake::default());
    p.hang_flush.store(true, Ordering::SeqCst);
    let w = writer(&p, &f, 100, 16);
    let start = Instant::now();
    w.submit(rec(RecordKind::Sample, 0));
    // Appended to the primary, but its flush hangs: the record must not exist only in its cache.
    wait_until("unflushed record in fallback", || f.len() >= 1);
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(100), "spilled before the deadline: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(1000), "spill took {elapsed:?}");
    assert_eq!(f.ids(), vec![0]);
    assert_eq!(w.stats().primary_stalls, 1);
    w.submit(rec(RecordKind::Sample, 1));
    wait_until("stalled-period record in fallback", || f.len() >= 2);
    assert_eq!(f.ids(), vec![0, 1]);
    p.hang_flush.store(false, Ordering::SeqCst);
    w.submit(rec(RecordKind::Sample, 2));
    wait_until("primary reconciled", || p.len() >= 3 && !w.stats().fallback_active);
    assert_eq!(p.ids(), vec![0, 1, 2], "each record exactly once in the primary");
}
