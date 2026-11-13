use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use wsg_core::{BootId, RecordKind, Ring, RingError, RingReader};

const BOOT: BootId = BootId([7u8; 16]);

fn payload_for(seq: u64, len: usize) -> Vec<u8> {
    // Bytes 0x20..0x7f only, so payloads never contain the frame magic or zeros.
    (0..len).map(|i| 0x20 + ((seq as usize * 31 + i) % 0x5f) as u8).collect()
}

fn seqs(path: &Path) -> Vec<u64> {
    RingReader::open(path).unwrap().records().iter().map(|r| r.seq).collect()
}

#[test]
fn appends_and_reads_back_in_seq_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ring.bin");
    let mut ring = Ring::create(&path, 64 * 1024).unwrap();
    for i in 1..=10u64 {
        let seq = ring
            .append(RecordKind::Sample, BOOT, i as i64 * 1000, i * 10, &payload_for(i, 40))
            .unwrap();
        assert_eq!(seq, i);
    }
    ring.flush().unwrap();
    assert_eq!(ring.last_durable_seq(), 10);
    assert!(matches!(
        ring.append(RecordKind::Sample, BOOT, 0, 0, &vec![b'x'; 64 * 1024 + 1]),
        Err(RingError::PayloadTooLarge(_))
    ));

    let reader = RingReader::open(&path).unwrap();
    let recs = reader.records();
    assert_eq!(recs.len(), 10);
    assert_eq!(reader.skipped_corrupt(), 0);
    for (i, r) in recs.iter().enumerate() {
        let seq = i as u64 + 1;
        assert_eq!(r.seq, seq);
        assert_eq!(r.boot, BOOT);
        assert_eq!(r.utc_ns, seq as i64 * 1000);
        assert_eq!(r.mono_ns, seq * 10);
        assert_eq!(r.kind, RecordKind::Sample);
        assert_eq!(r.payload, payload_for(seq, 40));
    }
}

#[test]
fn wraps_and_keeps_newest_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ring.bin");
    let mut ring = Ring::create(&path, 4096).unwrap();
    for i in 1..=200u64 {
        ring.append(RecordKind::Sample, BOOT, 0, i, &payload_for(i, 100)).unwrap();
    }
    ring.flush().unwrap();
    drop(ring);

    let check = |last: u64| {
        let reader = RingReader::open(&path).unwrap();
        let recs = reader.records();
        assert!(recs.len() >= 20, "kept only {} records", recs.len());
        assert!(recs[0].seq > 1, "oldest records must be overwritten");
        assert_eq!(recs.last().unwrap().seq, last);
        for w in recs.windows(2) {
            assert_eq!(w[1].seq, w[0].seq + 1, "kept window must be contiguous");
        }
        for r in &recs {
            assert_eq!(r.payload, payload_for(r.seq, 100));
        }
    };
    check(200);

    let mut ring = Ring::open(&path).unwrap();
    assert_eq!(ring.append(RecordKind::Sample, BOOT, 0, 201, &payload_for(201, 100)).unwrap(), 201);
    drop(ring);
    check(201);
}

#[test]
fn reopen_recovers_next_seq() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ring.bin");
    let mut ring = Ring::create(&path, 64 * 1024).unwrap();
    for i in 1..=5u64 {
        ring.append(RecordKind::Sample, BOOT, 0, i, b"abc").unwrap();
    }
    drop(ring);

    let mut ring = Ring::open(&path).unwrap();
    assert_eq!(ring.last_durable_seq(), 5);
    assert_eq!(ring.append(RecordKind::Heartbeat, BOOT, 0, 6, b"hb").unwrap(), 6);
    drop(ring);
    assert_eq!(seqs(&path), vec![1, 2, 3, 4, 5, 6]);
}

#[test]
fn torn_last_record_is_skipped_and_earlier_records_survive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ring.bin");
    let mut ring = Ring::create(&path, 64 * 1024).unwrap();
    for i in 1..=5u64 {
        ring.append(RecordKind::Sample, BOOT, 0, i, &payload_for(i, 60)).unwrap();
    }
    drop(ring);

    // The file is preallocated, so cut 10 bytes from the end of the used data, not the file.
    let bytes = std::fs::read(&path).unwrap();
    let used = bytes.iter().rposition(|&b| b != 0).unwrap() + 1;
    let f = OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(used as u64 - 10).unwrap();
    drop(f);

    let reader = RingReader::open(&path).unwrap();
    assert_eq!(reader.records().iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    assert_eq!(reader.skipped_corrupt(), 1);

    let mut ring = Ring::open(&path).unwrap();
    assert_eq!(ring.append(RecordKind::Sample, BOOT, 0, 5, b"again").unwrap(), 5);
    drop(ring);
    assert_eq!(seqs(&path), vec![1, 2, 3, 4, 5]);
}

#[test]
fn corrupt_middle_record_does_not_invalidate_others() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ring.bin");
    let mut ring = Ring::create(&path, 64 * 1024).unwrap();
    for i in 1..=5u64 {
        ring.append(RecordKind::Sample, BOOT, 0, i, &payload_for(i, 60)).unwrap();
    }
    drop(ring);

    // Flip one byte inside record 3's payload.
    let mut bytes = std::fs::read(&path).unwrap();
    let needle = payload_for(3, 60);
    let at = bytes.windows(needle.len()).position(|w| w == needle.as_slice()).unwrap();
    bytes[at + 30] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    let reader = RingReader::open(&path).unwrap();
    assert_eq!(reader.skipped_corrupt(), 1);
    let recs = reader.records();
    assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 4, 5]);
    for r in &recs {
        assert_eq!(r.payload, payload_for(r.seq, 60));
    }
}

#[test]
fn ended_cleanly_only_after_marker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ring.bin");
    let mut ring = Ring::create(&path, 64 * 1024).unwrap();
    assert!(!RingReader::open(&path).unwrap().ended_cleanly());
    ring.append(RecordKind::Sample, BOOT, 0, 42, b"s").unwrap();
    assert!(!RingReader::open(&path).unwrap().ended_cleanly());

    ring.mark_clean_shutdown(BOOT).unwrap();
    let reader = RingReader::open(&path).unwrap();
    assert!(reader.ended_cleanly());
    let last = reader.records().pop().unwrap();
    assert_eq!(last.kind, RecordKind::Marker);
    assert_eq!(last.payload, b"clean");
    assert_eq!(last.mono_ns, 42, "marker carries the last appended mono_ns");

    ring.append(RecordKind::Sample, BOOT, 0, 2, b"s").unwrap();
    assert!(!RingReader::open(&path).unwrap().ended_cleanly());
}

#[test]
fn orders_by_seq_when_wall_clock_goes_backwards() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ring.bin");
    let mut ring = Ring::create(&path, 64 * 1024).unwrap();
    for i in 1..=6u64 {
        ring.append(RecordKind::Sample, BOOT, 1_000_000 - i as i64 * 1000, i, b"p").unwrap();
    }
    drop(ring);
    let recs = RingReader::open(&path).unwrap().records();
    assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5, 6]);
    assert!(recs.windows(2).all(|w| w[1].utc_ns < w[0].utc_ns));
}

#[test]
fn reader_can_read_while_writer_appends() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ring.bin");
    // Small capacity: about 60 frames per lap, so the writer wraps many times during the reads.
    let mut ring = Ring::create(&path, 8192).unwrap();
    const N: u64 = 1000;
    let start = Arc::new(Barrier::new(2));
    let done = Arc::new(AtomicBool::new(false));

    let (wstart, wdone) = (start.clone(), done.clone());
    let writer = std::thread::spawn(move || {
        wstart.wait();
        for i in 1..=N {
            ring.append(RecordKind::Sample, BOOT, 0, i, &payload_for(i, 80)).unwrap();
        }
        ring.flush().unwrap();
        wdone.store(true, Ordering::SeqCst);
    });
    let rpath = path.clone();
    let reader = std::thread::spawn(move || {
        start.wait();
        let mut mid_write_snapshots = 0;
        while !done.load(Ordering::SeqCst) {
            let recs = RingReader::open(&rpath).unwrap().records();
            // A snapshot racing a wrap may mix two laps: require order and intact payloads only.
            assert!(recs.windows(2).all(|w| w[1].seq > w[0].seq));
            for r in &recs {
                assert_eq!(r.payload, payload_for(r.seq, 80));
            }
            if !recs.is_empty() && recs.last().unwrap().seq < N {
                mid_write_snapshots += 1;
            }
        }
        mid_write_snapshots
    });
    writer.join().unwrap();
    assert!(reader.join().unwrap() >= 1, "reader never overlapped the writer");

    let recs = RingReader::open(&path).unwrap().records();
    assert!(!recs.is_empty() && (recs.len() as u64) < N);
    assert_eq!(recs.last().unwrap().seq, N);
    for w in recs.windows(2) {
        assert_eq!(w[1].seq, w[0].seq + 1);
    }
    for r in &recs {
        assert_eq!(r.payload, payload_for(r.seq, 80));
    }
}
