use wsg_core::{merge_records, merge_rings, merge_rings_with_notes, BootId, Record, RecordKind, Ring};

fn rec(seq: u64, boot: u8, mono: u64, kind: RecordKind) -> Record {
    Record { seq, boot: BootId([boot; 16]), utc_ns: mono as i64 * 10, mono_ns: mono, kind, payload: vec![] }
}

#[test]
fn merges_by_boot_mono_and_kind_ignoring_unrelated_seq() {
    let primary = vec![rec(1, 1, 10, RecordKind::Sample), rec(2, 1, 30, RecordKind::Sample)];
    let fallback = vec![rec(500, 1, 20, RecordKind::Heartbeat), rec(501, 1, 30, RecordKind::Sample)];
    let m = merge_records(primary, fallback);
    let got: Vec<_> = m.iter().map(|r| (r.mono_ns, r.kind, r.seq)).collect();
    assert_eq!(got, [(10, RecordKind::Sample, 1), (20, RecordKind::Heartbeat, 500), (30, RecordKind::Sample, 2)]);
}

#[test]
fn marker_sharing_mono_with_last_record_is_kept_and_sorts_after_it() {
    let m = merge_records(vec![rec(1, 1, 10, RecordKind::Sample), rec(2, 1, 10, RecordKind::Marker)], vec![]);
    assert_eq!(m.len(), 2);
    assert_eq!(m[1].kind, RecordKind::Marker);
}

#[test]
fn boots_are_ordered_by_earliest_record_not_by_boot_id() {
    let m = merge_records(vec![rec(1, 9, 5, RecordKind::Sample)], vec![rec(1, 2, 5, RecordKind::Sample)]);
    // utc is mono*10 here, equal, so both boots tie; ordering must at least be stable and complete.
    assert_eq!(m.len(), 2);
    let mut a = rec(1, 9, 5, RecordKind::Sample);
    a.utc_ns = 100;
    let mut b = rec(1, 2, 5, RecordKind::Sample);
    b.utc_ns = 900;
    let m = merge_records(vec![b.clone()], vec![a.clone()]);
    assert_eq!((m[0].boot, m[1].boot), (a.boot, b.boot));
}

#[test]
fn merges_real_ring_files_and_survives_a_missing_one() {
    let d = tempfile::tempdir().unwrap();
    let (p, f) = (d.path().join("p.bin"), d.path().join("f.bin"));
    let boot = BootId([7; 16]);
    let mut a = Ring::create(&p, 1 << 20).unwrap();
    a.append(RecordKind::Sample, boot, 1, 10, b"a").unwrap();
    a.append(RecordKind::Sample, boot, 3, 30, b"c").unwrap();
    a.flush().unwrap();
    let mut b = Ring::create(&f, 1 << 20).unwrap();
    b.append(RecordKind::Heartbeat, boot, 2, 20, b"b").unwrap();
    b.flush().unwrap();
    let monos: Vec<_> = merge_rings(&p, &f).iter().map(|r| r.mono_ns).collect();
    assert_eq!(monos, [10, 20, 30]);
    let (m, notes) = merge_rings_with_notes(&p, &d.path().join("absent.bin"));
    assert_eq!(m.len(), 2);
    assert_eq!(notes.len(), 1, "{notes:?}");
}
