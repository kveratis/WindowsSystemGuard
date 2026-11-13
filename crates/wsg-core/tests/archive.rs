use std::path::Path;
use wsg_core::archive::{archive_if_unclean, list_incidents, IncidentState};
use wsg_core::{BootId, RecordKind, Ring, RingReader};

const OLD: BootId = BootId([7u8; 16]);
const NEW: BootId = BootId([9u8; 16]);

fn make_ring(path: &Path, clean: bool) {
    let mut ring = Ring::create(path, 64 * 1024).unwrap();
    for i in 1..=5u64 {
        ring.append(RecordKind::Sample, OLD, i as i64, i, format!("p{i}").as_bytes()).unwrap();
    }
    if clean {
        ring.mark_clean_shutdown(OLD).unwrap();
    }
    ring.flush().unwrap();
}

#[test]
fn unclean_ring_is_archived_with_metadata() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let arc = d.path().join("arc");
    make_ring(&ring, false);
    let id = archive_if_unclean(&ring, &arc, NEW, 123).unwrap().unwrap();
    assert!(id.0.starts_with("inc-"));
    assert!(arc.join(&id.0).join("ring.bin").exists());
    let list = list_incidents(&arc);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, id);
    assert_eq!(list[0].detected_utc_ns, 123);
    assert_eq!(list[0].state, IncidentState::Archived);
    assert_eq!(list[0].previous_boot, "07".repeat(16));
}

#[test]
fn clean_ring_is_not_archived() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let arc = d.path().join("arc");
    make_ring(&ring, true);
    assert!(archive_if_unclean(&ring, &arc, NEW, 1).unwrap().is_none());
    assert!(list_incidents(&arc).is_empty());
}

#[test]
fn second_call_for_same_ring_returns_same_id_without_new_copy() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let arc = d.path().join("arc");
    make_ring(&ring, false);
    let a = archive_if_unclean(&ring, &arc, NEW, 1).unwrap().unwrap();
    let copy = arc.join(&a.0).join("ring.bin");
    std::fs::write(&copy, b"sentinel").unwrap();
    let b = archive_if_unclean(&ring, &arc, NEW, 2).unwrap().unwrap();
    assert_eq!(a, b);
    assert_eq!(std::fs::read(&copy).unwrap(), b"sentinel");
    assert_eq!(list_incidents(&arc)[0].detected_utc_ns, 1);
}

#[test]
fn five_rapid_restarts_create_one_incident() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let arc = d.path().join("arc");
    make_ring(&ring, false);
    for i in 0..5 {
        archive_if_unclean(&ring, &arc, NEW, i).unwrap().unwrap();
    }
    assert_eq!(list_incidents(&arc).len(), 1);
}

#[test]
fn archive_failure_leaves_original_ring_untouched() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    make_ring(&ring, false);
    let before = std::fs::read(&ring).unwrap();
    // Parent of the archive dir is a regular file, so create_dir_all fails.
    let blocker = d.path().join("blocker");
    std::fs::write(&blocker, b"x").unwrap();
    let arc = blocker.join("arc");
    assert!(archive_if_unclean(&ring, &arc, NEW, 1).is_err());
    assert_eq!(std::fs::read(&ring).unwrap(), before);
}

#[test]
fn archived_copy_matches_original_records() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let arc = d.path().join("arc");
    make_ring(&ring, false);
    let id = archive_if_unclean(&ring, &arc, NEW, 1).unwrap().unwrap();
    let a = RingReader::open(&ring).unwrap().records();
    let b = RingReader::open(&arc.join(&id.0).join("ring.bin")).unwrap().records();
    assert_eq!(a, b);
    assert_eq!(a.len(), 5);
}
