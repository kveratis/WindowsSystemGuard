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
    let dirs: Vec<_> = std::fs::read_dir(&arc).unwrap().flatten().collect();
    assert_eq!(dirs.len(), 1);
    let mut names: Vec<String> = std::fs::read_dir(dirs[0].path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["incident.json", "ring.bin"]);
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

#[test]
fn retry_succeeds_with_stale_partial_and_ring_bin_without_meta() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let arc = d.path().join("arc");
    make_ring(&ring, false);
    let id = format!("inc-{}", "07".repeat(16));
    let dir = arc.join(&id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ring.bin.partial"), b"junk").unwrap();
    std::fs::write(dir.join("ring.bin"), b"stale").unwrap();
    let got = archive_if_unclean(&ring, &arc, NEW, 5).unwrap().unwrap();
    assert_eq!(got.0, id);
    assert!(!dir.join("ring.bin.partial").exists());
    assert_eq!(RingReader::open(&dir.join("ring.bin")).unwrap().records().len(), 5);
    assert_eq!(list_incidents(&arc).len(), 1);
}

#[test]
fn corrupt_incident_json_is_rearchived() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let arc = d.path().join("arc");
    make_ring(&ring, false);
    let id = archive_if_unclean(&ring, &arc, NEW, 1).unwrap().unwrap();
    std::fs::write(arc.join(&id.0).join("incident.json"), b"{\"id\":").unwrap();
    assert!(list_incidents(&arc).is_empty());
    archive_if_unclean(&ring, &arc, NEW, 2).unwrap().unwrap();
    let l = list_incidents(&arc);
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].detected_utc_ns, 2);
}

#[test]
fn second_incident_from_different_boot_preserves_first() {
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("arc");
    let r1 = d.path().join("r1.bin");
    make_ring(&r1, false);
    let a = archive_if_unclean(&r1, &arc, NEW, 1).unwrap().unwrap();
    let a_bytes = std::fs::read(arc.join(&a.0).join("ring.bin")).unwrap();
    let r2 = d.path().join("r2.bin");
    let mut ring = Ring::create(&r2, 64 * 1024).unwrap();
    ring.append(RecordKind::Sample, BootId([8u8; 16]), 1, 1, b"x").unwrap();
    ring.flush().unwrap();
    let b = archive_if_unclean(&r2, &arc, NEW, 2).unwrap().unwrap();
    assert_ne!(a, b);
    assert_eq!(list_incidents(&arc).len(), 2);
    assert_eq!(std::fs::read(arc.join(&a.0).join("ring.bin")).unwrap(), a_bytes);
}
