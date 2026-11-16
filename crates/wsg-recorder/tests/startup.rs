use std::process::Command;
use std::sync::{Arc, Mutex};

use wsg_core::{new_boot_id, now_utc_ns, RecordKind, Ring};
use wsg_recorder::pipe::{serve, PIPE_NAME};

#[test]
fn second_recorder_is_refused_before_it_touches_the_rings() {
    let d = tempfile::tempdir().unwrap();
    let ring = d.path().join("ring.bin");
    let mut r = Ring::create(&ring, 1 << 20).unwrap();
    r.append(RecordKind::Heartbeat, new_boot_id(), now_utc_ns(), 1, b"x").unwrap();
    drop(r);
    let before = std::fs::read(&ring).unwrap();

    // Stands in for the running recorder that owns the status pipe.
    let _first = serve(PIPE_NAME, Arc::new(Mutex::new(String::new()))).expect("pipe free for the test");
    let out = Command::new(env!("CARGO_BIN_EXE_wsg-recorder"))
        .args(["--console", "--data-dir"])
        .arg(d.path())
        .output()
        .unwrap();

    assert!(!out.status.success(), "second recorder must exit with an error");
    assert!(String::from_utf8_lossy(&out.stderr).contains("status pipe"), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read(&ring).unwrap(), before, "ring must not be archived or recreated");
    assert!(!d.path().join("archive").exists(), "nothing archived");
    assert!(!d.path().join("fallback.bin").exists(), "fallback not created");
}
