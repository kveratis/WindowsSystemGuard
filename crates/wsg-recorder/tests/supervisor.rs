use std::path::PathBuf;
use std::time::{Duration, Instant};

use wsg_core::sample::Reading;
use wsg_recorder::collectors::gpu_from_json;
use wsg_recorder::supervisor::{HelperSpec, HelperSupervisor};

/// Upper bound for a helper's first output. Normally well under a second, but antivirus on the
/// dev machine holds each launch of the real helper exes ~26 s, and std serializes all spawns
/// in the process behind that.
const STARTUP: Duration = Duration::from_secs(90);

fn fake(mode: &str, interval_ms: u64, deadline_ms: u64, limit: u32) -> HelperSpec {
    HelperSpec {
        exe: PathBuf::from(env!("CARGO_BIN_EXE_wsg-fake-helper")),
        args: vec![mode.into(), "--interval-ms".into(), interval_ms.to_string()],
        call_deadline: Duration::from_millis(deadline_ms),
        restart_limit: limit,
        restart_window: Duration::from_secs(60),
    }
}

fn reason<T: std::fmt::Debug>(r: &Reading<T>) -> String {
    match r {
        Reading::Unavailable { reason } => reason.clone(),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

/// Polls every 10 ms until `done` accepts the reading or `timeout` passes.
fn poll_until(
    s: &mut HelperSupervisor,
    timeout: Duration,
    done: impl Fn(&Reading<serde_json::Value>) -> bool,
) -> Reading<serde_json::Value> {
    let t = Instant::now();
    loop {
        let r = s.poll();
        if done(&r) || t.elapsed() > timeout {
            return r;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn is_value(r: &Reading<serde_json::Value>) -> bool {
    matches!(r, Reading::Value { .. })
}

#[test]
fn hung_helper_is_killed_and_poll_returns_unavailable_with_stall_time() {
    let mut s = HelperSupervisor::spawn(fake("hang", 50, 300, 5));
    assert!(is_value(&poll_until(&mut s, STARTUP, is_value)));
    let r = poll_until(&mut s, Duration::from_secs(3), |r| !is_value(r));
    assert!(reason(&r).starts_with("stale: no output for"), "{r:?}");
    let st = s.stats();
    assert!(st.last_stall_utc_ns.is_some());
    assert_eq!(st.restarts, 1, "the hung helper is killed and replaced");
    assert!(!st.abandoned);
}

#[test]
fn helper_restarts_up_to_limit_then_abandoned() {
    let mut s = HelperSupervisor::spawn(fake("crash", 50, 1000, 2));
    poll_until(&mut s, STARTUP, |r| {
        matches!(r, Reading::Unavailable { reason } if reason == "helper abandoned")
    });
    let st = s.stats();
    assert!(st.abandoned, "{st:?}");
    assert_eq!(st.restarts, 2);
    assert_eq!(reason(&s.poll()), "helper abandoned");
}

#[test]
fn poll_never_blocks_longer_than_call_deadline() {
    let deadline = Duration::from_millis(200);
    let mut s = HelperSupervisor::spawn(fake("hang", 50, 200, 3));
    assert!(is_value(&poll_until(&mut s, STARTUP, is_value)));
    let start = Instant::now();
    let mut worst = Duration::ZERO;
    while start.elapsed() < Duration::from_millis(1200) {
        let t = Instant::now();
        let _ = s.poll();
        worst = worst.max(t.elapsed());
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(worst < deadline, "slowest poll took {worst:?}");
}

#[test]
fn helper_error_line_becomes_unavailable_with_reason() {
    let mut s = HelperSupervisor::spawn(fake("error", 50, 1000, 3));
    let r = poll_until(&mut s, STARTUP, |r| {
        matches!(r, Reading::Unavailable { reason } if reason == "boom")
    });
    assert_eq!(reason(&r), "boom");
}

#[test]
fn stale_sample_age_is_reported() {
    let mut s = HelperSupervisor::spawn(fake("normal", 1000, 3000, 3));
    assert!(is_value(&poll_until(&mut s, STARTUP, is_value)));
    std::thread::sleep(Duration::from_millis(200));
    match s.poll() {
        Reading::Value { v, age_ms } => {
            assert_eq!(v["ok"], true);
            assert!((150..1000).contains(&age_ms), "age {age_ms}");
        }
        other => panic!("expected a value, got {other:?}"),
    }
}

#[test]
fn sensor_helper_unreachable_lhm_is_unavailable() {
    let addr = "127.0.0.1:8085".parse().unwrap();
    if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok() {
        println!("skipped: something is listening on 127.0.0.1:8085");
        return;
    }
    let mut s = HelperSupervisor::spawn(HelperSpec {
        exe: PathBuf::from(env!("CARGO_BIN_EXE_wsg-sensor-helper")),
        args: vec!["--interval-ms".into(), "50".into()],
        call_deadline: Duration::from_secs(5),
        restart_limit: 3,
        restart_window: Duration::from_secs(60),
    });
    let r = poll_until(&mut s, STARTUP, |r| {
        matches!(r, Reading::Unavailable { reason } if reason.starts_with("connect"))
    });
    let why = reason(&r);
    assert!(why.starts_with("connect 127.0.0.1:8085"), "{why}");
}

#[test]
fn gpu_unsupported_field_is_unavailable_not_zero() {
    let line: serde_json::Value = serde_json::from_str(
        r#"{"ok":true,"util_pct":12.0,"mem_used_bytes":1024,"temp_c":50.0,"power_w":null,"clock_mhz":null,"unsupported":["power_w","clock_mhz"]}"#,
    )
    .unwrap();
    let r = gpu_from_json(Reading::Value { v: line, age_ms: 7 });
    assert_eq!(reason(&r), "unsupported: power_w,clock_mhz");

    let full: serde_json::Value = serde_json::from_str(
        r#"{"ok":true,"util_pct":12.0,"mem_used_bytes":1024,"temp_c":50.0,"power_w":30.5,"clock_mhz":1800.0}"#,
    )
    .unwrap();
    match gpu_from_json(Reading::Value { v: full, age_ms: 7 }) {
        Reading::Value { v, age_ms } => {
            assert_eq!(age_ms, 7);
            assert_eq!(v.mem_used_bytes, 1024);
            assert_eq!(v.power_w, 30.5);
        }
        other => panic!("{other:?}"),
    }
}


#[test]
fn helper_dies_when_recorder_is_killed() {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};

    // The parent plays the recorder: it supervises a hung helper and prints that helper's pid.
    let mut parent = Command::new(env!("CARGO_BIN_EXE_wsg-fake-helper"))
        .arg("supervise")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let out = parent.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::BufReader::new(out).read_line(&mut line);
        let _ = tx.send(line);
    });
    let pid: u32 = rx.recv_timeout(STARTUP).unwrap().trim().parse().unwrap();
    let child = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    assert!(!child.is_null(), "hung helper {pid} should be running");

    parent.kill().unwrap(); // TerminateProcess: no Drop runs in the parent
    let _ = parent.wait();
    let waited = unsafe { WaitForSingleObject(child, 5000) };
    unsafe { CloseHandle(child) };
    if waited != WAIT_OBJECT_0 {
        // Do not leave the orphan behind when the assertion below fails.
        let _ = Command::new("taskkill").args(["/F", "/PID", &pid.to_string()]).output();
    }
    assert_eq!(waited, WAIT_OBJECT_0, "helper {pid} outlived its killed supervisor");
}

#[test]
fn overlong_line_is_protocol_error_and_helper_restarted() {
    // The deadline outlasts the wait, so only the line cap (closing the pipe, which makes the
    // flooding helper exit) can trigger the restart.
    let mut s = HelperSupervisor::spawn(fake("flood", 50, 600_000, 5));
    let t = Instant::now();
    while s.stats().restarts == 0 && t.elapsed() < STARTUP {
        assert!(!is_value(&s.poll()), "an overlong line must never become a value");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(s.stats().restarts >= 1, "{:?}", s.stats());
}

#[test]
fn invalid_utf8_line_is_skipped() {
    let mut s = HelperSupervisor::spawn(fake("badutf8", 50, 1000, 3));
    let r = poll_until(&mut s, STARTUP, is_value);
    match r {
        Reading::Value { v, .. } => assert!(v["n"].is_number(), "{v}"),
        other => panic!("reader should survive the bad line, got {other:?}"),
    }
    assert_eq!(s.stats().restarts, 0);
}
