use std::path::Path;
use std::process::{Command, Output};

use wsg_core::archive::{archive_if_unclean, list_incidents, IncidentState};
use wsg_core::{new_boot_id, now_utc_ns, BootId, Reading, RecordKind, Ring, Sample};

fn wsg(data_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wsg"))
        .arg("--data-dir")
        .arg(data_dir)
        // A pipe name nobody serves, so a recorder running on this machine cannot answer.
        .args(["--pipe", r"\\.\pipe\wsg-test-no-such-pipe"])
        .args(args)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn empty_sample() -> Sample {
    fn un<T>() -> Reading<T> {
        Reading::Unavailable { reason: "test".into() }
    }
    Sample { cpu: un(), mem: un(), disks: un(), net: un(), procs: vec![], gpu: un(), sensors: un(), wsl_vm_running: un(), cycle_ms: 1000 }
}

/// A ring for an unclean session: `n` seconds of heartbeats and samples, no clean marker.
fn unclean_ring(path: &Path, boot: BootId, n: u64) {
    unclean_ring_step(path, boot, n, 1);
}

/// Like `unclean_ring`, with the recorder sampling every `step_s` seconds.
fn unclean_ring_step(path: &Path, boot: BootId, n: u64, step_s: u64) {
    let mut r = Ring::create(path, 1 << 20).unwrap();
    let step = step_s as i64 * 1_000_000_000;
    let start = now_utc_ns() - n as i64 * step;
    for t in 0..n {
        let utc = start + t as i64 * step;
        r.append(RecordKind::Heartbeat, boot, utc, t * step as u64, &[]).unwrap();
        r.append(RecordKind::Sample, boot, utc, t * step as u64, &empty_sample().encode()).unwrap();
    }
    r.flush().unwrap();
}

fn archived_incident(data: &Path) -> String {
    let (ring, archive) = (data.join("ring.bin"), data.join("archive"));
    unclean_ring(&ring, BootId([4; 16]), 20);
    archive_if_unclean(&ring, &archive, new_boot_id(), now_utc_ns()).unwrap().unwrap().0
}

#[test]
fn postmortem_on_fixture_incident_writes_file_and_marks_analyzed() {
    let d = tempfile::tempdir().unwrap();
    let id = archived_incident(d.path());
    let o = wsg(d.path(), &["postmortem", "--auto", "--no-events"]);
    assert!(o.status.success(), "{}", text(&o));
    let file = d.path().join("archive").join(&id).join("postmortem.txt");
    let pm = std::fs::read_to_string(&file).expect("postmortem.txt written");
    assert!(pm.starts_with("Cause undetermined"), "{pm}");
    assert!(pm.contains("TIMELINE") && pm.contains("Last sample taken"));
    assert!(pm.contains("CHECKS OUTSIDE THE RECORDER"));
    let incidents = list_incidents(&d.path().join("archive"));
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].state, IncidentState::Analyzed);
}

#[test]
fn postmortem_auto_is_idempotent() {
    let d = tempfile::tempdir().unwrap();
    let id = archived_incident(d.path());
    assert!(wsg(d.path(), &["postmortem", "--auto", "--no-events"]).status.success());
    let file = d.path().join("archive").join(&id).join("postmortem.txt");
    let (first, mtime) = (std::fs::read(&file).unwrap(), std::fs::metadata(&file).unwrap().modified().unwrap());
    let o = wsg(d.path(), &["postmortem", "--auto", "--no-events"]);
    assert!(o.status.success());
    assert!(text(&o).contains("No incidents waiting"), "{}", text(&o));
    assert_eq!(std::fs::read(&file).unwrap(), first);
    assert_eq!(std::fs::metadata(&file).unwrap().modified().unwrap(), mtime, "file untouched");
    // Naming the incident re-renders it on request.
    assert!(wsg(d.path(), &["postmortem", "--incident", &id, "--no-events"]).status.success());
    assert!(!wsg(d.path(), &["postmortem", "--incident", "inc-nope", "--no-events"]).status.success());
}

#[test]
fn report_since_filters_by_window() {
    let d = tempfile::tempdir().unwrap();
    let count = |since: &str| -> u64 {
        let o = wsg(d.path(), &["report", "--since", since, "--level", "4"]);
        assert!(o.status.success(), "{}", text(&o));
        let t = text(&o);
        let line = t.lines().find(|l| l.contains("events in window")).unwrap_or_else(|| panic!("{t}"));
        line.split_whitespace().next().unwrap().parse().unwrap()
    };
    let (hour, month) = (count("1h"), count("7d"));
    assert!(hour <= month, "{hour} events in 1h but {month} in 7d");
    assert!(month > 0, "a week of logs is never empty");
    assert!(!wsg(d.path(), &["report", "--since", "soon"]).status.success());
    assert!(text(&wsg(d.path(), &["report", "--since", "5x"])).contains("unknown unit"));
}

#[test]
fn noise_add_then_list_shows_rule() {
    let d = tempfile::tempdir().unwrap();
    let list = |d: &Path| text(&wsg(d, &["noise", "list"]));
    assert!(list(d.path()).contains("DCOM 10016"), "built-in rules are listed");
    let o = wsg(d.path(), &["noise", "add", "Microsoft-Windows-Foo", "1234", "Foo is chatty"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(list(d.path()).contains("Foo is chatty | Microsoft-Windows-Foo 1234"), "{}", list(d.path()));
    assert!(!wsg(d.path(), &["noise", "add", "Microsoft-Windows-Foo", "1234", "Foo is chatty"]).status.success(), "duplicate refused");
    assert!(!wsg(d.path(), &["noise", "remove", "DCOM 10016 (permission settings)"]).status.success(), "built-in stays");
    assert!(wsg(d.path(), &["noise", "remove", "Foo is chatty"]).status.success());
    assert!(!list(d.path()).contains("Foo is chatty"));
}

#[test]
fn status_without_service_falls_back_to_ring_file() {
    let d = tempfile::tempdir().unwrap();
    let o = wsg(d.path(), &["status"]);
    assert!(!o.status.success(), "no service and no rings is an error");
    assert!(text(&o).contains("no ring files"), "{}", text(&o));

    unclean_ring(&d.path().join("ring.bin"), BootId([4; 16]), 5);
    let o = wsg(d.path(), &["status"]);
    let t = text(&o);
    assert!(o.status.success(), "{t}");
    assert!(t.contains("Recorder not reachable") && t.contains("Reading the ring files"), "{t}");
    assert!(t.contains("Records: 10 (5 samples, 5 heartbeats)"), "{t}");
    assert!(t.contains("Last session ended cleanly: no"), "{t}");
}

fn service_exists() -> bool {
    Command::new("sc.exe").args(["query", "WindowsSystemGuard"]).output().map(|o| o.status.success()).unwrap_or(false)
}

#[test]
fn install_dry_run_prints_planned_actions() {
    let d = tempfile::tempdir().unwrap();
    let had = service_exists();
    let o = wsg(d.path(), &["install", "--dry-run"]);
    let t = text(&o);
    assert!(o.status.success(), "{t}");
    for needle in [
        "Dry run: nothing is changed",
        "icacls.exe",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "sc.exe create WindowsSystemGuard binPath=",
        "wsg-recorder.exe",
        "start= auto",
        "obj= LocalSystem",
        "sc.exe failure WindowsSystemGuard reset= 86400 actions= restart/5000/restart/5000/restart/30000",
        "schtasks.exe /Create /TN WindowsSystemGuard-PostMortem /SC ONSTART",
        "/RU SYSTEM",
        "postmortem --auto",
        "sc.exe start WindowsSystemGuard",
    ] {
        assert!(t.contains(needle), "missing {needle:?} in:\n{t}");
    }
    let u = text(&wsg(d.path(), &["uninstall", "--dry-run"]));
    assert!(u.contains("sc.exe delete WindowsSystemGuard") && u.contains("schtasks.exe /Delete"), "{u}");
    assert_eq!(service_exists(), had, "a dry run must not change the machine");
}

#[test]
fn slow_recorder_cadence_does_not_move_freeze_onset_to_the_first_heartbeat() {
    let d = tempfile::tempdir().unwrap();
    let (ring, archive) = (d.path().join("ring.bin"), d.path().join("archive"));
    // 30 heartbeats five seconds apart: the 59th record is the last heartbeat.
    unclean_ring_step(&ring, BootId([5; 16]), 30, 5);
    archive_if_unclean(&ring, &archive, new_boot_id(), now_utc_ns()).unwrap().unwrap();
    let o = wsg(d.path(), &["postmortem", "--no-events"]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&o);
    let onset = t.lines().find(|l| l.contains("Freeze onset estimate")).unwrap_or_else(|| panic!("{t}"));
    assert!(onset.contains("(record 59)"), "onset should be the last heartbeat: {onset}");
}

#[test]
fn install_plan_quotes_the_service_executable_path() {
    let d = tempfile::tempdir().unwrap();
    let t = text(&wsg(d.path(), &["install", "--dry-run"]));
    let create = t.lines().find(|l| l.contains("sc.exe create")).unwrap();
    assert!(create.contains(r#"binPath= "\"C:\"#) || create.contains(r#"binPath= "\""#), "path stored with literal quotes: {create}");
    assert!(create.contains(r#"wsg-recorder.exe\"""#), "closing quote after the executable: {create}");
}
