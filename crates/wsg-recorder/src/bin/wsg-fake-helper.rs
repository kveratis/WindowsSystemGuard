//! Test helper for the supervisor:
//! `wsg-fake-helper <normal|hang|error|crash|flood|badutf8|supervise> [--interval-ms N]`.
//! `supervise` runs a HelperSupervisor over `wsg-fake-helper hang`, prints the hung child's pid
//! and then sleeps, so a test can kill this process and check the child dies with it.

use std::io::Write;
use std::time::Duration;

use wsg_core::sample::Reading;
use wsg_recorder::supervisor::{HelperSpec, HelperSupervisor};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("normal");
    let interval = args
        .iter()
        .position(|a| a == "--interval-ms")
        .and_then(|i| args.get(i + 1)?.parse().ok())
        .unwrap_or(2000);
    let mut out = std::io::stdout();
    match mode {
        "supervise" => supervise(),
        "flood" => {
            // One endless line with no newline; exits only when the reader closes the pipe.
            let chunk = vec![b'x'; 64 << 10];
            while out.write_all(&chunk).and_then(|_| out.flush()).is_ok() {}
            return;
        }
        "badutf8" if out.write_all(b"\xff\xfe{\"ok\":true}\n").and_then(|_| out.flush()).is_err() => {
            return;
        }
        _ => {}
    }
    for n in 0u64.. {
        let line = match mode {
            "error" => r#"{"ok":false,"error":"boom"}"#.to_string(),
            _ => format!(r#"{{"ok":true,"n":{n},"pid":{}}}"#, std::process::id()),
        };
        if writeln!(out, "{line}").and_then(|_| out.flush()).is_err() {
            return;
        }
        match mode {
            "crash" => std::process::exit(3),
            "hang" => sleep_forever(),
            _ => std::thread::sleep(Duration::from_millis(interval)),
        }
    }
}

fn supervise() -> ! {
    let mut s = HelperSupervisor::spawn(HelperSpec {
        exe: std::env::current_exe().unwrap(),
        args: vec!["hang".into()],
        call_deadline: Duration::from_secs(600),
        restart_limit: 0,
        restart_window: Duration::from_secs(60),
    });
    loop {
        if let Reading::Value { v, .. } = s.poll() {
            println!("{}", v["pid"]);
            let _ = std::io::stdout().flush();
            sleep_forever();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn sleep_forever() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
