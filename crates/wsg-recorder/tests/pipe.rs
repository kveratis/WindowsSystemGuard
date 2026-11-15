use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wsg_recorder::pipe::serve;

fn ask(name: &str, msg: &[u8]) -> String {
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(name).unwrap();
    f.write_all(msg).unwrap();
    let mut out = String::new();
    let mut buf = [0u8; 256];
    loop {
        match f.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.push_str(&String::from_utf8_lossy(&buf[..n])),
        }
        if out.ends_with('\n') {
            break;
        }
    }
    out
}

fn name(tag: &str) -> String {
    format!(r"\\.\pipe\wsg-test-{tag}-{}", std::process::id())
}

#[test]
fn status_command_returns_the_current_json_line() {
    let n = name("status");
    let st = Arc::new(Mutex::new(r#"{"cycles":1}"#.to_string()));
    let _s = serve(&n, st.clone()).unwrap();
    assert_eq!(ask(&n, b"STATUS\n"), "{\"cycles\":1}\n");
    *st.lock().unwrap() = r#"{"cycles":2}"#.into();
    assert_eq!(ask(&n, b"STATUS"), "{\"cycles\":2}\n", "fresh value, no trailing newline needed");
}

#[test]
fn unknown_command_is_refused_and_changes_nothing() {
    let n = name("unknown");
    let st = Arc::new(Mutex::new("{}".to_string()));
    let _s = serve(&n, st.clone()).unwrap();
    assert_eq!(ask(&n, b"STOP\n"), "ERR\n");
    assert_eq!(*st.lock().unwrap(), "{}");
}

#[test]
fn silent_client_does_not_block_other_clients() {
    let n = name("silent");
    let _s = serve(&n, Arc::new(Mutex::new("{}".to_string()))).unwrap();
    let _idle = std::fs::OpenOptions::new().read(true).write(true).open(&n).unwrap();
    let t = Instant::now();
    assert_eq!(ask(&n, b"STATUS\n"), "{}\n");
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
}

#[test]
fn second_server_on_the_same_name_is_refused() {
    let n = name("squat");
    let _a = serve(&n, Arc::new(Mutex::new(String::new()))).unwrap();
    assert!(serve(&n, Arc::new(Mutex::new(String::new()))).is_err());
}
