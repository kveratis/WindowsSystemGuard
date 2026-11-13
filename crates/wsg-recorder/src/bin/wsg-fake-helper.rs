//! Test helper for the supervisor: `wsg-fake-helper <normal|hang|error|crash> [--interval-ms N]`.

use std::io::Write;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("normal");
    let interval = args
        .iter()
        .position(|a| a == "--interval-ms")
        .and_then(|i| args.get(i + 1)?.parse().ok())
        .unwrap_or(2000);
    for n in 0u64.. {
        let line = match mode {
            "error" => r#"{"ok":false,"error":"boom"}"#.to_string(),
            _ => format!(r#"{{"ok":true,"n":{n}}}"#),
        };
        let mut out = std::io::stdout().lock();
        if writeln!(out, "{line}").and_then(|_| out.flush()).is_err() {
            return;
        }
        drop(out);
        match mode {
            "crash" => std::process::exit(3),
            "hang" => loop {
                std::thread::sleep(Duration::from_secs(3600));
            },
            _ => std::thread::sleep(Duration::from_millis(interval)),
        }
    }
}
