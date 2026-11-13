//! Prints one JSON line per interval with LibreHardwareMonitor's sensors, or `{"ok":false,...}`.

use std::io::Write;
use std::time::Duration;

use serde_json::{json, Value};
use wsg_recorder::lhm::{fetch_data_json, map_data_json};

fn main() {
    let interval = interval_ms();
    let addr = "127.0.0.1:8085".parse().unwrap();
    loop {
        let line = match fetch_data_json(addr)
            .and_then(|body| serde_json::from_str::<Value>(&body).map_err(|e| format!("malformed data.json: {e}")))
        {
            Ok(root) => {
                let mut v = serde_json::to_value(map_data_json(&root)).unwrap();
                v["ok"] = json!(true);
                v
            }
            Err(e) => json!({"ok": false, "error": e}),
        };
        let mut out = std::io::stdout().lock();
        if writeln!(out, "{line}").and_then(|_| out.flush()).is_err() {
            return; // supervisor went away
        }
        drop(out);
        std::thread::sleep(Duration::from_millis(interval));
    }
}

fn interval_ms() -> u64 {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == "--interval-ms")
        .and_then(|i| args.get(i + 1)?.parse().ok())
        .unwrap_or(2000)
}
