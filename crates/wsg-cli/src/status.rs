//! `wsg status`: ask the running recorder, or read the ring files when it is not reachable.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use wsg_core::{merge_rings_with_notes, RecordKind};
use wsg_events::format_system_time;

pub const PIPE_NAME: &str = r"\\.\pipe\wsg-recorder";
const PIPE_TIMEOUT: Duration = Duration::from_secs(3);

/// One `STATUS` round trip. Bounded by a timeout so a wedged recorder cannot hang the command.
pub fn ask_recorder(pipe: &str) -> Result<String, String> {
    let name = pipe.to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = (|| {
            let mut f = std::fs::OpenOptions::new().read(true).write(true).open(&name).map_err(|e| e.to_string())?;
            f.write_all(b"STATUS\n").map_err(|e| e.to_string())?;
            let (mut out, mut buf) = (String::new(), [0u8; 1024]);
            loop {
                match f.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.push_str(&String::from_utf8_lossy(&buf[..n])),
                }
                if out.ends_with('\n') {
                    break;
                }
            }
            Ok::<String, String>(out)
        })();
        let _ = tx.send(r);
    });
    rx.recv_timeout(PIPE_TIMEOUT).map_err(|_| "no answer within 3 seconds".to_string())?
}

pub fn run(pipe: &str, data_dir: &Path) -> Result<(), String> {
    match ask_recorder(pipe) {
        Ok(json) => {
            println!("Recorder is running (answered on {pipe}).");
            match serde_json::from_str::<serde_json::Value>(json.trim()) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or(json)),
                Err(_) => println!("{}", json.trim()),
            }
            Ok(())
        }
        Err(why) => {
            println!("Recorder not reachable ({why}). Reading the ring files in {} instead.", data_dir.display());
            ring_status(data_dir)
        }
    }
}

fn ring_status(data_dir: &Path) -> Result<(), String> {
    let (ring, fallback) = (data_dir.join("ring.bin"), data_dir.join("fallback.bin"));
    if !ring.exists() && !fallback.exists() {
        return Err(format!("no ring files in {}; the recorder has not run here", data_dir.display()));
    }
    let (records, notes) = merge_rings_with_notes(&ring, &fallback);
    for n in &notes {
        println!("note: {n}");
    }
    let Some(last) = records.last() else {
        println!("The rings hold no records.");
        return Ok(());
    };
    let count = |k: RecordKind| records.iter().filter(|r| r.kind == k).count();
    let clean = records.iter().rev().take_while(|r| r.boot == last.boot).any(|r| r.kind == RecordKind::Marker && r.payload == wsg_core::MARKER_CLEAN);
    println!("Records: {} ({} samples, {} heartbeats)", records.len(), count(RecordKind::Sample), count(RecordKind::Heartbeat));
    println!("Newest record: {}", format_system_time(last.utc_ns));
    let age_s = (wsg_core::now_utc_ns() - last.utc_ns) / super::common::NS;
    println!("Age of newest record: {age_s} s{}", if age_s > 10 && !clean { " (the recorder is not writing)" } else { "" });
    println!("Last session ended cleanly: {}", if clean { "yes" } else { "no (no clean-shutdown marker)" });
    Ok(())
}
