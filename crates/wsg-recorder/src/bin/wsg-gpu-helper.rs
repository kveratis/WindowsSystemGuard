//! Prints one JSON line per interval with NVML readings for GPU 0. A field NVML cannot read is
//! null and listed in `unsupported`; an NVML init failure prints `{"ok":false,...}` and retries.

use std::io::Write;
use std::time::Duration;

use nvml_wrapper::enum_wrappers::device::{Clock, TemperatureSensor};
use nvml_wrapper::Nvml;
use serde_json::{json, Map, Value};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let interval = args
        .iter()
        .position(|a| a == "--interval-ms")
        .and_then(|i| args.get(i + 1)?.parse().ok())
        .unwrap_or(2000);
    let mut nvml: Option<Nvml> = None;
    loop {
        if nvml.is_none() {
            nvml = Nvml::init().map_err(|e| print_line(&json!({"ok": false, "error": format!("NVML init: {e}")}))).ok();
        }
        if let Some(n) = &nvml {
            match n.device_by_index(0) {
                Ok(d) => {
                    let fields: [(&str, Option<Value>); 5] = [
                        ("util_pct", d.utilization_rates().ok().map(|u| json!(u.gpu))),
                        ("mem_used_bytes", d.memory_info().ok().map(|m| json!(m.used))),
                        ("temp_c", d.temperature(TemperatureSensor::Gpu).ok().map(|t| json!(t))),
                        ("power_w", d.power_usage().ok().map(|mw| json!(mw as f64 / 1000.0))),
                        ("clock_mhz", d.clock_info(Clock::Graphics).ok().map(|c| json!(c))),
                    ];
                    let mut line = Map::new();
                    line.insert("ok".into(), json!(true));
                    let mut unsupported = vec![];
                    for (k, v) in fields {
                        if v.is_none() {
                            unsupported.push(k);
                        }
                        line.insert(k.into(), v.unwrap_or(Value::Null));
                    }
                    if !unsupported.is_empty() {
                        line.insert("unsupported".into(), json!(unsupported));
                    }
                    print_line(&Value::Object(line));
                }
                Err(e) => print_line(&json!({"ok": false, "error": format!("NVML device 0: {e}")})),
            }
        }
        std::thread::sleep(Duration::from_millis(interval));
    }
}

fn print_line(v: &Value) {
    let mut out = std::io::stdout().lock();
    if writeln!(out, "{v}").and_then(|_| out.flush()).is_err() {
        std::process::exit(0); // supervisor went away
    }
}
