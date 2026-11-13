//! LibreHardwareMonitor web-server client and `data.json` mapping, used by `wsg-sensor-helper`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde_json::Value;
use wsg_core::sample::SensorSet;

/// GETs `/data.json` over HTTP/1.0 with 1 second connect, read and write timeouts.
pub fn fetch_data_json(addr: SocketAddr) -> Result<String, String> {
    let t = Duration::from_secs(1);
    let mut s = TcpStream::connect_timeout(&addr, t).map_err(|e| format!("connect {addr}: {e}"))?;
    s.set_read_timeout(Some(t)).and_then(|_| s.set_write_timeout(Some(t))).map_err(|e| e.to_string())?;
    s.write_all(format!("GET /data.json HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes())
        .map_err(|e| format!("send: {e}"))?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("malformed HTTP response")?;
    let status = head.lines().next().unwrap_or("");
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(format!("HTTP status: {status}"));
    }
    Ok(body.to_string())
}

/// Parses an LHM value string such as "45,5 °C", "1.23 V" or "1200 RPM"; None for anything else.
pub fn parse_value(s: &str) -> Option<f32> {
    let num: String = s
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || matches!(c, '-' | '.' | ','))
        .map(|c| if c == ',' { '.' } else { c })
        .collect();
    num.parse::<f32>().ok().filter(|v| v.is_finite())
}

/// Maps the LHM sensor tree by `SensorId` path segments. Sensors whose value does not parse are skipped.
pub fn map_data_json(root: &Value) -> SensorSet {
    let mut sensors = Vec::new();
    collect(root, &mut sensors);
    let mut set = SensorSet { cpu_temp_c: None, per_core_clock_mhz: vec![], voltages: vec![], fans_rpm: vec![] };
    let (mut package, mut max_cpu) = (None, None::<f32>);
    for (id, text, v) in sensors {
        let seg: Vec<&str> = id.split('/').filter(|s| !s.is_empty()).collect();
        let is_cpu = seg.first().is_some_and(|h| h.contains("cpu"));
        // Ids look like /<hw>[/<chip>]/<n>/<type>/<n>, so the type is the second-to-last segment.
        match seg.len().checked_sub(2).and_then(|i| seg.get(i)).copied() {
            Some("temperature") if is_cpu => {
                if ["Package", "Tctl", "Tdie"].iter().any(|k| text.contains(k)) {
                    package.get_or_insert(v);
                }
                max_cpu = Some(max_cpu.map_or(v, |m| m.max(v)));
            }
            Some("clock") if is_cpu && text.contains("Core") => set.per_core_clock_mhz.push(v),
            Some("voltage") => set.voltages.push((text.to_string(), v)),
            Some("fan") => set.fans_rpm.push((text.to_string(), v.round().max(0.0) as u32)),
            _ => {}
        }
    }
    set.cpu_temp_c = package.or(max_cpu);
    set
}

fn collect<'a>(node: &'a Value, out: &mut Vec<(&'a str, &'a str, f32)>) {
    if let (Some(id), Some(v)) = (node["SensorId"].as_str(), node["Value"].as_str().and_then(parse_value)) {
        out.push((id, node["Text"].as_str().unwrap_or(""), v));
    }
    for c in node["Children"].as_array().into_iter().flatten() {
        collect(c, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_value_handles_decimal_comma_units_and_garbage() {
        assert_eq!(parse_value("45,5 °C"), Some(45.5));
        assert_eq!(parse_value("1.23 V"), Some(1.23));
        assert_eq!(parse_value("1200 RPM"), Some(1200.0));
        assert_eq!(parse_value(" -3,0 °C"), Some(-3.0));
        assert_eq!(parse_value("-"), None);
        assert_eq!(parse_value(""), None);
        assert_eq!(parse_value("n/a"), None);
        assert_eq!(parse_value("1,2,3 V"), None);
    }

    const FIXTURE: &str = r#"{"id":0,"Text":"Sensor","Value":"","Children":[
      {"id":1,"Text":"PC","Value":"","Children":[
        {"id":2,"Text":"AMD Ryzen 7","HardwareId":"/amdcpu/0","Value":"","Children":[
          {"id":3,"Text":"Clocks","Value":"","Children":[
            {"id":4,"Text":"Core #1","SensorId":"/amdcpu/0/clock/1","Value":"4200,5 MHz","Children":[]},
            {"id":5,"Text":"Core #2","SensorId":"/amdcpu/0/clock/2","Value":"3900 MHz","Children":[]},
            {"id":6,"Text":"Bus Speed","SensorId":"/amdcpu/0/clock/0","Value":"100 MHz","Children":[]}]},
          {"id":7,"Text":"Temperatures","Value":"","Children":[
            {"id":8,"Text":"Core (CCD1)","SensorId":"/amdcpu/0/temperature/3","Value":"70,0 °C","Children":[]},
            {"id":9,"Text":"Core (Tctl/Tdie)","SensorId":"/amdcpu/0/temperature/2","Value":"65,5 °C","Children":[]}]},
          {"id":10,"Text":"Voltages","Value":"","Children":[
            {"id":11,"Text":"Core (SVI2 TFN)","SensorId":"/amdcpu/0/voltage/0","Value":"1,23 V","Children":[]}]}]},
        {"id":12,"Text":"Nuvoton","HardwareId":"/lpc/nct6798d/0","Value":"","Children":[
          {"id":13,"Text":"Fan #1","SensorId":"/lpc/nct6798d/0/fan/0","Value":"1200 RPM","Children":[]},
          {"id":14,"Text":"Fan #2","SensorId":"/lpc/nct6798d/0/fan/1","Value":"-","Children":[]},
          {"id":15,"Text":"System","SensorId":"/lpc/nct6798d/0/temperature/0","Value":"90 °C","Children":[]}]}]}]}"#;

    #[test]
    fn map_data_json_uses_sensor_id_segments() {
        let s = map_data_json(&serde_json::from_str(FIXTURE).unwrap());
        assert_eq!(s.cpu_temp_c, Some(65.5), "Tctl/Tdie wins over the hotter core sensor and non-CPU temps");
        assert_eq!(s.per_core_clock_mhz, vec![4200.5, 3900.0]);
        assert_eq!(s.voltages, vec![("Core (SVI2 TFN)".to_string(), 1.23)]);
        assert_eq!(s.fans_rpm, vec![("Fan #1".to_string(), 1200)], "unparsable fan is skipped, not 0");
    }

    #[test]
    fn map_data_json_falls_back_to_max_cpu_temp_then_none() {
        let fixture = FIXTURE.replace("Core (Tctl/Tdie)", "Core (CCD2)");
        assert_eq!(map_data_json(&serde_json::from_str(&fixture).unwrap()).cpu_temp_c, Some(70.0));
        assert_eq!(map_data_json(&serde_json::json!({"Children": []})).cpu_temp_c, None);
    }
}
