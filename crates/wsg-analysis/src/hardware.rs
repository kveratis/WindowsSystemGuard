//! Motherboard, BIOS and memory facts for the post-mortem's out-of-band checklist.

use std::process::Command;

use wsg_events::{format_system_time, query};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DimmInfo {
    pub slot: String,
    pub manufacturer: String,
    pub part_number: String,
    pub capacity_bytes: u64,
    /// Speed the module is rated for, in MT/s as Windows reports it.
    pub rated_mhz: Option<u32>,
    /// Speed it is running at.
    pub configured_mhz: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HardwareContext {
    pub motherboard: String,
    /// WMI does not report the chipset, so this is `None` until another source is wired in.
    pub chipset: Option<String>,
    pub bios_version: String,
    /// WMI does not report the AGESA version; read it from the BIOS setup screen.
    pub agesa: Option<String>,
    pub dimms: Vec<DimmInfo>,
    /// `Some(true)` only when memory runs faster than the DDR4 standard's top speed, which needs
    /// XMP/DOCP or a manual overclock. `None` means Windows cannot tell, not that it is off.
    pub xmp_docp_enabled: Option<bool>,
    /// Drivers updated in the last 14 days (Kernel-PnP 400 with `DeviceUpdated`), newest last.
    pub recent_driver_changes: Vec<String>,
    /// Sources that could not be read.
    pub notes: Vec<String>,
}

/// Fastest speed in the DDR4 standard, in MT/s.
const DDR4_TOP_JEDEC_MHZ: u32 = 3200;
/// SMBIOS memory type code for DDR4.
const SMBIOS_DDR4: u64 = 26;
const DRIVER_LOOKBACK_NS: i64 = 14 * 24 * 3600 * 1_000_000_000;

impl HardwareContext {
    /// Reads what this machine reports. A source that fails leaves its fields empty and adds a note.
    // shortcut: WMI is read by running PowerShell once (about a second); use COM directly if the
    // post-mortem must avoid starting a process.
    pub fn collect() -> HardwareContext {
        let mut h = HardwareContext::default();
        match wmi_json() {
            Ok(text) => h.apply_wmi(&text),
            Err(e) => h.notes.push(format!("hardware facts not read: {e}")),
        }
        let now = wsg_core::now_utc_ns();
        match query("Microsoft-Windows-Kernel-PnP/Configuration", now - DRIVER_LOOKBACK_NS, now, 5) {
            Ok(events) => {
                for e in events.iter().filter(|e| e.event_id == 400 && e.payload.get("DeviceUpdated").is_some_and(|v| v == "true")) {
                    let get = |k: &str| e.payload.get(k).map(String::as_str).unwrap_or("?");
                    h.recent_driver_changes.push(format!(
                        "{} {} {} ({})",
                        format_system_time(e.utc_ns),
                        get("DriverName"),
                        get("DriverVersion"),
                        get("DeviceInstanceId")
                    ));
                }
            }
            Err(e) => h.notes.push(format!("driver changes not read: {e}")),
        }
        h
    }

    fn apply_wmi(&mut self, text: &str) {
        let v: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                self.notes.push(format!("hardware facts unreadable: {e}"));
                return;
            }
        };
        let s = |x: &serde_json::Value| x.as_str().unwrap_or_default().trim().to_string();
        let board = &v["board"];
        self.motherboard = format!("{} {}", s(&board["Manufacturer"]), s(&board["Product"])).trim().to_string();
        self.bios_version = s(&v["bios"]["SMBIOSBIOSVersion"]);
        let mut ddr4_fast = false;
        for d in v["dimms"].as_array().into_iter().flatten() {
            let mhz = |k: &str| d[k].as_u64().filter(|n| *n > 0).map(|n| n as u32);
            let configured = mhz("ConfiguredClockSpeed");
            ddr4_fast |= d["SMBIOSMemoryType"].as_u64() == Some(SMBIOS_DDR4)
                && configured.is_some_and(|c| c > DDR4_TOP_JEDEC_MHZ);
            self.dimms.push(DimmInfo {
                slot: s(&d["DeviceLocator"]),
                manufacturer: s(&d["Manufacturer"]),
                part_number: s(&d["PartNumber"]),
                capacity_bytes: d["Capacity"].as_u64().unwrap_or(0),
                rated_mhz: mhz("Speed"),
                configured_mhz: configured,
            });
        }
        self.xmp_docp_enabled = ddr4_fast.then_some(true);
    }
}

fn wmi_json() -> Result<String, String> {
    let script = "$ErrorActionPreference='Stop'; \
        $b = Get-CimInstance Win32_BaseBoard | Select-Object -First 1 Manufacturer,Product; \
        $f = Get-CimInstance Win32_BIOS | Select-Object -First 1 SMBIOSBIOSVersion,Manufacturer; \
        $d = @(Get-CimInstance Win32_PhysicalMemory | Select-Object DeviceLocator,Manufacturer,PartNumber,Capacity,Speed,ConfiguredClockSpeed,SMBIOSMemoryType); \
        [pscustomobject]@{ board=$b; bios=$f; dimms=$d } | ConvertTo-Json -Depth 4 -Compress";
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| format!("cannot start powershell: {e}"))?;
    if !out.status.success() {
        return Err(format!("powershell exited with {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
