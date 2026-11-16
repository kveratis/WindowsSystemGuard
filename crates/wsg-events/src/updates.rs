//! What was installed or updated and when: Windows Update, hotfixes and driver configuration.
//! A package that installs again and again is the kind of lead a freeze investigation needs.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use crate::reader::{query, EventError};
use crate::xml::{parse_system_time, EventRecord};

const WU_PROVIDER: &str = "Microsoft-Windows-WindowsUpdateClient";
const PNP_CONFIG_CHANNEL: &str = "Microsoft-Windows-Kernel-PnP/Configuration";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateKind {
    Started,
    Succeeded,
    Failed { code: String },
    Hotfix,
    DriverInstall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateEvent {
    pub utc_ns: i64,
    pub kind: UpdateKind,
    pub name: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallLoop {
    pub name: String,
    pub count: u32,
    pub first_utc_ns: i64,
    pub last_utc_ns: i64,
}

/// Turns one event-log record into an update event, or `None` if it is not one we track:
/// WindowsUpdateClient 43 (started), 19 (succeeded) and 20 (failed), and Kernel-PnP 400 (a device
/// was configured with a driver).
pub fn update_event_from(e: &EventRecord) -> Option<UpdateEvent> {
    let get = |k: &str| e.payload.get(k).cloned().unwrap_or_default();
    let (kind, name, detail) = match (e.provider.as_str(), e.event_id) {
        (WU_PROVIDER, 43) => (UpdateKind::Started, get("updateTitle"), String::new()),
        (WU_PROVIDER, 19) => (UpdateKind::Succeeded, get("updateTitle"), String::new()),
        (WU_PROVIDER, 20) => {
            let code = normalize_code(&get("errorCode"));
            (UpdateKind::Failed { code: code.clone() }, get("updateTitle"), format!("error {code}"))
        }
        ("Microsoft-Windows-Kernel-PnP", 400) => {
            let name = match get("DriverName") {
                n if n.is_empty() => get("DeviceInstanceId"),
                n => n,
            };
            let detail = format!(
                "device {} driver {} {} from {}",
                get("DeviceInstanceId"),
                get("DriverVersion"),
                get("DriverDate"),
                get("DriverProvider")
            );
            (UpdateKind::DriverInstall, name, detail)
        }
        _ => return None,
    };
    (!name.is_empty()).then_some(UpdateEvent { utc_ns: e.utc_ns, kind, name, detail })
}

/// `0x80073d02` to `0x80073D02`; anything that is not a hex code is returned unchanged.
fn normalize_code(c: &str) -> String {
    match c.strip_prefix("0x").or_else(|| c.strip_prefix("0X")) {
        Some(h) if !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()) => format!("0x{}", h.to_ascii_uppercase()),
        _ => c.to_string(),
    }
}

/// Updates, hotfixes and driver installs in the window, oldest first. Fails if the System log cannot
/// be read; a missing optional source is reported by `update_timeline_with_notes` instead.
pub fn update_timeline(from_utc_ns: i64, to_utc_ns: i64) -> Result<Vec<UpdateEvent>, EventError> {
    update_timeline_with_notes(from_utc_ns, to_utc_ns).map(|(events, _)| events)
}

/// Like `update_timeline`, plus a note for each optional source that could not be read
/// (the PnP configuration channel, the hotfix list).
pub fn update_timeline_with_notes(from_utc_ns: i64, to_utc_ns: i64) -> Result<(Vec<UpdateEvent>, Vec<String>), EventError> {
    let mut out: Vec<UpdateEvent> = query("System", from_utc_ns, to_utc_ns, 5)?
        .iter()
        .filter(|e| e.provider == WU_PROVIDER)
        .filter_map(update_event_from)
        .collect();
    let mut notes = Vec::new();
    match query(PNP_CONFIG_CHANNEL, from_utc_ns, to_utc_ns, 5) {
        Ok(v) => out.extend(v.iter().filter_map(update_event_from)),
        Err(e) => notes.push(format!("driver installs not read: {e}")),
    }
    match installed_hotfixes() {
        Ok(v) => out.extend(v.into_iter().filter(|h| h.utc_ns >= from_utc_ns && h.utc_ns <= to_utc_ns)),
        Err(e) => notes.push(format!("hotfix list not read: {e}")),
    }
    out.sort_by(|a, b| a.utc_ns.cmp(&b.utc_ns).then_with(|| a.name.cmp(&b.name)));
    Ok((out, notes))
}

/// Hotfixes from `Win32_QuickFixEngineering`. Windows records only the install date, so the time
/// is that date's midnight.
// shortcut: reads WMI by running PowerShell once (about a second); call WMI directly if the report
// ever needs to avoid starting a process.
fn installed_hotfixes() -> Result<Vec<UpdateEvent>, String> {
    let script = "Get-CimInstance Win32_QuickFixEngineering | Where-Object { $_.InstalledOn } | ForEach-Object { '{0}|{1}|{2}' -f $_.HotFixID, $_.InstalledOn.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $_.Description }";
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| format!("cannot start powershell: {e}"))?;
    if !out.status.success() {
        return Err(format!("powershell exited with {}", out.status));
    }
    Ok(parse_hotfix_lines(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_hotfix_lines(text: &str) -> Vec<UpdateEvent> {
    text.lines()
        .filter_map(|l| {
            let mut p = l.trim().splitn(3, '|');
            let (id, when, desc) = (p.next()?, p.next()?, p.next().unwrap_or_default());
            Some(UpdateEvent {
                utc_ns: parse_system_time(when)?,
                kind: UpdateKind::Hotfix,
                name: id.to_string(),
                detail: desc.to_string(),
            })
        })
        .collect()
}

/// Names that were installed, failed or reconfigured at least `min_repeats` times inside one
/// `window`. Started events and hotfixes are not counted, so one install attempt counts once. The
/// reported span is the busiest window for that name. Most repeated first.
pub fn detect_install_loops(events: &[UpdateEvent], min_repeats: u32, window: Duration) -> Vec<InstallLoop> {
    let span = i64::try_from(window.as_nanos()).unwrap_or(i64::MAX);
    let mut by_name: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    for e in events {
        if matches!(e.kind, UpdateKind::Succeeded | UpdateKind::Failed { .. } | UpdateKind::DriverInstall) {
            by_name.entry(&e.name).or_default().push(e.utc_ns);
        }
    }
    let mut loops: Vec<InstallLoop> = by_name
        .into_iter()
        .filter_map(|(name, mut t)| {
            t.sort_unstable();
            // Slide a window over the sorted times and keep the one holding the most installs.
            let (mut best, mut lo) = ((0usize, 0usize, 0usize), 0usize);
            for hi in 0..t.len() {
                while t[hi] - t[lo] > span {
                    lo += 1;
                }
                if hi - lo + 1 > best.0 {
                    best = (hi - lo + 1, lo, hi);
                }
            }
            (best.0 as u32 >= min_repeats.max(2)).then(|| InstallLoop {
                name: name.to_string(),
                count: best.0 as u32,
                first_utc_ns: t[best.1],
                last_utc_ns: t[best.2],
            })
        })
        .collect();
    loops.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    loops
}
