//! Reads events through the Windows Event Log API (`EvtQuery`, `EvtRender`, `EvtFormatMessage`).

use std::collections::HashMap;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtFormatMessage, EvtGetChannelConfigProperty, EvtNext, EvtOpenChannelConfig,
    EvtOpenPublisherMetadata, EvtQuery, EvtRender, EVT_VARIANT,
};

use crate::xml::{format_system_time, parse_event_xml, EventRecord, XmlError};

/// Channels the post-mortem reads. WHEA-Logger events arrive through `System`.
pub const DEFAULT_CHANNELS: [&str; 7] = [
    "System",
    "Application",
    "Microsoft-Windows-Kernel-PnP/Configuration",
    "Microsoft-Windows-Hyper-V-VmSwitch-Operational",
    "Microsoft-Windows-Storage-ClassPnP/Operational",
    "Microsoft-Windows-Kernel-Boot/Operational",
    "Microsoft-Windows-Kernel-EventTracing/Admin",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    Ok,
    Disabled,
    AccessDenied,
    Missing,
    /// Enabled, but the oldest retained event is newer than the start of the window asked for.
    RolledOver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStatus {
    pub name: String,
    pub state: ChannelState,
}

impl ChannelStatus {
    /// Whether `query` can return events from this channel (a rolled-over channel still can).
    pub fn is_readable(&self) -> bool {
        matches!(self.state, ChannelState::Ok | ChannelState::RolledOver)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("{call} failed for {target}: Win32 error {code}")]
    Win32 { call: &'static str, target: String, code: u32 },
    #[error("event XML: {0}")]
    Xml(#[from] XmlError),
}

const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
const EVT_QUERY_FILE_PATH: u32 = 0x2;
const EVT_QUERY_FORWARD: u32 = 0x100;
const EVT_RENDER_EVENT_XML: u32 = 1;
const EVT_FORMAT_MESSAGE_EVENT: u32 = 1;
const EVT_CHANNEL_CONFIG_ENABLED: i32 = 0;
const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;
const ERROR_EVT_INVALID_CHANNEL_PATH: u32 = 15999;
const BATCH: usize = 64;

/// An `EVT_HANDLE` closed on drop.
struct Handle(isize);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle came from the Event Log API and is closed once.
            unsafe { EvtClose(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn win32(call: &'static str, target: &str) -> EventError {
    // SAFETY: reads the calling thread's last error.
    EventError::Win32 { call, target: target.to_string(), code: unsafe { GetLastError() } }
}

/// Reports whether each wanted channel can be read, so a report can name the ones it skipped.
pub fn inventory_channels(wanted: &[&str]) -> Vec<ChannelStatus> {
    wanted.iter().map(|n| ChannelStatus { name: n.to_string(), state: channel_state(n) }).collect()
}

fn channel_state(name: &str) -> ChannelState {
    let w = wide(name);
    // SAFETY: `w` is NUL terminated and outlives the call.
    let cfg = unsafe { EvtOpenChannelConfig(0, w.as_ptr(), 0) };
    if cfg == 0 {
        // SAFETY: reads the calling thread's last error.
        return match unsafe { GetLastError() } {
            ERROR_ACCESS_DENIED => ChannelState::AccessDenied,
            ERROR_EVT_CHANNEL_NOT_FOUND | ERROR_EVT_INVALID_CHANNEL_PATH => ChannelState::Missing,
            _ => ChannelState::Missing,
        };
    }
    let cfg = Handle(cfg);
    // SAFETY: EVT_VARIANT is plain data; the call fills it.
    let mut v: EVT_VARIANT = unsafe { std::mem::zeroed() };
    let mut used = 0u32;
    // SAFETY: `v` is a valid buffer of `size_of::<EVT_VARIANT>()` bytes.
    let ok = unsafe {
        EvtGetChannelConfigProperty(
            cfg.0,
            EVT_CHANNEL_CONFIG_ENABLED,
            0,
            std::mem::size_of::<EVT_VARIANT>() as u32,
            &mut v,
            &mut used,
        )
    };
    // SAFETY: the Enabled property is a boolean, so `BooleanVal` is the active field.
    if ok != 0 && unsafe { v.Anonymous.BooleanVal } == 0 {
        ChannelState::Disabled
    } else {
        ChannelState::Ok
    }
}

/// Marks readable channels whose oldest retained event is newer than `from_utc_ns` as
/// `RolledOver`, because the start of the window has been overwritten.
pub fn check_rollover(statuses: &mut [ChannelStatus], from_utc_ns: i64) {
    for s in statuses.iter_mut().filter(|s| s.state == ChannelState::Ok) {
        if oldest_event_ns(&s.name, EVT_QUERY_CHANNEL_PATH).is_some_and(|t| t > from_utc_ns) {
            s.state = ChannelState::RolledOver;
        }
    }
}

fn oldest_event_ns(channel: &str, path_flag: u32) -> Option<i64> {
    let events = run_query(channel, path_flag, "*", Some(1), false).ok()?;
    events.first().map(|e| e.utc_ns)
}

/// Events from a live channel with `from_utc_ns <= time <= to_utc_ns` and `Level <= max_level`
/// (1 critical to 5 verbose; events with level 0 are always included), oldest first.
pub fn query(channel: &str, from_utc_ns: i64, to_utc_ns: i64, max_level: u8) -> Result<Vec<EventRecord>, EventError> {
    run_query(channel, EVT_QUERY_CHANNEL_PATH, &xpath(from_utc_ns, to_utc_ns, max_level), None, true)
        .map(|v| in_range(v, from_utc_ns, to_utc_ns))
}

/// Like `query`, for an exported `.evtx` file.
pub fn query_file(path: &Path, from_utc_ns: i64, to_utc_ns: i64, max_level: u8) -> Result<Vec<EventRecord>, EventError> {
    let p = path.to_string_lossy();
    run_query(&p, EVT_QUERY_FILE_PATH, &xpath(from_utc_ns, to_utc_ns, max_level), None, true)
        .map(|v| in_range(v, from_utc_ns, to_utc_ns))
}

/// The XPath filter works in whole milliseconds; the exact bounds are applied afterwards.
fn xpath(from_ns: i64, to_ns: i64, max_level: u8) -> String {
    format!(
        "*[System[(Level <= {max_level}) and TimeCreated[@SystemTime >= '{}' and @SystemTime <= '{}']]]",
        format_system_time(from_ns),
        format_system_time(to_ns.saturating_add(1_000_000)),
    )
}

fn in_range(mut v: Vec<EventRecord>, from_ns: i64, to_ns: i64) -> Vec<EventRecord> {
    v.retain(|e| e.utc_ns >= from_ns && e.utc_ns <= to_ns);
    // The log is in record order, which a clock change can put out of time order.
    v.sort_by_key(|e| (e.utc_ns, e.record_id));
    v
}

fn run_query(
    target: &str,
    path_flag: u32,
    filter: &str,
    limit: Option<usize>,
    render_messages: bool,
) -> Result<Vec<EventRecord>, EventError> {
    let (t, f) = (wide(target), wide(filter));
    let flags = path_flag | EVT_QUERY_FORWARD;
    // SAFETY: both strings are NUL terminated and outlive the call.
    let results = unsafe { EvtQuery(0, t.as_ptr(), f.as_ptr(), flags) };
    if results == 0 {
        return Err(win32("EvtQuery", target));
    }
    let results = Handle(results);
    let mut publishers: HashMap<String, Option<Handle>> = HashMap::new();
    let mut out = Vec::new();
    loop {
        let mut batch = [0isize; BATCH];
        let mut got = 0u32;
        // SAFETY: `batch` holds BATCH handles and `got` receives how many were filled.
        let ok = unsafe { EvtNext(results.0, BATCH as u32, batch.as_mut_ptr(), 1000, 0, &mut got) };
        if ok == 0 {
            // SAFETY: reads the calling thread's last error.
            if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                break;
            }
            return Err(win32("EvtNext", target));
        }
        let handles: Vec<Handle> = batch[..got as usize].iter().map(|&h| Handle(h)).collect();
        for h in &handles {
            let xml = render_xml(h.0).ok_or_else(|| win32("EvtRender", target))?;
            let mut rec = parse_event_xml(&xml)?;
            if render_messages && rec.rendered_message.is_none() {
                rec.rendered_message = message_for(&mut publishers, &rec.provider, h.0);
            }
            out.push(rec);
            if limit.is_some_and(|l| out.len() >= l) {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

fn render_xml(event: isize) -> Option<String> {
    let mut buf: Vec<u16> = vec![0; 4096];
    loop {
        let (mut used, mut props) = (0u32, 0u32);
        // SAFETY: `buf` is a valid buffer of the stated size in bytes.
        let ok = unsafe {
            EvtRender(0, event, EVT_RENDER_EVENT_XML, (buf.len() * 2) as u32, buf.as_mut_ptr().cast(), &mut used, &mut props)
        };
        if ok != 0 {
            let chars = (used as usize / 2).saturating_sub(1);
            return Some(String::from_utf16_lossy(&buf[..chars]));
        }
        // SAFETY: reads the calling thread's last error.
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        buf.resize((used as usize).div_ceil(2) + 1, 0);
    }
}

/// The localized message of `event`, or `None` if the provider's metadata or message cannot be loaded.
fn message_for(cache: &mut HashMap<String, Option<Handle>>, provider: &str, event: isize) -> Option<String> {
    let meta = cache.entry(provider.to_string()).or_insert_with(|| {
        let w = wide(provider);
        // SAFETY: `w` is NUL terminated and outlives the call.
        let h = unsafe { EvtOpenPublisherMetadata(0, w.as_ptr(), std::ptr::null(), 0, 0) };
        (h != 0).then_some(Handle(h))
    });
    let meta = meta.as_ref()?;
    let mut buf: Vec<u16> = vec![0; 1024];
    loop {
        let mut used = 0u32;
        // SAFETY: `buf` is a valid buffer of `buf.len()` characters.
        let ok = unsafe {
            EvtFormatMessage(meta.0, event, 0, 0, std::ptr::null(), EVT_FORMAT_MESSAGE_EVENT, buf.len() as u32, buf.as_mut_ptr(), &mut used)
        };
        if ok != 0 {
            let s = String::from_utf16_lossy(&buf[..(used as usize).saturating_sub(1)]);
            let s = s.trim();
            return (!s.is_empty()).then(|| s.to_string());
        }
        // SAFETY: reads the calling thread's last error.
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        buf.resize(used as usize + 1, 0);
    }
}
