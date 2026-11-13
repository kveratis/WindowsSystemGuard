//! PDH-backed CPU, memory, disk and network counters. Rate counters need two samples, so
//! `new` primes the query; the first `collect` is valid once some time has passed since `new`.

use super::{value, CollectOutcome, Collector, SampleFragment};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Performance::*;
use wsg_core::sample::{CpuStats, DiskStats, MemStats, NetStats, Reading};

#[derive(Debug, thiserror::Error)]
pub enum CounterError {
    #[error("PDH call {0} failed with 0x{1:08x}")]
    Pdh(&'static str, u32),
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn add(q: PDH_HQUERY, path: &str) -> Option<PDH_HCOUNTER> {
    let mut h: PDH_HCOUNTER = std::ptr::null_mut();
    // SAFETY: path is NUL-terminated and outlives the call; h is a valid out-pointer.
    let rc = unsafe { PdhAddEnglishCounterW(q, wide(path).as_ptr(), 0, &mut h) };
    (rc == 0).then_some(h)
}

fn scalar(h: Option<PDH_HCOUNTER>) -> Option<f64> {
    // SAFETY: plain-data union; all-zero is valid.
    let mut v: PDH_FMT_COUNTERVALUE = unsafe { std::mem::zeroed() };
    // SAFETY: h came from PdhAddEnglishCounterW on a live query; v is a valid out-pointer.
    let rc = unsafe { PdhGetFormattedCounterValue(h?, PDH_FMT_DOUBLE, std::ptr::null_mut(), &mut v) };
    // SAFETY: PDH_FMT_DOUBLE was requested, so doubleValue is the active member.
    (rc == 0 && v.CStatus == 0).then_some(unsafe { v.Anonymous.doubleValue })
}

/// (instance name, value) pairs for a wildcard counter, `_Total` excluded. `None` (with a note in
/// `errors`) if the counter was never added or the read failed; items with a bad status are
/// dropped and noted, so the instance is simply absent for this counter.
fn array(h: Option<PDH_HCOUNTER>, what: &str, errors: &mut Vec<String>) -> Option<Pairs> {
    let Some(h) = h else {
        errors.push(format!("{what}: counter not available"));
        return None;
    };
    let (mut size, mut n) = (0u32, 0u32);
    // SAFETY: size query with a null buffer, per PDH contract (returns PDH_MORE_DATA).
    let rc = unsafe { PdhGetFormattedCounterArrayW(h, PDH_FMT_DOUBLE, &mut size, &mut n, std::ptr::null_mut()) };
    const PDH_MORE_DATA: u32 = 0x800007D2;
    const PDH_NO_DATA: u32 = 0x800007D5;
    if size == 0 {
        // A successful query with no instances (e.g. no adapters) is an empty value, not an error.
        if rc == 0 || rc == PDH_NO_DATA {
            return Some(vec![]);
        }
        errors.push(format!("{what}: size query failed 0x{rc:08x}"));
        return None;
    }
    if rc != PDH_MORE_DATA && rc != 0 {
        errors.push(format!("{what}: size query failed 0x{rc:08x}"));
        return None;
    }
    // u64 backing keeps the buffer 8-byte aligned for PDH_FMT_COUNTERVALUE_ITEM_W.
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    let p = buf.as_mut_ptr() as *mut PDH_FMT_COUNTERVALUE_ITEM_W;
    // SAFETY: buf is at least `size` bytes; PDH fills n items whose name pointers point into buf.
    let rc = unsafe { PdhGetFormattedCounterArrayW(h, PDH_FMT_DOUBLE, &mut size, &mut n, p) };
    if rc != 0 {
        errors.push(format!("{what}: PDH 0x{rc:08x}"));
        return None;
    }
    let mut out = vec![];
    for i in 0..n as usize {
        // SAFETY: i < n items initialised by PDH above.
        let it = unsafe { &*p.add(i) };
        let mut len = 0;
        // SAFETY: szName is a NUL-terminated wide string inside buf.
        while unsafe { *it.szName.add(len) } != 0 {
            len += 1;
        }
        let name = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(it.szName, len) });
        if name == "_Total" {
            continue;
        }
        if it.FmtValue.CStatus != 0 {
            errors.push(format!("{what}: instance '{name}' bad status 0x{:08x}", it.FmtValue.CStatus));
            continue;
        }
        // SAFETY: PDH_FMT_DOUBLE requested.
        out.push((name, unsafe { it.FmtValue.Anonymous.doubleValue }));
    }
    Some(out)
}

type Pairs = Vec<(String, f64)>;

pub(crate) fn net_stats(v: Pairs) -> Vec<NetStats> {
    v.into_iter()
        .map(|(adapter, v)| NetStats { adapter, bytes_per_sec: v as u64 })
        .collect()
}

/// A disk is emitted only when all four values exist for its instance; otherwise it is skipped
/// and noted. Never zero-fills.
pub(crate) fn build_disks(
    queue: &[(String, f64)],
    rlat: &[(String, f64)],
    wlat: &[(String, f64)],
    bps: &[(String, f64)],
    errors: &mut Vec<String>,
) -> Vec<DiskStats> {
    let get = |v: &[(String, f64)], id: &str| v.iter().find(|(n, _)| n == id).map(|x| x.1);
    let mut out = vec![];
    for (id, q) in queue {
        match (get(rlat, id), get(wlat, id), get(bps, id)) {
            (Some(r), Some(w), Some(b)) => out.push(DiskStats {
                disk_id: id.clone(),
                queue_len: *q as f32,
                read_latency_ms: (r * 1000.0) as f32,
                write_latency_ms: (w * 1000.0) as f32,
                bytes_per_sec: b as u64,
            }),
            _ => errors.push(format!("disk '{id}': missing counter value, skipped")),
        }
    }
    out
}

/// `None` (fragment omitted) when any of the four counters failed as a whole.
pub(crate) fn disk_part(
    q: Option<Pairs>,
    r: Option<Pairs>,
    w: Option<Pairs>,
    b: Option<Pairs>,
    errors: &mut Vec<String>,
) -> Option<Vec<DiskStats>> {
    Some(build_disks(&q?, &r?, &w?, &b?, errors))
}

struct DiskC {
    queue: Option<PDH_HCOUNTER>,
    rd: Option<PDH_HCOUNTER>,
    wr: Option<PDH_HCOUNTER>,
    bps: Option<PDH_HCOUNTER>,
}

pub struct CounterCollector {
    q: PDH_HQUERY,
    cpu: Option<PDH_HCOUNTER>,
    dpc: Option<PDH_HCOUNTER>,
    irq: Option<PDH_HCOUNTER>,
    commit: Option<PDH_HCOUNTER>,
    avail: Option<PDH_HCOUNTER>,
    nonpaged: Option<PDH_HCOUNTER>,
    paged: Option<PDH_HCOUNTER>,
    disk: DiskC,
    net: Option<PDH_HCOUNTER>,
    errors: Vec<String>,
}

// SAFETY: PDH handles are plain integers and the collector is only used from one thread at a time.
unsafe impl Send for CounterCollector {}

impl CounterCollector {
    pub fn new() -> Result<Self, CounterError> {
        let mut q: PDH_HQUERY = std::ptr::null_mut();
        // SAFETY: null source = live data; q is a valid out-pointer.
        let rc = unsafe { PdhOpenQueryW(std::ptr::null(), 0, &mut q) };
        if rc != 0 {
            return Err(CounterError::Pdh("PdhOpenQueryW", rc));
        }
        let c = CounterCollector {
            q,
            cpu: add(q, r"\Processor(_Total)\% Processor Time"),
            dpc: add(q, r"\Processor(_Total)\% DPC Time"),
            irq: add(q, r"\Processor(_Total)\% Interrupt Time"),
            commit: add(q, r"\Memory\Committed Bytes"),
            avail: add(q, r"\Memory\Available Bytes"),
            nonpaged: add(q, r"\Memory\Pool Nonpaged Bytes"),
            paged: add(q, r"\Memory\Pool Paged Bytes"),
            disk: DiskC {
                queue: add(q, r"\PhysicalDisk(*)\Avg. Disk Queue Length"),
                rd: add(q, r"\PhysicalDisk(*)\Avg. Disk sec/Read"),
                wr: add(q, r"\PhysicalDisk(*)\Avg. Disk sec/Write"),
                bps: add(q, r"\PhysicalDisk(*)\Disk Bytes/sec"),
            },
            net: add(q, r"\Network Interface(*)\Bytes Total/sec"),
            errors: vec![],
        };
        // SAFETY: q is a live query. Primes the rate counters.
        let rc = unsafe { PdhCollectQueryData(q) };
        if rc != 0 {
            return Err(CounterError::Pdh("PdhCollectQueryData", rc));
        }
        Ok(c)
    }
}

impl CounterCollector {
    /// Problems noted by the most recent `collect` (empty when everything read cleanly).
    pub fn last_errors(&self) -> &[String] {
        &self.errors
    }
}

impl Drop for CounterCollector {
    fn drop(&mut self) {
        // SAFETY: q was opened by PdhOpenQueryW and is closed exactly once.
        unsafe { PdhCloseQuery(self.q) };
    }
}

impl Collector for CounterCollector {
    fn name(&self) -> &'static str {
        "counters"
    }

    // shortcut: PdhCollectQueryData blocks and cannot be cancelled; budget is checked only after
    // it returns. Upgrade to a worker thread if PDH is seen to stall.
    fn collect(&mut self, budget: Duration) -> CollectOutcome {
        self.errors.clear();
        let t = Instant::now();
        // SAFETY: q is live for the lifetime of self.
        let rc = unsafe { PdhCollectQueryData(self.q) };
        if rc != 0 {
            return CollectOutcome::Unavailable(format!("PdhCollectQueryData 0x{rc:08x}"));
        }
        if t.elapsed() > budget {
            return CollectOutcome::TimedOut;
        }
        let pct = |h| scalar(h).map(|v| v.clamp(0.0, 100.0) as f32);
        let cpu = match (pct(self.cpu), pct(self.dpc), pct(self.irq)) {
            (Some(total_pct), Some(dpc_pct), Some(interrupt_pct)) => {
                value(CpuStats { total_pct, dpc_pct, interrupt_pct })
            }
            _ => Reading::Unavailable { reason: "cpu counters not ready".into() },
        };
        let mem = match (scalar(self.commit), scalar(self.avail), scalar(self.nonpaged), scalar(self.paged)) {
            (Some(c), Some(a), Some(n), Some(p)) => value(MemStats {
                commit_bytes: c as u64,
                available_bytes: a as u64,
                nonpaged_pool_bytes: n as u64,
                paged_pool_bytes: p as u64,
            }),
            _ => Reading::Unavailable { reason: "memory counters unavailable".into() },
        };
        if t.elapsed() > budget {
            return CollectOutcome::TimedOut;
        }
        let mut errors = vec![];
        let d0 = errors.len();
        let disks = disk_part(
            array(self.disk.queue, "disk queue", &mut errors),
            array(self.disk.rd, "disk read latency", &mut errors),
            array(self.disk.wr, "disk write latency", &mut errors),
            array(self.disk.bps, "disk bytes/sec", &mut errors),
            &mut errors,
        );
        let disks_frag = match disks {
            Some(d) => SampleFragment::Disks(d),
            None => SampleFragment::DisksUnavailable(errors[d0..].join("; ")),
        };
        let n0 = errors.len();
        let net_frag = match array(self.net, "net bytes/sec", &mut errors) {
            Some(v) => SampleFragment::Net(net_stats(v)),
            None => SampleFragment::NetUnavailable(errors[n0..].join("; ")),
        };
        if matches!(cpu, Reading::Unavailable { .. }) {
            errors.push("cpu counters not ready".into());
        }
        if matches!(mem, Reading::Unavailable { .. }) {
            errors.push("memory counters unavailable".into());
        }
        self.errors = errors;
        CollectOutcome::Ok(SampleFragment::Multi(vec![
            SampleFragment::Cpu(cpu),
            SampleFragment::Mem(mem),
            disks_frag,
            net_frag,
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(items: &[(&str, f64)]) -> Pairs {
        items.iter().map(|(n, v)| (n.to_string(), *v)).collect()
    }

    #[test]
    fn disk_without_all_four_counters_is_skipped_not_zero_filled() {
        let mut errs = vec![];
        let d = build_disks(
            &p(&[("0 C:", 1.0), ("1 D:", 2.0)]),
            &p(&[("0 C:", 0.002), ("1 D:", 0.003)]),
            &p(&[("0 C:", 0.004)]), // D: write latency missing
            &p(&[("0 C:", 100.0), ("1 D:", 200.0)]),
            &mut errs,
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].disk_id, "0 C:");
        assert_eq!(d[0].bytes_per_sec, 100);
        assert!(errs.iter().any(|e| e.contains("1 D:")));
    }

    #[test]
    fn counter_failure_is_reported_in_last_errors() {
        let mut errs = vec![];
        assert!(array(None, "disk queue", &mut errs).is_none());
        assert!(errs[0].contains("disk queue"));
        assert!(disk_part(None, Some(vec![]), Some(vec![]), Some(vec![]), &mut errs).is_none());
    }
}
