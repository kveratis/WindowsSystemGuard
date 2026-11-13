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

/// (instance name, value) pairs for a wildcard counter, `_Total` excluded.
fn array(h: Option<PDH_HCOUNTER>) -> Vec<(String, f64)> {
    let Some(h) = h else { return vec![] };
    let (mut size, mut n) = (0u32, 0u32);
    // SAFETY: size query with a null buffer, per PDH contract (returns PDH_MORE_DATA).
    unsafe { PdhGetFormattedCounterArrayW(h, PDH_FMT_DOUBLE, &mut size, &mut n, std::ptr::null_mut()) };
    if size == 0 {
        return vec![];
    }
    // u64 backing keeps the buffer 8-byte aligned for PDH_FMT_COUNTERVALUE_ITEM_W.
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    let p = buf.as_mut_ptr() as *mut PDH_FMT_COUNTERVALUE_ITEM_W;
    // SAFETY: buf is at least `size` bytes; PDH fills n items whose name pointers point into buf.
    let rc = unsafe { PdhGetFormattedCounterArrayW(h, PDH_FMT_DOUBLE, &mut size, &mut n, p) };
    if rc != 0 {
        return vec![];
    }
    (0..n as usize)
        .filter_map(|i| {
            // SAFETY: i < n items initialised by PDH above.
            let it = unsafe { &*p.add(i) };
            if it.FmtValue.CStatus != 0 {
                return None;
            }
            let mut len = 0;
            // SAFETY: szName is a NUL-terminated wide string inside buf.
            while unsafe { *it.szName.add(len) } != 0 {
                len += 1;
            }
            let name = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(it.szName, len) });
            // SAFETY: PDH_FMT_DOUBLE requested.
            let v = unsafe { it.FmtValue.Anonymous.doubleValue };
            (name != "_Total").then_some((name, v))
        })
        .collect()
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
        };
        // SAFETY: q is a live query. Primes the rate counters.
        let rc = unsafe { PdhCollectQueryData(q) };
        if rc != 0 {
            return Err(CounterError::Pdh("PdhCollectQueryData", rc));
        }
        Ok(c)
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
        let find = |v: &[(String, f64)], id: &str| v.iter().find(|(n, _)| n == id).map_or(0.0, |x| x.1);
        let (q, r, w, b) = (
            array(self.disk.queue),
            array(self.disk.rd),
            array(self.disk.wr),
            array(self.disk.bps),
        );
        let disks = q
            .iter()
            .map(|(id, ql)| DiskStats {
                disk_id: id.clone(),
                queue_len: *ql as f32,
                read_latency_ms: (find(&r, id) * 1000.0) as f32,
                write_latency_ms: (find(&w, id) * 1000.0) as f32,
                bytes_per_sec: find(&b, id) as u64,
            })
            .collect();
        let net = array(self.net)
            .into_iter()
            .map(|(adapter, v)| NetStats { adapter, bytes_per_sec: v as u64 })
            .collect();
        CollectOutcome::Ok(SampleFragment::Multi(vec![
            SampleFragment::Cpu(cpu),
            SampleFragment::Mem(mem),
            SampleFragment::Disks(disks),
            SampleFragment::Net(net),
        ]))
    }
}
