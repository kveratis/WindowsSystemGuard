//! Process enumeration via Toolhelp + per-process query APIs.
//! CPU% and I/O rate come from the delta against the previous call. `new` runs one priming
//! pass, so the first caller-visible collect already has deltas; a process first seen later
//! reports 0.0 / 0 until its second sample.

use super::wsl::exe_name;
use super::{CollectOutcome, Collector, SampleFragment};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::ALL_PROCESSOR_GROUPS;
use windows_sys::Win32::System::Threading::*;
use wsg_core::sample::ProcStat;

pub struct ProcessCollector {
    top_n: usize,
    ncpu: f64,
    prev: HashMap<u32, (u64, u64)>, // pid -> (cpu 100ns ticks, io bytes)
    prev_at: Option<Instant>,
    enum_ms: u64,
}

fn ft(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

impl ProcessCollector {
    pub fn new(top_n: usize) -> Self {
        // SAFETY: no pointers; counts logical processors across all groups.
        let ncpu = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
        let mut c = ProcessCollector {
            top_n,
            ncpu: ncpu.max(1) as f64,
            prev: HashMap::new(),
            prev_at: None,
            enum_ms: 0,
        };
        // Timed priming pass: measures enumeration cost (`last_enumeration_ms`) and seeds deltas.
        c.collect(Duration::from_secs(30));
        c
    }

    /// Wall time of the most recent full enumeration, in milliseconds.
    pub fn last_enumeration_ms(&self) -> u64 {
        self.enum_ms
    }

    /// (cpu ticks, io bytes, working set, handles); None if the process cannot be opened.
    fn query(pid: u32) -> Option<(u64, u64, u64, u32)> {
        // SAFETY: standard query APIs on a handle opened and closed here; structs are plain data.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let (mut c, mut e, mut k, mut u): (FILETIME, FILETIME, FILETIME, FILETIME) =
                (std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed());
            let times = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) != 0;
            let mut io: IO_COUNTERS = std::mem::zeroed();
            let io_ok = GetProcessIoCounters(h, &mut io) != 0;
            let mut m: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            m.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            let mem_ok = GetProcessMemoryInfo(h, &mut m, m.cb) != 0;
            let mut handles = 0u32;
            GetProcessHandleCount(h, &mut handles);
            CloseHandle(h);
            times.then(|| {
                let iob = if io_ok { io.ReadTransferCount + io.WriteTransferCount } else { 0 };
                (ft(k) + ft(u), iob, if mem_ok { m.WorkingSetSize as u64 } else { 0 }, handles)
            })
        }
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "processes"
    }

    // shortcut: budget is checked between processes only; a single blocking query is not
    // cancellable. Fine unless one process query is seen to hang.
    fn collect(&mut self, budget: Duration) -> CollectOutcome {
        let t = Instant::now();
        // SAFETY: snapshot handle is closed below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return CollectOutcome::Unavailable("process snapshot failed".into());
        }
        let dt = self.prev_at.map(|p| t.duration_since(p).as_secs_f64());
        // SAFETY: PROCESSENTRY32W is plain data; all-zero is valid.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut procs: Vec<(f64, ProcStat)> = vec![];
        let mut next = HashMap::new();
        let mut ok = unsafe { Process32FirstW(snap, &mut e) } != 0;
        let mut timed_out = false;
        while ok {
            if t.elapsed() > budget {
                timed_out = true;
                break;
            }
            let pid = e.th32ProcessID;
            if let Some((cpu, io, ws, handles)) = Self::query(pid) {
                let (cpu_pct, io_rate) = match (dt, self.prev.get(&pid)) {
                    (Some(dt), Some(&(pc, pio))) if dt > 0.0 => (
                        (cpu.saturating_sub(pc) as f64 / 1e7 / dt / self.ncpu * 100.0).clamp(0.0, 100.0),
                        (io.saturating_sub(pio) as f64 / dt) as u64,
                    ),
                    _ => (0.0, 0),
                };
                next.insert(pid, (cpu, io));
                let score = cpu_pct / 100.0 + io_rate as f64 / 1e8 + ws as f64 / 8e9;
                procs.push((
                    score,
                    ProcStat {
                        pid,
                        name: exe_name(&e),
                        cpu_pct: cpu_pct as f32,
                        working_set_bytes: ws,
                        io_bytes_per_sec: io_rate,
                        handles,
                    },
                ));
            }
            ok = unsafe { Process32NextW(snap, &mut e) } != 0;
        }
        // SAFETY: snap valid, closed once.
        unsafe { CloseHandle(snap) };
        if timed_out {
            return CollectOutcome::TimedOut;
        }
        self.enum_ms = t.elapsed().as_millis() as u64;
        self.prev = next;
        self.prev_at = Some(t);
        procs.sort_by(|a, b| b.0.total_cmp(&a.0));
        let me = std::process::id();
        let mut top: Vec<ProcStat> = procs.iter().take(self.top_n).map(|p| p.1.clone()).collect();
        if self.top_n > 0 && !top.iter().any(|p| p.pid == me) {
            if let Some(s) = procs.iter().find(|p| p.1.pid == me) {
                top.pop();
                top.push(s.1.clone());
            }
        }
        CollectOutcome::Ok(SampleFragment::Procs(top))
    }
}
