//! Runs a helper process that may hang (NVML, sensor polling) and reads its JSON lines without
//! ever blocking the caller. A stalled or dead helper is killed and restarted a bounded number
//! of times, then abandoned.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wsg_core::sample::Reading;
pub use wsg_core::stats::HelperStats;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// A helper line longer than this is a protocol error.
pub const MAX_LINE: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct HelperSpec {
    pub exe: PathBuf,
    pub args: Vec<String>,
    /// A line older than this (or no line this long after the helper started) counts as a stall.
    pub call_deadline: Duration,
    pub restart_limit: u32,
    pub restart_window: Duration,
}

/// State shared with one child's thread. Each child gets a fresh slot, so a dying thread
/// cannot touch its successor's state.
#[derive(Default)]
struct Slot {
    child: Option<Child>,
    running_since: Option<Instant>,
    spawn_error: Option<String>,
    job_error: Option<String>,
    cancelled: bool,
    latest: Option<(serde_json::Value, Instant)>,
}

pub struct HelperSupervisor {
    spec: HelperSpec,
    slot: Arc<Mutex<Slot>>,
    started_at: Instant,
    restart_times: VecDeque<Instant>,
    stats: HelperStats,
}

impl HelperSupervisor {
    pub fn spawn(spec: HelperSpec) -> HelperSupervisor {
        let mut s = HelperSupervisor {
            spec,
            slot: Arc::default(),
            started_at: Instant::now(),
            restart_times: VecDeque::new(),
            stats: HelperStats::default(),
        };
        s.start();
        s
    }

    pub fn stats(&self) -> HelperStats {
        self.stats.clone()
    }

    /// Why the current child could not be put in the kill-on-close job, if it could not.
    pub fn job_error(&self) -> Option<String> {
        self.slot.lock().unwrap().job_error.clone()
    }

    /// Returns the helper's latest line and its age; never waits on the helper.
    pub fn poll(&mut self) -> Reading<serde_json::Value> {
        if self.stats.abandoned {
            return unavailable("helper abandoned".into());
        }
        let mut slot = self.slot.lock().unwrap();
        if let Some(e) = slot.spawn_error.take() {
            drop(slot);
            self.restart();
            return unavailable(format!("helper spawn failed: {e}"));
        }
        // shortcut: a spawn still in progress is never a stall, because antivirus can hold
        // CreateProcess for tens of seconds; a CreateProcess that never returns only pins its thread.
        let Some(since) = slot.running_since else {
            return unavailable(format!("helper starting for {} s", self.started_at.elapsed().as_secs()));
        };
        if !matches!(slot.child.as_mut().map(Child::try_wait), Some(Ok(None))) {
            drop(slot);
            self.restart();
            return unavailable("helper exited".into());
        }
        let latest = slot.latest.clone();
        drop(slot);
        let age = latest.as_ref().map_or(since, |(_, at)| *at).elapsed();
        if age > self.spec.call_deadline {
            self.stats.last_stall_utc_ns = Some(utc_now_ns());
            self.restart();
            return unavailable(format!("stale: no output for {} ms", age.as_millis()));
        }
        match latest {
            None => unavailable("no output yet".into()),
            Some((v, _)) if v["ok"] != true => {
                unavailable(v["error"].as_str().unwrap_or("helper reported ok:false").into())
            }
            Some((v, _)) => Reading::Value { v, age_ms: age.as_millis().min(u32::MAX as u128) as u32 },
        }
    }

    /// Spawns the child and reads its stdout on one thread, so a slow spawn never blocks `poll`.
    fn start(&mut self) {
        self.slot = Arc::default();
        self.started_at = Instant::now();
        let slot = self.slot.clone();
        let (exe, args) = (self.spec.exe.clone(), self.spec.args.clone());
        std::thread::spawn(move || {
            let job_error = join_job().err();
            let spawned = Command::new(exe)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            let out = {
                let mut s = slot.lock().unwrap();
                match spawned {
                    Err(e) => {
                        s.spawn_error = Some(e.to_string());
                        return;
                    }
                    Ok(mut c) if s.cancelled => {
                        let _ = c.kill();
                        return;
                    }
                    Ok(mut c) => {
                        s.job_error = job_error;
                        let out = c.stdout.take();
                        s.child = Some(c);
                        s.running_since = Some(Instant::now());
                        out
                    }
                }
            };
            // Ends when the helper exits or is killed and the pipe closes, or on an overlong
            // line: the helper then goes stale (or dies on the closed pipe) and is restarted.
            let mut r = BufReader::new(out.expect("stdout is piped"));
            let mut line = Vec::new();
            loop {
                line.clear();
                match (&mut r).take(MAX_LINE as u64 + 1).read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line.len() > MAX_LINE => break,
                    Ok(_) => {}
                }
                let parsed = std::str::from_utf8(&line).ok().and_then(|t| serde_json::from_str(t).ok());
                if let Some(v) = parsed {
                    slot.lock().unwrap().latest = Some((v, Instant::now()));
                }
            }
        });
    }

    /// Kills the current child and starts a new one, or abandons once the restart budget is spent.
    fn restart(&mut self) {
        self.kill();
        let now = Instant::now();
        while self.restart_times.front().is_some_and(|t| now - *t > self.spec.restart_window) {
            self.restart_times.pop_front();
        }
        if self.restart_times.len() >= self.spec.restart_limit as usize {
            self.stats.abandoned = true;
            return;
        }
        self.restart_times.push_back(now);
        self.stats.restarts += 1;
        self.start();
    }

    /// Kills the child, or tells a spawn still in progress to kill it on arrival. Never waits.
    fn kill(&mut self) {
        let mut s = self.slot.lock().unwrap();
        s.cancelled = true;
        if let Some(mut c) = s.child.take() {
            let _ = c.kill();
        }
    }
}

impl Drop for HelperSupervisor {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Puts this process in a kill-on-close job, once. Children inherit the job when they are
/// created, so a helper is never outside it, even if this process dies right after the spawn;
/// when this process ends, however it ends, the job closes and kills every helper in it.
fn join_job() -> Result<(), String> {
    static JOINED: OnceLock<Result<(), String>> = OnceLock::new();
    JOINED
        .get_or_init(|| unsafe {
            // The job handle is never closed on purpose: its closing is the kill signal.
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return Err(format!("CreateJobObjectW: {}", std::io::Error::last_os_error()));
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of_val(&info) as u32,
            );
            if ok == 0 {
                return Err(format!("SetInformationJobObject: {}", std::io::Error::last_os_error()));
            }
            if AssignProcessToJobObject(h as HANDLE, GetCurrentProcess()) == 0 {
                return Err(format!("AssignProcessToJobObject: {}", std::io::Error::last_os_error()));
            }
            Ok(())
        })
        .clone()
}

fn unavailable<T>(reason: String) -> Reading<T> {
    Reading::Unavailable { reason }
}

fn utc_now_ns() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;

    #[test]
    fn child_is_born_inside_the_job() {
        join_job().unwrap();
        // A plain spawn, with no assignment step: membership comes from this process's job.
        let mut c = Command::new("cmd").args(["/c", "ping -n 3 127.0.0.1 >nul"]).spawn().unwrap();
        let mut inside = 0;
        let ok = unsafe { IsProcessInJob(std::os::windows::io::AsRawHandle::as_raw_handle(&c) as HANDLE, std::ptr::null_mut(), &mut inside) };
        let _ = c.kill();
        assert!(ok != 0 && inside != 0, "child must be in a job without any post-spawn assignment");
    }
}
