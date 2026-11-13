//! WSL liveness via the `vmmem`/`vmmemWSL` host process. Hyper-V vSwitch counters are not
//! collected: `Sample` has no field for them, so they are ignored by design.

use super::{value, CollectOutcome, Collector, SampleFragment};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;

#[derive(Default)]
pub struct WslCollector;

impl WslCollector {
    pub fn new() -> Self {
        WslCollector
    }
}

pub(crate) fn exe_name(e: &PROCESSENTRY32W) -> String {
    let n = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
    String::from_utf16_lossy(&e.szExeFile[..n])
}

impl Collector for WslCollector {
    fn name(&self) -> &'static str {
        "wsl"
    }
    fn collect(&mut self, _budget: Duration) -> CollectOutcome {
        // SAFETY: plain Toolhelp snapshot; handle closed below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return CollectOutcome::Unavailable("process snapshot failed".into());
        }
        // SAFETY: PROCESSENTRY32W is plain data; all-zero is valid.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut running = false;
        // SAFETY: e.dwSize is set; snap is a valid snapshot.
        let mut ok = unsafe { Process32FirstW(snap, &mut e) } != 0;
        while ok {
            let n = exe_name(&e).to_ascii_lowercase();
            if n == "vmmem.exe" || n == "vmmemwsl.exe" || n == "vmmem" || n == "vmmemwsl" {
                running = true;
                break;
            }
            ok = unsafe { Process32NextW(snap, &mut e) } != 0;
        }
        // SAFETY: snap is valid and closed once.
        unsafe { CloseHandle(snap) };
        CollectOutcome::Ok(SampleFragment::Wsl(value(running)))
    }
}
