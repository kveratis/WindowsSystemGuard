//! Wall and monotonic clocks plus boot id generation.

use crate::record::BootId;
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

/// System clock as nanoseconds since the Unix epoch.
pub fn now_utc_ns() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    }
}

/// QueryPerformanceCounter in nanoseconds.
pub fn mono_ns() -> u64 {
    let (mut ticks, mut freq) = (0i64, 0i64);
    // SAFETY: both pointers are valid for the call; these APIs never fail on supported Windows.
    unsafe {
        QueryPerformanceCounter(&mut ticks);
        QueryPerformanceFrequency(&mut freq);
    }
    (ticks as u128 * 1_000_000_000 / freq.max(1) as u128) as u64
}

pub fn new_boot_id() -> BootId {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("os randomness unavailable");
    BootId(b)
}
