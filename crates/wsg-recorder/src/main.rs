//! The recorder. `wsg-recorder --console [--data-dir DIR]` runs in the foreground until Ctrl-C;
//! with no flags it runs as the Windows service `WindowsSystemGuard` (installed by `wsg install`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::json;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use wsg_core::new_boot_id;
use wsg_recorder::collectors::{
    Collector, CounterCollector, GpuCollector, ProcessCollector, SensorCollector, WslCollector,
};
use wsg_recorder::config::{self, Config};
use wsg_recorder::cycle::{cycles, run_cycle, SystemClock};
use wsg_recorder::pipe;
use wsg_recorder::service::Session;
use wsg_recorder::supervisor::HelperSpec;

const SERVICE_NAME: &str = "WindowsSystemGuard";

static CONSOLE_STOP: OnceLock<Sender<()>> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--console") {
        let data_dir = args
            .iter()
            .position(|a| a == "--data-dir")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .unwrap_or_else(default_data_dir);
        let (tx, rx) = mpsc::channel();
        let _ = CONSOLE_STOP.set(tx);
        // SAFETY: the handler is a plain function that only sends on a channel.
        unsafe { SetConsoleCtrlHandler(Some(on_ctrl_c), 1) };
        if let Err(e) = run(&data_dir, rx) {
            eprintln!("wsg-recorder: {e}");
            std::process::exit(1);
        }
    } else if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        eprintln!("wsg-recorder: not started by the service manager ({e}); use --console to run in a terminal");
        std::process::exit(2);
    }
}

unsafe extern "system" fn on_ctrl_c(_: u32) -> i32 {
    if let Some(tx) = CONSOLE_STOP.get() {
        let _ = tx.send(());
    }
    1
}

fn default_data_dir() -> PathBuf {
    config::default_path().parent().map(Path::to_path_buf).unwrap_or_default()
}

fn service_main(_args: Vec<OsString>) {
    let (tx, rx) = mpsc::channel();
    let handler = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    });
    let Ok(handler) = handler else { return };
    let status = |state, accept, code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: code,
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    let _ = handler.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    ));
    let code = match run(&default_data_dir(), rx) {
        Ok(()) => 0,
        Err(_) => 1,
    };
    let _ = handler.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(code),
    ));
}

/// Directory holding `ring.bin`, `fallback.bin`, `archive/` and `config.toml`.
// shortcut: the directory is created with inherited permissions; the installer (Task 16) must
// restrict it to SYSTEM and Administrators.
fn run(data_dir: &Path, stop: Receiver<()>) -> Result<(), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("cannot create {}: {e}", data_dir.display()))?;
    let cfg_path = data_dir.join("config.toml");
    let cfg = if cfg_path.exists() { config::load(&cfg_path).map_err(|e| e.to_string())? } else { Config::default() };
    let ring = cfg.ring_path.clone().unwrap_or_else(|| data_dir.join("ring.bin"));
    let fallback = cfg.fallback_path.clone().unwrap_or_else(|| data_dir.join("fallback.bin"));
    let boot = new_boot_id();
    let session = Session::start(&ring, &fallback, &data_dir.join("archive"), boot).map_err(|e| e.to_string())?;

    let interval = Duration::from_millis(cfg.interval_ms);
    let mut collectors = build_collectors(interval);
    let status = Arc::new(Mutex::new(String::from("{}")));
    let pipe = pipe::serve(pipe::PIPE_NAME, status.clone()).map_err(|e| format!("status pipe: {e}"))?;

    let mut next = Instant::now();
    loop {
        run_cycle(&mut collectors, session.writer(), boot, &SystemClock, interval, interval / 4);
        let helpers: serde_json::Map<_, _> = collectors
            .iter()
            .filter_map(|c| c.helper_stats().map(|s| (c.name().to_string(), json!(s))))
            .collect();
        *status.lock().unwrap() = json!({
            "cycles": cycles(),
            "ring": ring,
            "fallback": fallback,
            "primary_error": session.primary_error(),
            "writer": session.writer().stats(),
            "helpers": helpers,
        })
        .to_string();
        next += interval;
        match stop.recv_timeout(next.saturating_duration_since(Instant::now())) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(pipe);
    session.stop();
    Ok(())
}

fn build_collectors(interval: Duration) -> Vec<Box<dyn Collector>> {
    let mut v: Vec<Box<dyn Collector>> = Vec::new();
    match CounterCollector::new() {
        Ok(c) => v.push(Box::new(c)),
        Err(e) => eprintln!("wsg-recorder: counters unavailable: {e}"),
    }
    v.push(Box::new(ProcessCollector::new(10)));
    v.push(Box::new(WslCollector::new()));
    let dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_default();
    // A call deadline must cover helper start-up, NVML init, one interval and the 1 s sensor
    // connect timeout, so it is never shorter than 5 s (Task 8 ruling).
    let spec = |exe: &str| HelperSpec {
        exe: dir.join(exe),
        args: vec!["--interval-ms".into(), interval.as_millis().to_string()],
        call_deadline: (interval * 3).max(Duration::from_secs(5)),
        restart_limit: 5,
        restart_window: Duration::from_secs(600),
    };
    v.push(Box::new(GpuCollector::new(spec("wsg-gpu-helper.exe"))));
    v.push(Box::new(SensorCollector::new(spec("wsg-sensor-helper.exe"))));
    v
}
