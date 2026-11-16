//! `wsg install` and `wsg uninstall`: the steps are planned as data first, so `--dry-run` shows
//! exactly what a real run would do and tests never touch the machine.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const SERVICE_NAME: &str = "WindowsSystemGuard";
pub const TASK_NAME: &str = "WindowsSystemGuard-PostMortem";
/// Executables copied next to the service: the CLI, the recorder and its two helpers.
const BINARIES: [&str; 4] = ["wsg.exe", "wsg-recorder.exe", "wsg-gpu-helper.exe", "wsg-sensor-helper.exe"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    CreateDir(PathBuf),
    Copy { from: PathBuf, to: PathBuf },
    Run { program: String, args: Vec<String> },
    /// A step that a real run may let fail, such as stopping a service that is not running.
    RunOptional { program: String, args: Vec<String> },
}

pub struct Paths {
    /// Where the running `wsg.exe` and its sibling binaries are.
    pub source_dir: PathBuf,
    /// Where the binaries are installed; the default ACL of Program Files is administrators only.
    pub program_dir: PathBuf,
    /// Rings, archive and configuration.
    pub data_dir: PathBuf,
}

impl Paths {
    pub fn standard(source_dir: PathBuf) -> Paths {
        let env = |k: &str, d: &str| PathBuf::from(std::env::var_os(k).unwrap_or_else(|| d.into()));
        Paths {
            source_dir,
            program_dir: env("ProgramFiles", r"C:\Program Files").join("WindowsSystemGuard"),
            data_dir: env("ProgramData", r"C:\ProgramData").join("WindowsSystemGuard"),
        }
    }
}

fn run(program: &str, args: &[&str]) -> Step {
    Step::Run { program: program.into(), args: args.iter().map(|s| s.to_string()).collect() }
}

pub fn plan_install(p: &Paths) -> Vec<Step> {
    let recorder = p.program_dir.join("wsg-recorder.exe");
    let cli = p.program_dir.join("wsg.exe");
    let mut steps = vec![Step::CreateDir(p.program_dir.clone()), Step::CreateDir(p.data_dir.clone())];
    steps.extend(BINARIES.iter().map(|b| Step::Copy { from: p.source_dir.join(b), to: p.program_dir.join(b) }));
    // SYSTEM and Administrators only, by SID so the grant works in any Windows language.
    steps.push(Step::Run {
        program: "icacls.exe".into(),
        args: vec![
            p.data_dir.display().to_string(),
            "/inheritance:r".into(),
            "/grant:r".into(),
            "*S-1-5-18:(OI)(CI)F".into(),
            "*S-1-5-32-544:(OI)(CI)F".into(),
        ],
    });
    steps.push(Step::Run {
        program: "sc.exe".into(),
        args: ["create", SERVICE_NAME, "binPath=", &recorder.display().to_string(), "start=", "auto", "obj=", "LocalSystem", "DisplayName=", "Windows System Guard"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    });
    steps.push(run("sc.exe", &["description", SERVICE_NAME, "Records system telemetry that survives a freeze or hard reset."]));
    steps.push(run("sc.exe", &["failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000"]));
    steps.push(Step::Run {
        program: "schtasks.exe".into(),
        args: vec![
            "/Create".into(),
            "/TN".into(),
            TASK_NAME.into(),
            "/SC".into(),
            "ONSTART".into(),
            "/DELAY".into(),
            "0001:00".into(),
            "/RU".into(),
            "SYSTEM".into(),
            "/RL".into(),
            "HIGHEST".into(),
            "/TR".into(),
            format!("\"{}\" postmortem --auto", cli.display()),
            "/F".into(),
        ],
    });
    steps.push(run("sc.exe", &["start", SERVICE_NAME]));
    steps
}

/// Removes the service and the task. Binaries, rings and archived incidents stay: they are the evidence.
pub fn plan_uninstall() -> Vec<Step> {
    vec![
        Step::RunOptional { program: "schtasks.exe".into(), args: ["/Delete", "/TN", TASK_NAME, "/F"].iter().map(|s| s.to_string()).collect() },
        Step::RunOptional { program: "sc.exe".into(), args: ["stop", SERVICE_NAME].iter().map(|s| s.to_string()).collect() },
        run("sc.exe", &["delete", SERVICE_NAME]),
    ]
}

pub fn describe(s: &Step) -> String {
    let quote = |a: &String| if a.contains(' ') || a.contains('"') { format!("\"{}\"", a.replace('"', "\\\"")) } else { a.clone() };
    match s {
        Step::CreateDir(d) => format!("create directory {}", d.display()),
        Step::Copy { from, to } => format!("copy {} to {}", from.display(), to.display()),
        Step::Run { program, args } | Step::RunOptional { program, args } => {
            format!("run {program} {}", args.iter().map(quote).collect::<Vec<_>>().join(" "))
        }
    }
}

/// Runs the steps in order and stops at the first one that fails.
pub fn execute(steps: &[Step]) -> Result<(), String> {
    for s in steps {
        println!("{}", describe(s));
        match s {
            Step::CreateDir(d) => std::fs::create_dir_all(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?,
            Step::Copy { from, to } => {
                std::fs::copy(from, to).map_err(|e| format!("cannot copy {} to {}: {e}", from.display(), to.display()))?;
            }
            Step::Run { program, args } | Step::RunOptional { program, args } => {
                let out = Command::new(program).args(args).output().map_err(|e| format!("cannot start {program}: {e}"))?;
                if !out.status.success() && matches!(s, Step::Run { .. }) {
                    return Err(format!(
                        "{program} failed ({}): {}{}",
                        out.status,
                        String::from_utf8_lossy(&out.stdout).trim(),
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn source_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_default()
}
