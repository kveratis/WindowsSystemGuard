//! `wsg`: status, event triage, post-mortems, noise rules and service installation.

mod common;
mod install;
mod postmortem;
mod report;
mod status;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wsg_events::{NoiseRule, NoiseRules};

#[derive(Parser)]
#[command(name = "wsg", about = "Windows System Guard")]
struct Cli {
    /// Where the rings, archive and configuration live (default: %ProgramData%\WindowsSystemGuard).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Name of the recorder's status pipe.
    #[arg(long, global = true, default_value = status::PIPE_NAME)]
    pipe: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the recorder's health; reads the ring files if the recorder is not running.
    Status,
    /// Triage the event logs over a window, without AI.
    Report {
        /// How far back to look: 90s, 15m, 12h or 14d.
        #[arg(long, default_value = "24h")]
        since: String,
        /// Worst-to-least severity to include: 1 critical, 2 error, 3 warning, 4 information.
        #[arg(long, default_value_t = 3)]
        level: u8,
        /// Most surfaced groups to print.
        #[arg(long, default_value_t = 30)]
        top: usize,
    },
    /// Build and render the post-mortem of an archived incident.
    Postmortem {
        /// Incident id (default: the newest).
        #[arg(long, conflicts_with = "auto")]
        incident: Option<String>,
        /// Analyze every incident still waiting, writing postmortem.txt beside its ring.
        #[arg(long)]
        auto: bool,
        /// Skip the event logs and hardware (faster).
        #[arg(long)]
        no_events: bool,
    },
    /// Manage the known-noise rules.
    Noise {
        #[command(subcommand)]
        action: NoiseCmd,
    },
    /// Install the recorder service and the start-up post-mortem task.
    Install {
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the service and the task; rings and archived incidents are kept.
    Uninstall {
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum NoiseCmd {
    /// List built-in and user rules.
    List,
    /// Suppress an event: provider name, event id and the reason shown in reports.
    Add { provider: String, event_id: u16, reason: String },
    /// Remove a user rule by its name (built-in rules cannot be removed).
    Remove { rule: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.clone().unwrap_or_else(common::default_data_dir);
    match dispatch(cli, &data_dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wsg: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli, data_dir: &std::path::Path) -> Result<(), String> {
    let archive = data_dir.join("archive");
    match cli.cmd {
        Cmd::Status => status::run(&cli.pipe, data_dir),
        Cmd::Report { since, level, top } => {
            print!("{}", report::run(data_dir, common::parse_duration(&since)?, level, top)?);
            Ok(())
        }
        Cmd::Postmortem { auto: true, no_events, .. } => postmortem::run_auto(&archive, data_dir, !no_events),
        Cmd::Postmortem { incident, no_events, .. } => postmortem::run_one(&archive, data_dir, incident.as_deref(), !no_events),
        Cmd::Noise { action } => noise(data_dir, action),
        Cmd::Install { dry_run } => {
            let steps = install::plan_install(&install::Paths::standard(install::source_dir()));
            apply(&steps, dry_run)
        }
        Cmd::Uninstall { dry_run } => apply(&install::plan_uninstall(), dry_run),
    }
}

fn apply(steps: &[install::Step], dry_run: bool) -> Result<(), String> {
    if dry_run {
        println!("Dry run: nothing is changed. A real run would:");
        for s in steps {
            println!("  {}", install::describe(s));
        }
        Ok(())
    } else {
        install::execute(steps)
    }
}

fn noise(data_dir: &std::path::Path, action: NoiseCmd) -> Result<(), String> {
    let path = common::noise_path(data_dir);
    let mut user = if path.exists() { NoiseRules::load(&path).map_err(|e| e.to_string())? } else { NoiseRules::default() };
    match action {
        NoiseCmd::List => {
            let show = |label: &str, rules: &NoiseRules| {
                for r in &rules.rules {
                    println!("{label:8} {} | {} {}{}", r.name, r.provider, r.event_id, r.payload_key.as_ref().map_or(String::new(), |k| format!(" where {k} contains {:?}", r.payload_contains.clone().unwrap_or_default())));
                }
            };
            show("built-in", &NoiseRules::builtin());
            show("user", &user);
            Ok(())
        }
        NoiseCmd::Add { provider, event_id, reason } => {
            if user.rules.iter().any(|r| r.name == reason) {
                return Err(format!("a rule named {reason:?} already exists"));
            }
            user.rules.push(NoiseRule { name: reason.clone(), provider, event_id, payload_key: None, payload_contains: None });
            std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
            user.save(&path).map_err(|e| e.to_string())?;
            println!("Added rule {reason:?}. Suppressed events are still counted and kept; they just stop being ranked.");
            Ok(())
        }
        NoiseCmd::Remove { rule } => {
            let before = user.rules.len();
            user.rules.retain(|r| r.name != rule);
            if user.rules.len() == before {
                return Err(format!("no user rule named {rule:?} (built-in rules cannot be removed)"));
            }
            user.save(&path).map_err(|e| e.to_string())?;
            println!("Removed rule {rule:?}.");
            Ok(())
        }
    }
}
