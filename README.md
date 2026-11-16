# Windows System Guard

Windows System Guard is a flight recorder and log analyst for one Windows 11 machine that hard-locks without leaving a trace in the event logs. A small service samples the system every second into a ring file that survives a hard reset. After an unclean reboot the `wsg` command turns that recording, the Windows event logs, the update history and the hardware facts into a plain-text post-mortem.

The tool narrows a cause; it does not promise to find one. When the evidence does not support a conclusion, the post-mortem says "Cause undetermined" and lists checks to make outside the recorder.

Nothing in the tool sends data off the machine. The only network traffic is a request to `127.0.0.1:8085` for sensor data (see [Sensors](#sensors)).

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Before the first freeze: crash dump preparation](#before-the-first-freeze-crash-dump-preparation)
- [Build](#build)
- [Sensors](#sensors)
- [Choosing where the ring lives](#choosing-where-the-ring-lives)
- [Install](#install)
- [Check that it is recording](#check-that-it-is-recording)
- [After a freeze](#after-a-freeze)
- [Commands](#commands)
- [Configuration](#configuration)
- [Files and folders](#files-and-folders)
- [Uninstall](#uninstall)
- [Measuring the recorder's own cost](#measuring-the-recorders-own-cost)
- [Reading a post-mortem](#reading-a-post-mortem)
- [Limits](#limits)
- [Development](#development)

## How it works

Four programs are installed together.

- `wsg-recorder.exe` is the Windows service `WindowsSystemGuard`. It runs as LocalSystem and starts at boot. Each cycle it writes a heartbeat first and then a sample: per-process CPU, working set, I/O and handles for the busiest processes, system CPU with DPC and interrupt time, commit and pool memory, per-disk queue length and latency, network throughput, GPU readings, sensor readings and whether the WSL virtual machine is running. A reading that cannot be taken is recorded as unavailable with a reason. It is never recorded as zero.
- `wsg-gpu-helper.exe` and `wsg-sensor-helper.exe` run as child processes of the recorder. They talk to the NVIDIA driver and to the sensor program, which are the calls most likely to hang. If a helper stalls, the recorder abandons the call, restarts the helper (at most five times in ten minutes) and keeps writing heartbeats. The helpers are bound to the recorder with a Windows job object, so they cannot outlive it.
- `wsg.exe` is the command-line tool. It reads the recorder's status, triages the event logs, builds post-mortems and manages installation.

The recorder writes two files. The primary ring (64 MiB by default) belongs on a different drive from Windows, so a drive that is still reachable after a freeze holds the last minutes. The fallback ring (8 MiB) stays on the system drive. If a write or flush on the primary takes longer than one second, for example because a USB drive was pulled, the recorder counts a stall and switches to the fallback while the original call is still outstanding. Records are flushed to the drive by the writer rather than left to the operating system's cache, but how much a power cut loses depends on the drive and has to be measured, not assumed (see [Limits](#limits)).

When the service starts it checks the previous primary ring for a clean-shutdown marker. If the marker is missing, the ring is copied to `archive\inc-<boot id>\ring.bin` together with an `incident.json` before recording resumes, so a restart loop cannot overwrite the only useful window. A non-empty fallback ring from the previous session is copied to `archive\fallback-<time>.bin` before it is recreated.

A scheduled task runs `wsg postmortem --auto` one minute after each boot. It analyzes every archived incident that has not been analyzed yet and writes `postmortem.txt` next to the archived ring.

## Requirements

- Windows 11 on x64, with an administrator account. Installing, reading the recorder's pipe and reading the data directory all need an elevated shell.
- Rust stable with the MSVC toolchain, and the Visual Studio C++ build tools, to build from source.
- An NVIDIA GPU and driver for GPU readings. Without them the GPU fields are recorded as unavailable.
- LibreHardwareMonitor for temperatures, voltages, fan speeds and per-core clocks (see [Sensors](#sensors)). Without it those fields are recorded as unavailable and the post-mortem says so.
- Optional: a second drive for the primary ring, preferably a removable one that stays reachable when Windows does not respond.

## Before the first freeze: crash dump preparation

A freeze that Windows cannot recover from leaves nothing behind unless the machine is set up to write a memory dump when told to. Do this first, before installing the recorder, because the next freeze may be the one that matters.

`scripts\phase0-dump-prep.ps1` checks the prerequisites and reports PASS or FAIL for each:

- `CrashDumpEnabled` is 1 (complete dump) or 2 (kernel dump).
- The pagefile on the system drive is large enough for that dump type, and the drive has enough free space.
- `CrashOnCtrlScroll` is 1 for the keyboard driver that applies (`kbdhid`, and `i8042prt` when a PS/2 keyboard is present).
- `NMICrashDump` is 1.

Run it without arguments from an elevated PowerShell to see the state of the machine. It changes nothing in that mode.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\phase0-dump-prep.ps1
```

To set the registry values, run it with `-Apply` and reboot. The values apply only after a restart.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\phase0-dump-prep.ps1 -Apply
```

`-Apply` writes these values and nothing else:

| Key | Value |
| --- | --- |
| `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl` | `CrashDumpEnabled = 1` (only if it was neither 1 nor 2), `NMICrashDump = 1` |
| `HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters` | `CrashOnCtrlScroll = 1` |
| `HKLM\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters` | `CrashOnCtrlScroll = 1` |

The script never changes the pagefile. If the pagefile check fails, the message gives the size to set under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PagingFiles`, or set it in System Properties, Advanced, Performance, Advanced, Virtual memory. A complete dump needs a pagefile at least as large as RAM on the system drive.

With the keyboard trigger enabled, a frozen machine writes a dump when you hold the right Ctrl key and press Scroll Lock twice. That works only if the freeze has not reached a state where the keyboard driver itself is stuck. If the motherboard has an NMI or reset header, note where it is for the same reason.

To undo the preparation, delete the values `CrashOnCtrlScroll` (both keys) and `NMICrashDump`, and restore `CrashDumpEnabled` to its earlier value, then reboot.

## Build

From the repository root:

```powershell
cargo build --release --workspace
```

The programs are written to `target\release`: `wsg.exe`, `wsg-recorder.exe`, `wsg-gpu-helper.exe` and `wsg-sensor-helper.exe`. The installer copies the four files from the folder that holds the `wsg.exe` you run, so run `wsg install` from `target\release` (or from any folder that has all four).

## Sensors

Windows does not expose most temperatures, voltages or fan speeds to a service without a kernel driver, and this tool bundles none. It reads them from LibreHardwareMonitor's built-in web server instead.

1. Install LibreHardwareMonitor and start it as administrator, so it can load its sensor driver.
2. In its Options menu, enable the remote web server and leave the port at 8085.
3. Keep it running, ideally from a startup task, so it is up before the recorder starts sampling.

The sensor helper requests `http://127.0.0.1:8085/data.json` once per cycle. If the page is unreachable the sensor fields are recorded as unavailable and the post-mortem tells you to start the program. The recorder works without it, but thermal and power evidence will be missing from any incident.

## Choosing where the ring lives

With no configuration both rings are created in `C:\ProgramData\WindowsSystemGuard`, on the same drive. That protects against a crash of the recorder but not against a drive that stops answering. For the intended protection, put the primary ring on a second drive and leave the fallback on the system drive.

Create a folder on that drive first, for example `E:\wsg`. The recorder does not create the parent folder of a configured ring path. Then create the configuration file as described in [Configuration](#configuration). The archive folder stays on the system drive, so an unclean primary ring is copied there at the next start.

## Install

Open an elevated PowerShell in the folder that holds the built programs and run a dry run first. It prints every action and changes nothing.

```powershell
cd target\release
.\wsg.exe install --dry-run
```

The plan has these steps:

1. Create `C:\Program Files\WindowsSystemGuard` and `C:\ProgramData\WindowsSystemGuard`.
2. Copy `wsg.exe`, `wsg-recorder.exe`, `wsg-gpu-helper.exe` and `wsg-sensor-helper.exe` into the Program Files folder, which only administrators can write to by default.
3. Restrict `C:\ProgramData\WindowsSystemGuard` to SYSTEM and Administrators with `icacls`, using well-known SIDs so it works in any Windows language. The recorder refuses a configuration file that anyone else can write.
4. Create the service `WindowsSystemGuard` as LocalSystem, start type automatic, with `sc.exe`. The service restarts after a failure: after 5 seconds, 5 seconds and 30 seconds, with the failure count reset after a day.
5. Register the scheduled task `WindowsSystemGuard-PostMortem`, which runs `wsg.exe postmortem --auto` as SYSTEM one minute after boot.
6. Start the service.

Run the real install when the plan looks right:

```powershell
.\wsg.exe install
```

Each step is printed as it runs and the command stops at the first failure. Installing twice fails at `sc.exe create` because the service exists; run `wsg uninstall` first.

The service starts recording at once. If you want a ring on another drive, stop the service, write the configuration file and start it again:

```powershell
sc.exe stop WindowsSystemGuard
notepad C:\ProgramData\WindowsSystemGuard\config.toml
sc.exe start WindowsSystemGuard
```

Restart the machine once after installing, then confirm the service came up on its own (see the next section).

## Check that it is recording

From an elevated shell:

```powershell
wsg status
```

When the service is running, `status` prints a JSON document read from the recorder's named pipe `\\.\pipe\wsg-recorder`. The fields to look at:

- `cycles` increases by about one per second.
- `ring` and `fallback` are the files being written.
- `primary_error` is `null`. A message there means the primary ring could not be created, for example because its drive or folder was missing at start. Records go to the fallback in that case.
- `writer.dropped` counts records lost, `writer.fallback_active` is true while the primary is not being written, and `writer.memory_only` is true only if neither ring is accepting records.
- `helpers` shows restarts, whether a helper was abandoned, and the time of its last stall, for the GPU and sensor helpers.

If the service is not running, `status` says so and reads the ring files directly instead, printing the record count, the age of the newest record and whether the last session ended cleanly. The pipe is readable only by SYSTEM, Administrators and the account the recorder runs as, and by its design it answers only the `STATUS` command.

## After a freeze

Power-cycle the machine. On the next boot the recorder archives the previous ring as an incident, and a minute later the scheduled task writes the post-mortem. To read it, from an elevated shell:

```powershell
wsg postmortem
```

That prints the newest incident's post-mortem and also writes it to `C:\ProgramData\WindowsSystemGuard\archive\<incident id>\postmortem.txt`. Use `--incident <id>` for an older one. The ids appear as folder names under `archive`.

To look at the event logs on their own, with no recorder data:

```powershell
wsg report --since 24h
```

## Commands

All commands accept `--data-dir <folder>` to use a different data folder and `--pipe <name>` to talk to a different recorder pipe. Run `wsg <command> --help` for the full text.

| Command | What it does |
| --- | --- |
| `wsg status` | Shows the recorder's health, or the ring files' state when the recorder is not running. |
| `wsg report [--since 24h] [--level 3] [--top 30]` | Triages the default event channels over a window. `--since` takes `90s`, `15m`, `12h` or `14d`. `--level` is the worst severity to include: 1 critical, 2 error, 3 warning, 4 information. |
| `wsg postmortem [--incident <id>] [--auto] [--no-events]` | Builds and prints the post-mortem for an incident. `--auto` analyzes every incident still waiting and prints nothing but a summary line for each. `--no-events` skips the event logs and hardware, which is faster but leaves those sections empty. |
| `wsg noise list` | Lists the built-in and user noise rules. |
| `wsg noise add <provider> <event id> <reason>` | Adds a user rule that suppresses one provider and event id. The reason is the rule's name in reports. |
| `wsg noise remove <rule>` | Removes a user rule by name. Built-in rules cannot be removed. |
| `wsg install [--dry-run]` | Installs the service and the start-up task. |
| `wsg uninstall [--dry-run]` | Removes the service and the task. |

`wsg postmortem --auto` is idempotent. A second run finds no incident waiting and leaves the existing files untouched.

### Noise rules

A noise rule marks an event group as known chatter so it does not crowd the ranked list. The built-in rules cover DCOM 10016, Ntfs 98, Tcpip 4266, Windows Firewall 2042 and Kernel-PnP 219 for the WUDFRd driver. A suppressed group keeps its count, timestamps and payload variants and is reported as a count under its rule's name. In a post-mortem, a rule never hides a group that was absent from the preceding 14 days and occurs inside the incident window: a rare event just before a freeze is always shown. `wsg report` has no earlier period to compare against and applies the rules as written.

User rules are stored in `noise.toml` in the data folder:

```toml
[[rule]]
name = "Foo is chatty"
provider = "Microsoft-Windows-Foo"
event_id = 1234
```

A rule may also carry `payload_key` and `payload_contains` to match only events whose payload field contains a given text.

## Configuration

The recorder reads `config.toml` from its data folder if the file exists. All keys are optional.

```toml
# Milliseconds between samples. Accepted range: 250 to 60000. Default: 1000.
interval_ms = 1000

# Primary ring. Default: ring.bin in the data folder.
ring_path = 'E:\wsg\ring.bin'

# Fallback ring. Default: fallback.bin in the data folder.
# Keep it on a different drive from the primary ring.
fallback_path = 'C:\ProgramData\WindowsSystemGuard\fallback.bin'
```

Use single quotes for Windows paths so the backslashes are literal. Unknown keys are an error.

The recorder refuses to start if the file is owned by an account other than SYSTEM, Administrators or TrustedInstaller, or if any other account can write to it. It also refuses a file with access entries it cannot evaluate, such as conditional or object entries. The reason is that a configuration file controls where a LocalSystem service writes. Create it from an elevated shell inside the already-restricted data folder.

`ring_path` and `fallback_path` must name different files; the recorder refuses to start otherwise. It does not check that they are on different drives, so that is up to you.

## Files and folders

The data folder is `C:\ProgramData\WindowsSystemGuard` unless `--data-dir` says otherwise.

| Path | Contents |
| --- | --- |
| `ring.bin` | Primary ring, unless `ring_path` moves it. |
| `fallback.bin` | Fallback ring, unless `fallback_path` moves it. |
| `config.toml` | Optional recorder configuration. |
| `noise.toml` | Optional user noise rules. |
| `archive\inc-<boot id>\ring.bin` | The archived ring of an unclean session. |
| `archive\inc-<boot id>\incident.json` | The incident's id, detection time and state (`Archived` or `Analyzed`). |
| `archive\inc-<boot id>\postmortem.txt` | The rendered post-mortem. |
| `archive\fallback-<time>.bin` | A fallback ring from an earlier session that still held records. |

`C:\Program Files\WindowsSystemGuard` holds the four programs.

## Uninstall

Remove the service and the scheduled task from an elevated shell:

```powershell
wsg uninstall --dry-run
wsg uninstall
```

This stops and deletes the service `WindowsSystemGuard` and deletes the task `WindowsSystemGuard-PostMortem`. It leaves the programs, the rings, the archive and the configuration in place, because they are evidence. If the service is not running, the stop step is skipped and the removal still completes.

To remove everything else, delete these by hand once you no longer need the recordings:

```powershell
Remove-Item -Recurse -Force 'C:\Program Files\WindowsSystemGuard'
Remove-Item -Recurse -Force 'C:\ProgramData\WindowsSystemGuard'
```

Also delete the ring folder on the other drive (for example `E:\wsg`) if you configured one. Run `wsg.exe` from a copy, not from the Program Files folder, when you delete that folder. The crash dump settings from [the preparation step](#before-the-first-freeze-crash-dump-preparation) are independent of the install and stay until you revert them as described there.

## Measuring the recorder's own cost

The recorder must not add load that could mask or worsen the freeze. `scripts\measure-overhead.ps1` runs the recorder in the foreground on a temporary data folder, samples the recorder and its helpers every 5 seconds, and prints PASS or FAIL lines against two limits: average CPU of 1% of the whole machine and a combined working set of 100 MB. The first 60 seconds are left out of the average, because security software can hold a newly built helper for about half a minute on its first launch.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\measure-overhead.ps1 -Minutes 10
```

It uses `target\release` if that exists and `target\debug` otherwise, or the path given with `-Exe`. A foreground run uses `wsg-recorder.exe --console [--data-dir <folder>]`, which stops cleanly on Ctrl-C.

## Reading a post-mortem

The first line states the position. "Cause undetermined" means no recorded metric moved away from its baseline. A line that starts with a count of diverged metrics means there are leads, and the report says plainly that leads are not a proven cause.

The sections, in order:

- Timeline. Each entry states what it can and cannot show. The last sample taken is the last cycle the recorder started. The last sample persisted is the last complete sample in the ring, which trails the first when the machine stopped partway through a cycle. The freeze onset estimate is where heartbeats stopped or slowed for good, accurate to about one interval. It shows lost progress, not a cause. A forced power-off time appears only when the power button was held (Kernel-Power 41 records it). The next boot is the first unclean-shutdown report in the log, which is written during the next boot and so bounds the restart, not the freeze.
- What changed before the freeze. Metrics from the last 15 minutes of the ring compared with everything earlier in the same ring, with the ring record numbers that show each divergence. If the ring holds under a quarter hour of history there is no baseline and nothing is reported.
- Surfaced events. Event groups ranked by severity, rarity, novelty against the preceding 14 days and closeness to the incident, followed by suppressed noise as counts only.
- Updates and install loops. Windows Update installs and failures, hotfixes and driver configuration, and any package that installed repeatedly within a day.
- Hardware context. Board, BIOS, memory modules with rated and running speed, and drivers updated in the last 14 days. Windows does not report the chipset, the AGESA version or whether XMP or DOCP is on. The report says so and tells you to read the BIOS screen.
- Evidence quality. Records lost, ring stalls, helper restarts, missing sensors and the sampling limits.
- Checks outside the recorder: dump settings, BIOS and AGESA, the memory profile, the power supply, a memory test, and an experiment with `wsl --shutdown`.

## Limits

- The recorder runs in user mode. If the whole kernel stalls, the recorder stalls with it. A recording can show that progress stopped and what the system looked like just before, not why.
- Samples are taken about once a second by default. A brief voltage or power excursion between samples is not captured.
- The primary ring is opened once, at service start. If its drive is pulled, records go to the fallback ring for the rest of that session, and the primary stays unused until the service restarts. A primary that is missing at start is not retried either.
- The post-mortem reads the archived primary ring of an incident. Records that reached only the fallback ring are kept in `archive\fallback-<time>.bin` and are shown by `wsg status`, but `wsg postmortem` does not read them.
- The data-loss bound after a power cut or a pulled cable has to be measured on the actual drive. Pull the primary drive's cable while the service runs, then run `wsg postmortem` and compare the newest record's time with the time of the pull. The same measurement was planned for a Windows `logman` collector in `docs\spikes\logman-spike.md`; its default decision there is "reject" until measured.
- Baseline comparison across several freeze-free windows needs more than one recorded incident. A single incident yields leads, not statistics.
- The tool has no natural-language explanation layer. `wsg` does not call any language model.
- Reading the event log needs an elevated shell for some channels. A channel that is missing, disabled or denied is listed in the report as skipped.

## Development

Run the whole suite from the repository root:

```powershell
cargo test --workspace
```

Notes for running the tests:

- Several tests read this machine's live event log and WMI data, so they need Windows and take longer on a machine with a large log. The CLI tests that exercise `wsg report` and `wsg postmortem` run the real binary.
- `WSG_FIXTURES` names a folder that may hold `system.evtx`, an export of the System log. Tests that read exported logs use it and print a skip notice when it is unset. Create one with `wevtutil epl System <folder>\system.evtx`.
- Security software can hold a freshly built executable for tens of seconds on its first launch. The helper supervision tests start real helper processes, so they can time out on the first run after a rebuild. Run them again once the programs have been scanned.
- The tests in `crates\wsg-recorder\tests` run actual processes and named pipes. The pipe tests include the process id in the pipe name. The startup test that checks a second recorder is refused holds the real pipe name `\\.\pipe\wsg-recorder`, so stop an installed recorder before running it, or it fails to take the name.

The workspace has five crates.

| Crate | Role |
| --- | --- |
| `wsg-core` | Record and sample types, the crash-consistent ring file, the tiered writer, archive-on-boot, and the merge of the two rings. |
| `wsg-recorder` | The service, the collectors, the helper supervisor, configuration, and the status pipe. Builds `wsg-recorder`, `wsg-gpu-helper` and `wsg-sensor-helper`. |
| `wsg-events` | Event log reader, event grouping, noise rules, scoring, and the update and install timeline. |
| `wsg-analysis` | The incident timeline, gap classification, divergence from baseline, hardware context and the post-mortem renderer. |
| `wsg-cli` | The `wsg` command. |

The design and the implementation plan are in `docs\superpowers\specs` and `docs\superpowers\plans`.
