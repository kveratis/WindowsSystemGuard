# WindowsSystemGuard design

Date: 2026-11-13

## Intent and why

The owner's high-performance workstation (Ryzen 7 3700X, RTX 3060, 64 GB RAM, Windows 11 Pro) has been hard-locking in the middle of the workday for about two weeks. The machine becomes unresponsive (processes cannot be killed, applications cannot be reached) and never recovers; the owner must power-cycle it. Virus scans and driver updates did not help.

The owner believes the clues are in the logs but cannot separate signal from noise. A read-only scan of the last 14 days showed:

- Three unclean reboots (Kernel-Power 41 plus EventLog 6008) on Nov 10 at 11:33, Nov 11 at 13:47 and Nov 12 at 14:19, all mid-workday.
- No log entries in the final 1 to 3 minutes before each one, no minidumps or live-kernel dumps, and no GPU timeout events. This points to a hard lockup where Windows never gets to record a cause.
- Heavy benign noise (DCOM 10016, Ntfs 98, Windows Update, Tcpip 4266, Firewall 2042).
- A repeating candidate lead: `Microsoft-Windows-Hyper-V-VmSwitch` event 285 ("OID_GEN_STATISTICS took too long", host vNIC) about once a minute before the Nov 12 crash. WSL (Ubuntu) is installed. This is unverified; it has not been compared against freeze-free periods.

Because the logs go silent before the freeze, log analysis alone cannot find the cause. The tool must collect evidence while the system is alive and correlate it with the logs afterwards. The longer-term goal is an ongoing-monitoring AI agent that finds problems on this machine and helps resolve them. The freeze is the first problem it must solve.

## Goals

1. Capture continuous system telemetry that survives a hard reset, so the last minutes before a freeze are recoverable.
2. After an unclean reboot, automatically produce a post-mortem: a timeline of the last 10 to 15 minutes of telemetry joined with event-log entries, highlighting what changed or degraded just before the freeze.
3. Triage Windows event logs: read, dedupe, group, suppress known noise, score severity, surface real problems.
4. Use AI to classify and explain grouped events: a local LLM by default, a frontier model for escalation.
5. Suggest fixes in plain language. Never apply them.
6. Stay light enough to run permanently on the workstation without contributing to the problem it is diagnosing.

## Non-goals (v1)

- Registry and system-configuration auditing (planned later; keep the architecture open to it).
- Auto-remediation of any kind.
- Real-time freeze prediction or prevention.
- A GUI, tray app or dashboard (CLI first).
- Multi-machine or fleet monitoring.

## Anti-goals

- The recorder must not add meaningful CPU, memory, disk or GPU load, or it could mask or worsen the freeze.
- No bulk raw logs sent to any cloud model. No unredacted user, host, IP or path data leaving the machine.
- No tool that "works" but yields a report the owner cannot act on (for example a wall of events with no ranking or explanation).

## Constraints

- Language: Rust. Platform: Windows 11, single machine.
- Local LLM: the owner already has llama.cpp with Gemma and Qwen based models. The tool talks to `llama-server`'s OpenAI-compatible HTTP API rather than embedding a model, so models can be swapped through configuration.
- Frontier model: used only for escalation, only with redacted grouped summaries, and only when the owner has configured an API key (see Privacy).
- The recorder must survive a hard power loss with minimal data loss: append-only writes with explicit periodic flush to a pre-allocated ring buffer file.
- Reading all logs needs elevated rights (Security log in particular); the service runs as a Windows service.
- The project directory is not a git repository.

## Approaches considered

1. Log triage only. Simple, but cannot find a bug that leaves no log trail. Rejected as the sole approach.
2. Flight recorder plus log triage (chosen by the owner). Only approach that can capture evidence of a silent lockup, and the same recorder serves the ongoing-monitoring goal. Cost: a long-running service and more upfront work.
3. Triage first, recorder later. Delivers the noise filter sooner but delays the evidence needed for the freeze. Not chosen.

## Design

### Components

1. **Recorder service** (`wsg-recorder`): a Windows service that starts at boot. Every 2 to 5 seconds (configurable) it samples:
   - per-process CPU, working set, I/O bytes and handle count (top N by activity, plus totals)
   - system CPU utilisation, per-core clocks where available, interrupt and DPC time
   - memory: commit charge, available, paged and non-paged pool
   - disk: queue length, read/write latency and throughput per physical disk, NVMe health counters where exposed
   - network: per-adapter throughput and, where available, Hyper-V vSwitch counters
   - GPU via NVML: utilisation, memory, temperature, power, clocks
   - temperatures and fan or voltage sensors where Windows exposes them
   Samples go to a fixed-size ring buffer file with periodic flush. Retention target: at least the last several hours at full resolution.
2. **Event reader**: reads EVTX logs (System, Application and relevant operational channels such as Kernel-Power, Hyper-V-VmSwitch, Storage, Kernel-PnP, WHEA) with time-range and level filters.
3. **Triage engine**: dedupes and groups events by provider, id and normalised message template; applies a built-in known-noise ruleset (user-extensible); scores severity from level, frequency, novelty and proximity to incidents.
4. **Incident detector and post-mortem**: on boot, detects an unclean shutdown (Kernel-Power 41, EventLog 6008, ring buffer without a clean-shutdown marker). Builds a timeline of the last 10 to 15 minutes of telemetry before the last recorded sample, joined with event-log entries, and reports metrics that diverged from baseline (rising disk latency, memory growth, a runaway process, thermal or power spike, driver activity).
5. **Baseline and comparison**: compares an incident window against freeze-free periods, so a recurring event (such as the vSwitch 285 messages) is judged by whether it is actually correlated with freezes.
6. **AI layer**:
   - Local LLM (llama.cpp `llama-server`, OpenAI-compatible API) classifies and explains grouped events and the post-mortem summary.
   - Frontier model escalation for hard cases, for example when the local model is low confidence or the owner asks for a deeper analysis.
   - The AI receives grouped, redacted summaries and structured telemetry deltas, never raw bulk logs.
7. **Redaction**: a local step that replaces usernames, hostnames, IP and MAC addresses and file paths with stable placeholders before any frontier-model call. Placeholders map back locally so the final report reads naturally.
8. **CLI** (`wsg`): `status` (recorder health), `report` (triage of a time window), `postmortem` (latest or chosen incident), `explain <group>` (AI explanation), `noise` (manage suppressions), plus configuration for LLM endpoints and keys.

### Data flow

Recorder writes samples continuously. On `report` or after an unclean boot, the event reader and triage engine produce grouped events; the incident detector joins them with telemetry; the redactor prepares summaries; the AI layer annotates and ranks; the CLI prints a ranked, explained list with suggested next steps.

### Privacy

Default: nothing leaves the machine. The local LLM handles all routine classification. The frontier model is off until the owner configures a key, and every cloud call uses redacted, grouped summaries only. The owner confirmed using local models; the exact cloud-escalation default (opt-in versus never) is the builder's choice of opt-in, noted below as an assumption to confirm.

### Phasing inside v1

1. Recorder plus ring buffer, with a way to read it back.
2. Event reader, triage and noise rules, plain CLI report with no AI.
3. Post-mortem and baseline comparison.
4. Local LLM integration.
5. Redaction plus frontier-model escalation.

Phases 1 to 3 should already be useful for the freeze before any AI work.

## Decisions made by the owner

- Option 2 (recorder plus triage).
- Use the existing local llama.cpp setup with Gemma and Qwen based models.
- Redact before any cloud call; local LLM first.

## Calls made by the assistant (owner may override)

- Windows service for the recorder; CLI first; no GUI in v1.
- Talk to `llama-server` over HTTP instead of embedding a model.
- Telemetry sample interval of 2 to 5 seconds, ring-buffer retention of several hours.
- NVML for GPU data (RTX 3060).
- Frontier-model use is opt-in and off by default.
- Suggest fixes only; never apply them.

## Left to the builder

- Crate choices (Windows API bindings, EVTX parsing, service wrapper, HTTP client).
- Exact ring-buffer format, flush cadence and record schema.
- Which sensors are reachable without a kernel driver (some temperature and voltage data may need a third-party driver; document what is and is not available).
- Noise-rule format and initial ruleset.
- Baseline and divergence statistics.
- Prompt design and the local-model confidence threshold for escalation.
- Test strategy, including a way to replay recorded samples and EVTX fixtures.

## Resolved after builder review (assistant calls unless noted)

- **Durability:** ring buffer written with write-through and `FlushFileBuffers` about every 5 seconds; the roughly 10 second loss bound is a target to be measured on this exact drive and USB chain, not a guarantee (see the Codex review section). Fault-injection acceptance: a kill-the-process test is automated; a real power-cut test is run manually by the owner. Volume for the ring buffer (owner decision): the external USB drive E: (My Passport), so evidence does not share a disk with C:. If E: is missing at start or disappears, the recorder falls back to a small ring on C:, records the drive-loss event with a timestamp, and reports it in the post-mortem. Write-through is used because an external drive may have its own cache. Risk noted: a USB stall could itself affect the system; the heartbeat gaps help show if that happens.
- **Success for the freeze:** the tool must narrow the cause, not guarantee a fix. If telemetry shows nothing, the post-mortem says so and prints an out-of-band checklist (enable full or kernel dump settings, check BIOS and AGESA version, XMP/DOCP state, PSU, RAM test; the platform is AM4/DDR4, so EXPO does not apply). The recorder adds hang-oriented signals: a heartbeat whose gaps mark when sampling stalled, and optional ETW DPC/ISR latency.
- **Overhead budget:** under 1% CPU on average, under 100 MB RAM, ring buffer about 1 GB, at least 6 hours at full resolution. NVML runs in a separate helper process (a thread timeout cannot cancel a blocked native call); an NVML stall is itself recorded as evidence. See the Codex review section for the full isolation rules.
- **Hyper-V and WSL:** record vmmem usage and vSwitch counters. Baseline comparison starts as ranked hypotheses (event X is present in N of N incident windows and M of K quiet windows), not statistics, until enough incidents exist. Disabling WSL as an experiment is suggested by the tool, never required.
- **Service model:** runs as LocalSystem, installed with `wsg install`, auto-restart on failure. The CLI talks to the service over a named pipe and falls back to reading the ring buffer file directly. The post-mortem is generated automatically on the first boot after an unclean shutdown and written to disk; `wsg postmortem` re-renders it.
- **AI:** llama-server is started by the owner, not spawned by the tool. AI analysis runs only on demand or post-boot, never during sampling, so it cannot load the GPU during work. Frontier calls require per-run confirmation, use the Anthropic API first behind an OpenAI-compatible-style interface, and read the key from an environment variable or DPAPI-protected config. Redaction covers usernames, hostnames, IPs, MACs and user-profile paths; process and driver names are not redacted because they are the diagnostic signal.
- **Fixtures:** EVTX exports of the incident windows are taken with `wevtutil epl`, stored locally in a git-ignored fixtures folder, and never shared. The Security log is out of scope for v1.
- **Sensors (owner decision):** a third-party sensor source is acceptable. The recorder reads HWiNFO shared memory or LibreHardwareMonitor data when one of them is running, and bundles no driver of its own. When neither is running, temperature, voltage and per-core clock fields are recorded as unavailable and the post-mortem says so. The owner must install and run one of them for thermal and voltage evidence.

## Revisions after independent review (Codex, 2026-11-13)

An independent reviewer read this design and raised 18 findings. All are accepted. Where this section conflicts with earlier text, this section wins. Items marked "owner" need the owner's confirmation when the plan is reviewed; everything else is the assistant's call.

### Changes to the design

**Phase 0 and evidence preservation**
- **Phase 0, before any recorder code (new):** prepare for the next freeze now. Validate a manual crash-dump path: confirm the pagefile and disk space allow a complete or kernel dump, enable the keyboard crash trigger (CrashOnCtrlScroll), and note that it can itself fail if the freeze is at high IRQL. Also record the steps for an NMI or hardware reset button if the board has one. Waiting for telemetry to fail first would waste another incident.
- **Spike before building collectors:** benchmark the built-in Windows `logman` counter collection (circular, interval-based) as the phase 1 collector. If it covers CPU, memory, disk and network counters with acceptable durability, the Rust recorder becomes a thin layer for what `logman` cannot do (process top-N, NVML, sensors, heartbeat). This may shrink phase 1 considerably.
- **Preserve before reuse:** on service start, if the previous session ended without a clean marker, the previous ring is archived or pinned (copied or renamed with a boot and incident ID) before recording resumes. Incident identity and archive progress are persisted so repeated boots or restart loops cannot overwrite the only useful window. Archived incident windows and compact healthy-period summaries are kept separately from the live ring so baselines can span days.

**Ring buffer crash-consistency**
- Replace "append-only" with a real ring design: fixed-size records with framing, a monotonically increasing sequence number, a per-record checksum, a schema version, and a recoverable write position derived by scanning (not a single metadata pointer that can tear). Readers tolerate torn or corrupt records and skip them; one damaged write must not invalidate the rest. Reader and writer rules are defined so the CLI can read while the service writes.
- The data-loss bound is measured, not assumed: a test harness records the last durable sequence number under a real power cut or USB pull and reports the observed loss for this drive. The "about 10 seconds" figure is a target until measured.

**Isolation of anything that can block**
- NVML, sensor queries (HWiNFO, LibreHardwareMonitor) and storage writes each run behind bounded isolation: a helper process or dedicated worker with explicit abandonment, restart limits and no shared locks with the main sampling loop. A blocked call must not stall the heartbeat. No user-mode isolation survives a kernel-wide hang; the post-mortem says so instead of implying otherwise.
- Storage: a disconnected drive and a hung write are different conditions. Writes go through a bounded queue with dropped-sample accounting. If a write or flush does not return within a deadline, the recorder falls back to the C: ring while the original operation is still outstanding, and reconciles both files afterwards. The drive is identified by volume GUID or serial, not by the letter `E:`. If C: also fails, the recorder degrades to in-memory only and reports that.

**Honest incident timeline**
- Record and distinguish: last sample taken, last sample confirmed persisted, observed freeze onset (inferred from heartbeat gaps), forced power-off, and next boot. Kernel-Power 41 marks an unclean restart, not the freeze moment, and a missing clean-shutdown marker can also mean the recorder itself crashed. Use boot and session IDs, UTC wall time plus a monotonic clock, and handle sleep, clock adjustments and service restarts.
- Each signal states what it can and cannot support. A 2 to 5 second sample cannot catch brief voltage or power excursions, and a heartbeat gap shows missing progress, not USB or any specific cause. The post-mortem outputs "cause undetermined" when evidence is insufficient, together with the out-of-band checklist.

**Event logs**
- Use the Windows Event Log APIs (live queries and exported-file queries) rather than hand-parsed files where avoidable. Inventory the actual channels first and report any that are missing, disabled, inaccessible or rolled over. Preserve the structured XML when message rendering fails. Group by provider identity, event ID, version and relevant payload fields, not by localized message text.
- Suppression keeps evidence: a suppressed group still keeps counts, timing and payload variants, and the report can show suppressed noise on demand. Severity scoring must not rank routine chatter above rare precursors; novelty and proximity to an incident weigh heavily. Low-frequency, never-before-seen events near an incident are always surfaced.

**Sensors and GPU**
- Sensor source (owner decision): LibreHardwareMonitor is the supported source for v1; HWiNFO is dropped (its free shared memory stops after 12 hours). The plan picks one transport (its built-in web server or a small reader), documents supported versions, and notes that LibreHardwareMonitor loads its own kernel driver for sensor access, so it must run elevated and the owner should keep it updated. Define sensor identity, units and freshness (sample age), and record when the source is stale or missing. The external tools bring their own hardware-access cost, which counts toward the overhead budget.
- NVML support is checked per metric at start. Unsupported fields, unavailable values, initialization failure, GPU loss and reinitialization are handled, error status and sample age are preserved, and zero is never substituted for "unavailable".

**Security**
- LocalSystem is kept as small as possible. The service only samples, writes the ring and answers a read-only named pipe with an explicit ACL (administrators and the installing user). The service never loads code or reads configuration from user-writable paths; its binary, config and ring directory have restricted permissions, and the removable drive's files are validated on read. The AI layer, redaction and report interpretation run in the unprivileged CLI, outside the recorder.
- Per-run confirmation for frontier calls happens in the CLI, which is interactive, not in the service. The outbound payload uses an allowlisted schema (fixed fields, grouped counts, redacted strings), and every AI explanation must cite the evidence records it relied on. Redaction is best-effort and documented as not a guarantee of anonymity, so frontier calls stay opt-in and show the owner the exact payload before sending. A model's self-reported confidence is not used as the escalation threshold; escalation is triggered by the owner or by objective rules (for example, unclassified high-severity groups).
- Because the project directory is not a git repository, fixtures are kept outside the project tree (under the owner's profile with restricted access), unless the owner prefers to initialize a repository with the fixtures folder ignored.

**Overhead budget**
- Beyond average CPU, the budget includes a per-cycle collection deadline, bounded queue sizes, a tail-latency limit (the sampler must not hold up foreground work), and the combined overhead of the recorder plus the sensor application. Process enumeration cost is measured before choosing top-N. Slow-changing health counters (NVMe health, SMART) are polled less often than fast counters. ETW DPC/ISR tracing stays optional and off until its session scope, buffer sizes and lost-event accounting are defined and measured.

**Baseline and Hyper-V**
- Quiet-window comparisons record exposure and context: uptime, workload, whether WSL2 or its virtual network was actually active, and configuration changes. Counts such as "N of N incident windows, M of K quiet windows" are shown with those caveats so they cannot mislead. Installed does not mean active, so the recorder notes whether the WSL VM was running.

**Hardware context (owner)**
- The first run and the post-mortem collect the platform facts that discriminate Ryzen freeze causes: motherboard and chipset, BIOS and AGESA version, DIMM make, speed and configuration, whether XMP/DOCP, PBO or undervolting is enabled, and recent changes (BIOS, driver or hardware) near the start of the freezes two weeks ago. The owner reports no deliberate hardware, BIOS or driver change before the freezes began; the only known change is a Windows update. The platform is AM4/DDR4, so EXPO does not apply.
- **Update history is evidence (found 2026-11-13):** installed OS updates are KB5127647 (Oct 14), KB5127694 and KB5121794 (Oct 15), KB5132688 (Nov 10) and KB5132061 (Nov 11, 2:38 AM, build 26300.9974). Other changes near the freezes: WSL 3.0.5.0 installed Nov 10 at 1:28 PM, a Realtek audio driver update Nov 11 at 9:58 PM, and Ubuntu installed Nov 12. Windows Update also shows heavy churn: `Microsoft.WindowsAppRuntime.2` installed 53 times and a Visual Studio 2019 security update 16.11.62 installed about 18 times in 14 days, plus repeated failures (0x80073D02) for GamingApp and WhatsApp. The recorder and post-mortem include an "update and install timeline" (hotfixes, Windows Update client events 19, 20 and 43, driver installs) aligned to incidents, and flag install loops as a possible load source. Whether any of this relates to the freezes is unproven.

### Testing and acceptance (added)

Acceptance covers: ring wrap, torn and corrupted records, stalled collectors (NVML, sensors), USB removal and hung writes, exhausted disks, repeated boots and service restart loops, and partially written reports. It also covers a measured power-cut test on E: reporting the observed loss, plus replay of recorded samples and EVTX fixtures. The kill-the-process test remains but is not accepted as proof of power-loss durability.

### Updated phasing

0. Dump-path preparation and the `logman` spike (no Rust required).
1. Recorder plus ring buffer and archive-on-boot, with reader. Scope depends on the `logman` spike.
2. Event reader, triage, noise rules (evidence-preserving), CLI report with no AI.
3. Post-mortem with honest timeline, hardware context and baseline comparison.
4. Local LLM integration.
5. Redaction, allowlisted payload and frontier-model escalation.
