# WindowsSystemGuard Phases 0-3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the crash-surviving system recorder, the evidence-preserving event-log triage, and the post-mortem that explains what happened before each hard freeze, with no AI.

**Architecture:** A Cargo workspace of five crates. `wsg-core` owns the record schema and the crash-consistent ring file. `wsg-recorder` is a small LocalSystem Windows service that samples through isolated collectors and writes the ring through a tiered (E: then C:) writer. `wsg-events` reads Windows event logs through the Event Log API and does grouping and noise handling. `wsg-analysis` joins ring data with events into an honest incident post-mortem. `wsg-cli` provides the unprivileged `wsg` command.

**Tech Stack:** Rust (cargo 1.100), `windows` (windows-rs) for Event Log, PDH, services, volumes and named pipes; `windows-service`; `serde` with `postcard`; `crc32fast`; `clap`; `thiserror`; `nvml-wrapper` (GPU helper only); `wmi`; `tempfile` for tests.

**Spec:** `docs/superpowers/specs/2026-11-13-windows-system-guard-design.md` (read it with this plan; the section "Revisions after independent review" overrides earlier text).

**Scope note:** The spec's phases 4 and 5 (local LLM, redaction, frontier escalation) are a separate subsystem and get their own plan after this one ships and the freeze evidence is in hand. This plan implements spec phases 0 to 3.

## Global Constraints

- Language Rust, Windows 11, single machine. No GUI. Suggest fixes only, never apply them.
- Sample interval 2 to 5 seconds, configurable, default 5. Ring flush about every 5 seconds with write-through plus `FlushFileBuffers`.
- Ring about 1 GB, at least 6 hours at full resolution.
- Overhead: under 1% CPU average, under 100 MB RAM, per-cycle collection deadline, bounded queues.
- Ring primary location is the external USB drive (My Passport, currently `E:`), identified by volume GUID, never by drive letter. Fallback is a small ring on C:. If both fail, record in memory only and report it.
- Recorder runs as LocalSystem, only samples, writes the ring, and serves a read-only named pipe with an explicit ACL (administrators and the installing user). It never loads code or config from user-writable paths.
- Sensor source is LibreHardwareMonitor only, read through its built-in web server (`http://localhost:8085/data.json`). The project bundles no driver. HWiNFO is not supported.
- Anything that can block (NVML, sensor HTTP, storage writes) runs behind bounded isolation (helper process or worker) with restart limits and no shared locks with the sampling loop.
- Unavailable data is `Unavailable{reason}` plus sample age. Zero is never substituted for unavailable.
- Event logs are read with the Windows Event Log APIs. Group by provider, event ID, version and payload fields, never by localized message text. The Security log is out of scope.
- Noise suppression keeps counts, timing and payload variants. Rare events near an incident are always surfaced.
- The post-mortem says "cause undetermined" when evidence is insufficient, and distinguishes last sample taken, last sample persisted, inferred freeze onset, forced power-off and next boot.
- Fixtures (EVTX exports, recorded rings) live outside the project tree, at the path in env var `WSG_FIXTURES` (default `%USERPROFILE%\wsg-fixtures`). Tests needing them skip with a printed notice when unset.
- Platform is AM4/DDR4 (Ryzen 7 3700X); never mention EXPO, use XMP/DOCP.

## Review Focus

1. A freeze-looking gap that is really sleep, hibernate or resume: expected to be classified as sleep, not freeze (Task 13).
2. The USB drive missing or asleep at the very first start, or removed mid-run: expected to fall back to C: without crashing or losing the heartbeat (Task 6).
3. Wall clock jumping backwards (NTP sync, DST): expected to order by sequence and monotonic time, never reorder or drop records (Tasks 3 and 13).
4. A recorder restart loop within seconds of boot: expected to never overwrite or re-archive an already archived incident (Task 5).
5. An event whose message cannot be rendered, has no payload, or is non-English: expected to be kept with raw XML and still grouped correctly (Tasks 10 and 11).

## File Structure

```
Cargo.toml                      workspace
crates/wsg-core/src/{lib,record,ring,sample,archive,writer,clock}.rs
crates/wsg-recorder/src/{main,service,collectors/{mod,heartbeat,counters,processes,wsl}.rs,supervisor,pipe}.rs
crates/wsg-recorder/src/bin/{wsg-gpu-helper,wsg-sensor-helper}.rs
crates/wsg-events/src/{lib,reader,xml,group,noise,score,updates}.rs
crates/wsg-analysis/src/{lib,timeline,gap,diverge,baseline,hardware,render}.rs
crates/wsg-cli/src/{main,install}.rs
scripts/{phase0-dump-prep.ps1,measure-overhead.ps1,logman-spike.ps1}
docs/spikes/logman-spike.md
```

---

### Task 1: Phase 0 dump preparation

**Files:**
- Create: `scripts/phase0-dump-prep.ps1`

**Interfaces:**
- Produces: a script, `phase0-dump-prep.ps1 [-Apply]`, printing a PASS/FAIL line per check and exit code 0 only if all pass.

- [ ] **Step 1: Implement the script.** Without `-Apply` it only reads. Checks: `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl` `CrashDumpEnabled` is 1 (complete) or 2 (kernel); pagefile exists on the system volume and its max size is at least physical RAM (64 GB) for a complete dump, or 16 GB for a kernel dump; free space on the system volume is at least that size; `Services\kbdhid\Parameters\CrashOnCtrlScroll` is 1 (and `i8042prt` if a PS/2 keyboard is present); `NMICrashDump` is 1. With `-Apply` it sets these values and prints that a reboot is required; it never changes the pagefile, only reports what to change.
- [ ] **Step 2: Run without `-Apply` in an elevated shell.**
Run: `pwsh -File scripts/phase0-dump-prep.ps1`
Expected: one line per check, FAIL lines naming the exact registry value to change.
- [ ] **Step 3: The owner runs with `-Apply`, reboots, and re-runs.** Expected: all PASS, exit code 0. Record the result and the owner's keyboard type and whether the board has a reset or NMI header in `docs/spikes/logman-spike.md` under "Phase 0 results".
- [ ] **Step 4: Commit** (after Task 2 step 1 creates the repository): `git add scripts docs && git commit -m "feat: phase 0 dump preparation script"`

### Task 2: logman spike and gate

**Files:**
- Create: `scripts/logman-spike.ps1`, `docs/spikes/logman-spike.md`

**Interfaces:**
- Produces: a recorded go/no-go decision in `docs/spikes/logman-spike.md` ("adopt" or "reject") that gates Task 7.

- [ ] **Step 1: Create the workspace and repository.** `git init`, root `Cargo.toml` listing the five crates as empty `lib`/`bin` stubs, `.gitignore` for `target/` and `*.bin`. Verify `cargo build --workspace` succeeds. Commit `chore: workspace scaffold`.
- [ ] **Step 2: Implement `logman-spike.ps1`.** Creates a circular counter data collector set `wsg-spike` at a 5 second interval for `\Processor(_Total)\% Processor Time`, `\Memory\Available MBytes`, `\Memory\Pool Nonpaged Bytes`, `\PhysicalDisk(*)\Avg. Disk sec/Read`, `\PhysicalDisk(*)\Avg. Disk sec/Write`, `\PhysicalDisk(*)\Current Disk Queue Length`, `\Network Interface(*)\Bytes Total/sec`, output to the E: drive, max size 256 MB. Provides `-Start`, `-Stop`, `-Remove`.
- [ ] **Step 3: Run it for 30 minutes, then pull the E: USB cable without ejecting, then reconnect.** Measure the seconds between the last data in the file (`relog -f csv`) and the pull time.
- [ ] **Step 4: Write the decision.** Rule: "adopt" only if the observed loss is 15 seconds or less AND the file is readable after the pull AND per-process data is not required from it. Otherwise "reject". Record measured numbers.
- [ ] **Step 5: Commit** `docs: logman spike result`.

### Task 3: Record format and crash-consistent ring

**Files:**
- Create: `crates/wsg-core/src/{record,ring}.rs`; Test: `crates/wsg-core/tests/ring.rs`

**Interfaces:**
- Produces:
  - `pub struct BootId(pub [u8;16])`, `pub enum RecordKind { Sample=1, Heartbeat=2, Marker=3 }`
  - `pub struct Record { pub seq:u64, pub boot:BootId, pub utc_ns:i64, pub mono_ns:u64, pub kind:RecordKind, pub payload:Vec<u8> }`
  - `Ring::create(path:&Path, capacity_bytes:u64) -> Result<Ring,RingError>`, `Ring::open(path:&Path) -> Result<Ring,RingError>`
  - `Ring::append(&mut self, kind:RecordKind, boot:BootId, utc_ns:i64, mono_ns:u64, payload:&[u8]) -> Result<u64,RingError>` (returns seq)
  - `Ring::flush(&mut self) -> Result<(),RingError>`, `Ring::last_durable_seq(&self) -> u64`, `Ring::mark_clean_shutdown(&mut self, boot:BootId) -> Result<(),RingError>`
  - `RingReader::open(path:&Path) -> Result<RingReader,RingError>`, `records(&self) -> Vec<Record>` (ordered by `seq`, corrupt skipped), `skipped_corrupt(&self) -> usize`, `ended_cleanly(&self) -> bool`
- Format: fixed header with magic, schema version and capacity; each slot is framed with magic, `seq`, length, payload, CRC32 over the frame. The write position is recovered by scanning for the highest valid `seq`; there is no separate position pointer. The file is opened with `FILE_FLAG_WRITE_THROUGH`.

- [ ] **Step 1: Write failing tests** in `tests/ring.rs`: `appends_and_reads_back_in_seq_order`, `wraps_and_keeps_newest_records`, `reopen_recovers_next_seq`, `torn_last_record_is_skipped_and_earlier_records_survive` (truncate the last N bytes), `corrupt_middle_record_does_not_invalidate_others` (flip a byte, assert `skipped_corrupt()==1` and the rest intact), `ended_cleanly_only_after_marker`, `orders_by_seq_when_wall_clock_goes_backwards` (append with decreasing `utc_ns`, assert order by `seq`), `reader_can_read_while_writer_appends` (two threads).
- [ ] **Step 2: Run** `cargo test -p wsg-core --test ring`. Expected: FAIL (items undefined).
- [ ] **Step 3: Implement the signatures above** in `record.rs` and `ring.rs`; payload size cap 64 KiB, `RingError::PayloadTooLarge` beyond it.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat(core): crash-consistent ring`.

### Task 4: Sample schema and clocks

**Files:**
- Create: `crates/wsg-core/src/{sample,clock}.rs`; Test: `crates/wsg-core/tests/sample.rs`

**Interfaces:**
- Produces:
  - `pub enum Reading<T> { Value{ v:T, age_ms:u32 }, Unavailable{ reason:String } }`
  - `pub struct Sample { pub cpu:Reading<CpuStats>, pub mem:Reading<MemStats>, pub disks:Vec<DiskStats>, pub net:Vec<NetStats>, pub procs:Vec<ProcStat>, pub gpu:Reading<GpuStats>, pub sensors:Reading<SensorSet>, pub wsl_vm_running:Reading<bool>, pub cycle_ms:u32 }` with `encode(&self)->Vec<u8>` and `decode(&[u8])->Result<Sample,DecodeError>` (postcard, leading schema-version byte)
  - `pub fn now_utc_ns()->i64`, `pub fn mono_ns()->u64` (QueryUnbiasedInterruptTime is not used; use `QueryPerformanceCounter`), `pub fn new_boot_id()->BootId`
  - `CpuStats { total_pct, dpc_pct, interrupt_pct }`, `MemStats { commit_bytes, available_bytes, nonpaged_pool_bytes, paged_pool_bytes }`, `DiskStats { disk_id:String, queue_len, read_latency_ms, write_latency_ms, bytes_per_sec }`, `NetStats { adapter:String, bytes_per_sec }`, `ProcStat { pid, name, cpu_pct, working_set_bytes, io_bytes_per_sec, handles }`, `GpuStats { util_pct, mem_used_bytes, temp_c, power_w, clock_mhz }`, `SensorSet { cpu_temp_c:Option<f32>, per_core_clock_mhz:Vec<f32>, voltages:Vec<(String,f32)>, fans_rpm:Vec<(String,u32)> }`

- [ ] **Step 1: Write failing tests:** `unavailable_roundtrips_and_is_not_zero` (a `Reading::Unavailable` decodes as Unavailable, never `Value{0}`), `sample_roundtrips`, `rejects_unknown_schema_version`, `mono_ns_is_monotonic`.
- [ ] **Step 2: Run** `cargo test -p wsg-core --test sample`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(core): sample schema and clocks`.

### Task 5: Archive-on-boot

**Files:**
- Create: `crates/wsg-core/src/archive.rs`; Test: `crates/wsg-core/tests/archive.rs`

**Interfaces:**
- Consumes: `RingReader`, `BootId` (Task 3).
- Produces: `pub struct IncidentId(pub String)`; `pub fn archive_if_unclean(ring:&Path, archive_dir:&Path, new_boot:BootId, now_utc_ns:i64) -> Result<Option<IncidentId>,ArchiveError>`; `pub fn list_incidents(archive_dir:&Path)->Vec<IncidentMeta>`; `IncidentMeta { id, previous_boot, detected_utc_ns, state:IncidentState }` where `IncidentState` is `Archived` or `Analyzed`.
- Behavior: if the ring did not end cleanly, copy it to `<archive_dir>/<id>/ring.bin`, verify the copy with a full checksum scan, write `incident.json`, and only then return. A clean ring returns `None`.

- [ ] **Step 1: Write failing tests:** `unclean_ring_is_archived_with_metadata`, `clean_ring_is_not_archived`, `second_call_for_same_ring_returns_same_id_without_new_copy` (restart loop), `five_rapid_restarts_create_one_incident`, `archive_failure_leaves_original_ring_untouched` (read-only archive dir), `archived_copy_matches_original_records`.
- [ ] **Step 2: Run** `cargo test -p wsg-core --test archive`. Expected: FAIL.
- [ ] **Step 3: Implement.** Derive the incident id from the previous boot id so repeats are idempotent.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(core): archive previous ring on unclean shutdown`.

### Task 6: Tiered writer

**Files:**
- Create: `crates/wsg-core/src/writer.rs`; Test: `crates/wsg-core/tests/writer.rs`

**Interfaces:**
- Consumes: `Ring` (Task 3).
- Produces:
  - `pub trait RingSink: Send { fn append(&mut self, rec:&NewRecord)->io::Result<()>; fn flush(&mut self)->io::Result<()>; }` and `pub struct NewRecord { kind, boot, utc_ns, mono_ns, payload:Vec<u8> }`
  - `pub struct TieredWriter`; `TieredWriter::new(primary:Box<dyn RingSink>, fallback:Box<dyn RingSink>, deadline:Duration, queue_cap:usize)->TieredWriter`
  - `submit(&self, r:NewRecord)->SubmitResult` (`Queued` or `Dropped`), `stats(&self)->WriterStats { dropped:u64, fallback_active:bool, primary_stalls:u64, memory_only:bool }`
  - `pub fn resolve_volume_path(volume_guid:&str)->Option<PathBuf>`, `pub fn volume_guid_for(path:&Path)->Option<String>`
- Behavior: a worker thread drains the bounded queue. If primary `append` or `flush` does not return within `deadline`, mark a stall, switch to fallback while the primary operation stays outstanding, and reconcile later. If both sinks fail, `memory_only` is true and records stay in a bounded in-memory buffer.

- [ ] **Step 1: Write failing tests** with fake sinks: `queue_full_drops_and_counts`, `hung_primary_switches_to_fallback_within_deadline`, `primary_recovers_and_records_reconcile_in_seq_order`, `both_sinks_failing_goes_memory_only`, `missing_primary_at_start_uses_fallback_immediately`, `heartbeat_records_still_written_during_primary_stall`.
- [ ] **Step 2: Run** `cargo test -p wsg-core --test writer`. Expected: FAIL.
- [ ] **Step 3: Implement.** `resolve_volume_path` uses `FindFirstVolume`/`GetVolumePathNamesForVolumeName`.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(core): tiered writer with fallback`.

### Task 7: Collectors

**Files:**
- Create: `crates/wsg-recorder/src/collectors/{mod,heartbeat,counters,processes,wsl}.rs`; Test: `crates/wsg-recorder/tests/collectors.rs`

**Interfaces:**
- Consumes: sample types (Task 4).
- Produces: `pub trait Collector: Send { fn name(&self)->&'static str; fn collect(&mut self, budget:Duration)->CollectOutcome; }`; `pub enum CollectOutcome { Ok(SampleFragment), Unavailable(String), TimedOut }`; `SampleFragment` is an enum with one variant per `Sample` field; `pub fn assemble(frags:Vec<SampleFragment>, cycle_ms:u32)->Sample`. Collectors: `HeartbeatCollector`, `CounterCollector` (PDH: CPU, DPC, interrupt, memory, pools, per-disk latency and queue, per-adapter throughput), `ProcessCollector::new(top_n:usize)` (enumerate all, return top N by CPU plus I/O plus working set), `WslCollector` (whether `vmmem`/`vmmemWSL` runs, plus Hyper-V vSwitch counters if present).
- Gate: if `docs/spikes/logman-spike.md` says "adopt", skip `CounterCollector` and instead read the logman output in Task 13 via `relog -f csv`; every other collector stays.

- [ ] **Step 1: Write failing tests:** `assemble_marks_missing_fragments_unavailable_not_zero`, `process_collector_returns_at_most_top_n_and_includes_self`, `counter_collector_returns_values_on_this_machine` (live, cpu 0 to 100), `collector_over_budget_returns_timed_out` (fake slow collector), `wsl_collector_reports_bool_or_unavailable`.
- [ ] **Step 2: Run** `cargo test -p wsg-recorder --test collectors`. Expected: FAIL.
- [ ] **Step 3: Implement** with the signatures above. The process enumeration time is measured once and logged at startup.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(recorder): in-process collectors`.

### Task 8: Isolated helpers (GPU and sensors)

**Files:**
- Create: `crates/wsg-recorder/src/supervisor.rs`, `crates/wsg-recorder/src/bin/{wsg-gpu-helper,wsg-sensor-helper}.rs`; Test: `crates/wsg-recorder/tests/supervisor.rs`

**Interfaces:**
- Produces:
  - `pub struct HelperSpec { pub exe:PathBuf, pub args:Vec<String>, pub call_deadline:Duration, pub restart_limit:u32, pub restart_window:Duration }`
  - `pub struct HelperSupervisor`; `HelperSupervisor::spawn(spec:HelperSpec)->HelperSupervisor`; `poll(&mut self)->Reading<serde_json::Value>`; `stats(&self)->HelperStats { restarts:u32, abandoned:bool, last_stall_utc_ns:Option<i64> }`
  - Helper protocol: the helper prints one JSON line per sample on stdout. `wsg-gpu-helper` reports per-metric values or an `unsupported` marker for each NVML field; `wsg-sensor-helper` GETs LibreHardwareMonitor's `data.json` with a 1 second HTTP timeout and maps it to `SensorSet`.
  - Adapters: `GpuCollector` and `SensorCollector` implement `Collector` over a supervisor.

- [ ] **Step 1: Write failing tests** using a fake helper binary: `hung_helper_is_killed_and_poll_returns_unavailable_with_stall_time`, `helper_restarts_up_to_limit_then_abandoned`, `poll_never_blocks_longer_than_call_deadline`, `helper_error_line_becomes_unavailable_with_reason`, `stale_sample_age_is_reported`, `sensor_helper_unreachable_lhm_is_unavailable` (nothing listening on 8085), `gpu_unsupported_field_is_unavailable_not_zero`.
- [ ] **Step 2: Run** `cargo test -p wsg-recorder --test supervisor`. Expected: FAIL.
- [ ] **Step 3: Implement.** The supervisor reads helper stdout on its own thread; `poll` returns the latest line with its age and never waits.
- [ ] **Step 4: Run.** Expected: PASS. Then run `wsg-gpu-helper` by hand once and confirm it prints a JSON line for the RTX 3060.
- [ ] **Step 5: Commit** `feat(recorder): isolated gpu and sensor helpers`.

### Task 9: Recorder service

**Files:**
- Create: `crates/wsg-recorder/src/{main,service,pipe}.rs`, `scripts/measure-overhead.ps1`; Test: `crates/wsg-recorder/tests/loop.rs`

**Interfaces:**
- Consumes: Tasks 3 to 8.
- Produces: `pub fn run_cycle(collectors:&mut [Box<dyn Collector>], writer:&TieredWriter, boot:BootId, seq_clock:&dyn Clock, interval:Duration, per_collector_budget:Duration)`; `pub trait Clock { fn utc_ns(&self)->i64; fn mono_ns(&self)->u64; }`; named pipe `\\.\pipe\wsg-recorder` serving `STATUS` (JSON with `WriterStats`, `HelperStats`, last seq, ring path) read-only, with a DACL for Administrators and the installing user only.
- Behavior: on start, call `archive_if_unclean` before opening the ring; write a heartbeat record every cycle even when every collector fails; on service stop write the clean-shutdown marker; configuration is read only from `%ProgramData%\WindowsSystemGuard\config.toml` (ACL: administrators and SYSTEM write only).

- [ ] **Step 1: Write failing tests:** `cycle_writes_heartbeat_even_if_all_collectors_time_out`, `cycle_respects_total_deadline` (assert a cycle with a 10 s collector finishes within interval), `start_archives_unclean_previous_ring`, `stop_writes_clean_marker`, `config_from_user_writable_path_is_rejected`.
- [ ] **Step 2: Run** `cargo test -p wsg-recorder --test loop`. Expected: FAIL.
- [ ] **Step 3: Implement** `run_cycle`, the service entry through `windows-service`, and the pipe server.
- [ ] **Step 4: Run.** Expected: PASS. Then run `scripts/measure-overhead.ps1 -Minutes 10` against the live service. Expected: average CPU under 1%, working set under 100 MB, printed as PASS lines.
- [ ] **Step 5: Commit** `feat(recorder): service, cycle loop and status pipe`.

### Task 10: Event Log reader

**Files:**
- Create: `crates/wsg-events/src/{reader,xml}.rs`; Test: `crates/wsg-events/tests/reader.rs`

**Interfaces:**
- Produces:
  - `pub struct EventRecord { pub channel:String, pub provider:String, pub event_id:u16, pub version:u8, pub level:u8, pub utc_ns:i64, pub record_id:u64, pub payload:BTreeMap<String,String>, pub rendered_message:Option<String>, pub raw_xml:String }`
  - `pub fn parse_event_xml(xml:&str)->Result<EventRecord,XmlError>`
  - `pub struct ChannelStatus { name:String, state:ChannelState }` with `ChannelState { Ok, Disabled, AccessDenied, Missing, RolledOver }`; `pub fn inventory_channels(wanted:&[&str])->Vec<ChannelStatus>`
  - `pub fn query(channel:&str, from_utc_ns:i64, to_utc_ns:i64, max_level:u8)->Result<Vec<EventRecord>,EventError>` and `pub fn query_file(path:&Path, from_utc_ns:i64, to_utc_ns:i64, max_level:u8)->Result<Vec<EventRecord>,EventError>` (EvtQuery and EvtRender; if message rendering fails, `rendered_message` is `None` and `raw_xml` is kept)
- Default wanted channels: System, Application, Kernel-PnP, Hyper-V-VmSwitch-Operational, Storage-ClassPnP, Kernel-Boot, Kernel-EventTracing/Admin (WHEA-Logger events come from the System channel). Query only the channels `inventory_channels` reports `Ok` and list the rest in the report.

- [ ] **Step 1: Write failing tests:** `parses_kernel_power_41_fixture_xml`, `parses_event_with_no_eventdata`, `parses_non_english_message_xml`, `render_failure_keeps_raw_xml_and_none_message`, `live_system_query_returns_events_in_range`, `inventory_reports_missing_channel`, `query_file_reads_exported_evtx` (uses `WSG_FIXTURES`, skips if unset).
- [ ] **Step 2: Run** `cargo test -p wsg-events --test reader`. Expected: FAIL.
- [ ] **Step 3: Implement.** Export the incident-window fixtures once with `wevtutil epl System <fixtures>\system.evtx` into `WSG_FIXTURES`.
- [ ] **Step 4: Run.** Expected: PASS (fixture test prints a skip notice if the folder is absent).
- [ ] **Step 5: Commit** `feat(events): event log reader`.

### Task 11: Grouping, noise rules and scoring

**Files:**
- Create: `crates/wsg-events/src/{group,noise,score}.rs`; Test: `crates/wsg-events/tests/triage.rs`

**Interfaces:**
- Consumes: `EventRecord` (Task 10).
- Produces:
  - `pub struct GroupKey { provider:String, event_id:u16, version:u8, payload_sig:String }`; `pub struct EventGroup { key:GroupKey, count:u64, first_utc_ns:i64, last_utc_ns:i64, times_utc_ns:Vec<i64> /*capped at 1000*/, payload_variants:Vec<BTreeMap<String,String>> /*capped at 20*/, sample:EventRecord }`; `pub fn group(events:&[EventRecord])->Vec<EventGroup>`
  - `pub struct NoiseRules`; `NoiseRules::builtin()->NoiseRules` (DCOM 10016, Ntfs 98, Tcpip 4266, Firewall 2042, Kernel-PnP 219 pattern for WUDFRd after boot, and similar); `NoiseRules::load(path:&Path)`, `NoiseRules::save(&self, path:&Path)`; `pub enum Disposition { Suppressed{ rule:String }, Surfaced }`; `pub fn classify(&self, g:&EventGroup)->Disposition`
  - `pub struct IncidentWindow { start_utc_ns:i64, end_utc_ns:i64 }`; `pub struct History(pub HashMap<GroupKey,u64>)` (prior counts); `pub fn score(g:&EventGroup, incident:Option<&IncidentWindow>, history:&History)->f32`

- [ ] **Step 1: Write failing tests:** `same_event_different_locale_text_groups_together`, `different_payload_creates_different_group`, `suppressed_group_keeps_count_times_and_variants`, `rare_never_seen_event_near_incident_outranks_frequent_noise`, `suppression_never_hides_a_group_inside_incident_window_if_novel`, `builtin_rules_suppress_dcom_10016_on_fixture` (fixture-gated), `rules_roundtrip_through_file`, `huge_group_caps_times_and_variants`.
- [ ] **Step 2: Run** `cargo test -p wsg-events --test triage`. Expected: FAIL.
- [ ] **Step 3: Implement.** Score combines level, log-scaled frequency (lower for frequent), novelty (not in `History`), and proximity to the incident (higher closer to `end_utc_ns`).
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(events): grouping, noise rules and scoring`.

### Task 12: Update and install timeline

**Files:**
- Create: `crates/wsg-events/src/updates.rs`; Test: `crates/wsg-events/tests/updates.rs`

**Interfaces:**
- Produces: `pub struct UpdateEvent { utc_ns:i64, kind:UpdateKind, name:String, detail:String }` with `UpdateKind { Started, Succeeded, Failed{ code:String }, Hotfix, DriverInstall }`; `pub fn update_timeline(from_utc_ns:i64, to_utc_ns:i64)->Result<Vec<UpdateEvent>,EventError>` (WindowsUpdateClient events 19, 20, 43, installed hotfixes via WMI `Win32_QuickFixEngineering`, driver installs from Kernel-PnP/DriverFrameworks channels where present); `pub struct InstallLoop { name:String, count:u32, first_utc_ns:i64, last_utc_ns:i64 }`; `pub fn detect_install_loops(events:&[UpdateEvent], min_repeats:u32, window:Duration)->Vec<InstallLoop>`.

- [ ] **Step 1: Write failing tests** from synthetic events: `detects_package_installed_ten_times_in_a_day`, `ignores_single_install`, `failed_events_carry_error_code_0x80073D02`, `loops_are_sorted_by_count_desc`.
- [ ] **Step 2: Run** `cargo test -p wsg-events --test updates`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS. Then run once live over the last 14 days and confirm `Microsoft.WindowsAppRuntime.2` is reported as a loop (the owner's machine had 53 installs).
- [ ] **Step 5: Commit** `feat(events): update and install timeline`.

### Task 13: Honest incident timeline and gap classification

**Files:**
- Create: `crates/wsg-analysis/src/{timeline,gap}.rs`; Test: `crates/wsg-analysis/tests/timeline.rs`

**Interfaces:**
- Consumes: `Record`, `Sample` (Tasks 3, 4), `EventRecord` (Task 10).
- Produces:
  - `pub struct IncidentTimeline { last_sample_taken:Option<Stamp>, last_sample_persisted:Option<Stamp>, freeze_onset_estimate:Option<Stamp>, forced_power_off:Option<Stamp>, next_boot:Option<Stamp>, ring_ended_cleanly:bool, recorder_crash_suspected:bool }` where `Stamp { utc_ns:i64, mono_ns:Option<u64>, seq:Option<u64> }`
  - `pub enum GapKind { Sleep, Freeze, RecorderStopped }`; `pub fn classify_gap(gap_start_utc_ns:i64, gap_end_utc_ns:i64, events:&[EventRecord])->GapKind` (Sleep if Kernel-Power 42/506/507/105 or Power-Troubleshooter 1 spans the gap; RecorderStopped if a Service Control Manager stop/start for the recorder spans it; else Freeze)
  - `pub fn build_timeline(records:&[Record], events:&[EventRecord], heartbeat_interval:Duration)->IncidentTimeline` (uses heartbeat gaps for onset, orders by `seq` and `mono_ns`, tolerates backwards wall clock)

- [ ] **Step 1: Write failing tests:** `heartbeat_gap_with_kernel_power_41_is_freeze`, `gap_spanning_sleep_events_is_sleep_not_freeze`, `gap_with_recorder_service_restart_is_recorder_stopped`, `wall_clock_going_backwards_does_not_reorder_records`, `forced_power_off_and_next_boot_come_from_event_41_and_6008`, `last_persisted_differs_from_last_taken_when_writer_lagged`, `clean_marker_means_no_incident`.
- [ ] **Step 2: Run** `cargo test -p wsg-analysis --test timeline`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(analysis): honest incident timeline`.

### Task 14: Divergence, baseline and hardware context

**Files:**
- Create: `crates/wsg-analysis/src/{diverge,baseline,hardware}.rs`; Test: `crates/wsg-analysis/tests/analysis.rs`

**Interfaces:**
- Produces:
  - `pub struct Divergence { metric:String, baseline_median:f64, incident_value:f64, ratio:f64, evidence_seqs:Vec<u64> }`; `pub fn diverged_metrics(window:&[Sample], baseline:&[Sample], min_ratio:f64)->Vec<Divergence>` (disk latency, queue length, commit growth, pool growth, per-process CPU and I/O, GPU temp and util, sensors; skips Unavailable readings)
  - `pub struct Presence { incident:(u32,u32), quiet:(u32,u32), caveats:Vec<String> }`; `pub fn compare(incident_windows:&[WindowSummary], quiet_windows:&[WindowSummary], key:&GroupKey)->Presence` where `WindowSummary { groups:HashSet<GroupKey>, uptime_s:u64, wsl_vm_running:Option<bool>, config_changes:Vec<String> }` and caveats name differing uptime, differing WSL state and config changes
  - `pub struct HardwareContext { motherboard:String, chipset:Option<String>, bios_version:String, agesa:Option<String>, dimms:Vec<DimmInfo>, xmp_docp_enabled:Option<bool>, recent_driver_changes:Vec<String> }`; `HardwareContext::collect()->HardwareContext` (WMI `Win32_BaseBoard`, `Win32_BIOS`, `Win32_PhysicalMemory`)

- [ ] **Step 1: Write failing tests:** `disk_latency_spike_is_reported_with_evidence_seqs`, `unavailable_readings_are_skipped_not_treated_as_zero`, `no_divergence_above_threshold_returns_empty`, `presence_shows_n_of_n_and_m_of_k_with_caveats`, `compare_flags_wsl_state_mismatch`, `hardware_context_collects_on_this_machine` (live: motherboard and bios_version non-empty).
- [ ] **Step 2: Run** `cargo test -p wsg-analysis --test analysis`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(analysis): divergence, baseline and hardware context`.

### Task 15: Post-mortem renderer

**Files:**
- Create: `crates/wsg-analysis/src/render.rs`; Test: `crates/wsg-analysis/tests/render.rs`

**Interfaces:**
- Consumes: Tasks 11 to 14.
- Produces: `pub struct PostMortemInput { timeline:IncidentTimeline, divergences:Vec<Divergence>, surfaced_groups:Vec<(EventGroup,f32)>, suppressed_summary:Vec<(String,u64)>, update_events:Vec<UpdateEvent>, install_loops:Vec<InstallLoop>, presence:Vec<(GroupKey,Presence)>, hardware:HardwareContext, writer_stats:Option<WriterStats>, helper_stats:Vec<HelperStats>, sensors_available:bool }`; `pub fn render_postmortem(i:&PostMortemInput)->String`.
- Behavior: sections for timeline, what changed before the freeze, surfaced events, updates and install loops, hardware context, evidence quality (E: loss, helper stalls, missing sensors), and an out-of-band checklist (dump settings, BIOS/AGESA, XMP/DOCP state, PSU, RAM test, `wsl --shutdown` experiment). If `divergences` is empty and the timeline has no heartbeat-gap evidence, the first line is "Cause undetermined".

- [ ] **Step 1: Write failing tests:** `empty_evidence_says_cause_undetermined_first`, `divergence_appears_with_evidence_seq_numbers`, `sensors_unavailable_is_stated`, `install_loop_is_listed`, `never_mentions_expo`, `suppressed_noise_shown_as_counts_only`.
- [ ] **Step 2: Run** `cargo test -p wsg-analysis --test render`. Expected: FAIL.
- [ ] **Step 3: Implement** plain-text rendering.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(analysis): post-mortem renderer`.

### Task 16: CLI, install and automatic post-mortem

**Files:**
- Create: `crates/wsg-cli/src/{main,install}.rs`; Test: `crates/wsg-cli/tests/cli.rs`

**Interfaces:**
- Consumes: all earlier tasks.
- Produces: binary `wsg` with subcommands `status` (reads the named pipe, falls back to reading the ring file), `report [--since <dur>]` (triage of a window, no AI), `postmortem [--incident <id>] [--auto]` (builds and renders; `--auto` processes every `Archived` incident and sets it `Analyzed`, writing `<archive_dir>/<id>/postmortem.txt`), `noise list|add <provider> <id> <reason>|remove <rule>`, `install` and `uninstall` (register the `wsg-recorder` service with auto-restart on failure under LocalSystem, set the directory ACLs, and register a startup scheduled task that runs `wsg postmortem --auto`).

- [ ] **Step 1: Write failing tests:** `postmortem_on_fixture_incident_writes_file_and_marks_analyzed`, `postmortem_auto_is_idempotent`, `report_since_filters_by_window`, `noise_add_then_list_shows_rule`, `status_without_service_falls_back_to_ring_file`, `install_dry_run_prints_planned_actions` (`wsg install --dry-run`).
- [ ] **Step 2: Run** `cargo test -p wsg-cli --test cli`. Expected: FAIL.
- [ ] **Step 3: Implement.** Use `clap`; `--dry-run` for install and uninstall.
- [ ] **Step 4: Run.** Expected: PASS. Then, as owner in an elevated shell: `wsg install`, reboot, `wsg status` shows a live ring on the E: volume.
- [ ] **Step 5: Run the power-cut acceptance:** with the service running for 30 minutes, pull the E: USB cable, then run `wsg postmortem`. Expected: the report states observed data loss in seconds and the fallback ring takes over. Record the measured loss in `docs/spikes/logman-spike.md`.
- [ ] **Step 6: Commit** `feat(cli): wsg command, install and automatic post-mortem`.

---

## Self-Review

- **Spec coverage:** phase 0 (Task 1), logman spike (2), ring and crash-consistency (3), schema and unavailable semantics (4), archive-on-boot (5), tiered writer and volume GUID (6), collectors including heartbeat, process top-N and WSL (7), isolation of NVML, sensors, LibreHardwareMonitor (8), service, ACL, clean marker, overhead (9), Event Log API, channel inventory and XML retention (10), evidence-preserving suppression and scoring (11), update and install timeline (12), honest timeline and sleep versus freeze (13), baseline with caveats, divergence and hardware context (14), post-mortem with "cause undetermined" and checklist (15), CLI, install, scheduled task, power-cut test (16). Spec phases 4 and 5 are deliberately a later plan.
- **Deferred inside this plan:** ETW DPC/ISR tracing is optional in the spec and is not built here; add it only if the post-mortem shows a driver-latency lead.
- **Type consistency:** `Record`, `BootId`, `Sample`, `Reading`, `EventRecord`, `GroupKey`, `EventGroup`, `IncidentWindow`, `IncidentTimeline`, `Divergence`, `Presence`, `HardwareContext`, `WriterStats` and `HelperStats` are each defined once and used with the same names later.
