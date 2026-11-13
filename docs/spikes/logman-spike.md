# logman spike

## Phase 0 results

OWNER-PENDING: run scripts/phase0-dump-prep.ps1 -Apply in an elevated shell, reboot, re-run, then record results here (keyboard type, reset/NMI header).

## logman spike

Question: does a logman circular counter collector set on a USB drive lose at most 15 seconds of data when the cable is pulled?

Procedure:

1. Elevated shell: `scripts/logman-spike.ps1 -Start` (set `wsg-spike`, 5 s interval, circular, 256 MB max, output `E:\wsg-spike`).
2. Run for 30 minutes.
3. Pull the E: USB cable without ejecting. Note the exact clock time of the pull. Reconnect.
4. Convert the file with `relog -f csv` and measure the seconds between the last sample and the pull time.
5. `scripts/logman-spike.ps1 -Stop`, then `-Remove`.

Decision rule: "adopt" only if the observed loss is 15 seconds or less AND the file is readable after the pull AND per-process data is not required from it. Otherwise "reject". Record measured numbers.

Decision: reject (default until measured). OWNER-PENDING: run scripts/logman-spike.ps1 -Start, pull the E: USB cable after 30 minutes, record the measured loss here.
