<#
.SYNOPSIS
  Measures the recorder's own CPU and memory cost while it records.

.DESCRIPTION
  Starts wsg-recorder in --console mode on a throwaway data directory, samples it and its helper
  processes every 5 seconds, then stops it. CPU is the share of the whole machine (all logical
  processors) used by the recorder and its helpers together. The first 60 seconds are excluded
  from the average when -Minutes allows it, because new helper executables can be held by
  antivirus for about 30 seconds each on first launch.

  Prints PASS or FAIL lines and exits 1 if any limit is exceeded.

.PARAMETER Minutes
  How long to measure (default 10).
.PARAMETER Exe
  Path to wsg-recorder.exe (default: target\release, then target\debug).
.PARAMETER MaxCpuPercent
  Average CPU limit (default 1).
.PARAMETER MaxWorkingSetMB
  Largest combined working set limit (default 100).
#>
param(
    [double]$Minutes = 10,
    [string]$Exe,
    [double]$MaxCpuPercent = 1.0,
    [double]$MaxWorkingSetMB = 100
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Exe) {
    $Exe = @("$root\target\release\wsg-recorder.exe", "$root\target\debug\wsg-recorder.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Exe -or -not (Test-Path $Exe)) { throw "wsg-recorder.exe not found; build it or pass -Exe" }

$data = Join-Path ([IO.Path]::GetTempPath()) ("wsg-overhead-" + [guid]::NewGuid().ToString('N'))
$cores = [Environment]::ProcessorCount
$rec = Start-Process -PassThru -WindowStyle Hidden $Exe -ArgumentList '--console', '--data-dir', $data

function Get-Tree([int]$RootPid) {
    $kids = Get-CimInstance Win32_Process -Filter "ParentProcessId=$RootPid" | Select-Object -ExpandProperty ProcessId
    @($RootPid) + $kids | ForEach-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }
}

try {
    $warmup = if ($Minutes -gt 2) { 60 } else { 0 }
    $end = (Get-Date).AddMinutes($Minutes)
    $start = Get-Date
    $samples = @()
    $prevCpu = $null; $prevAt = $null
    while ((Get-Date) -lt $end) {
        Start-Sleep -Seconds 5
        if ($rec.HasExited) { throw "recorder exited early with code $($rec.ExitCode)" }
        $tree = Get-Tree $rec.Id
        $cpu = ($tree | ForEach-Object { $_.TotalProcessorTime.TotalSeconds } | Measure-Object -Sum).Sum
        $ws = ($tree | ForEach-Object { $_.WorkingSet64 } | Measure-Object -Sum).Sum / 1MB
        $now = Get-Date
        if ($prevCpu -ne $null -and ((($now - $start).TotalSeconds) -gt $warmup)) {
            $pct = 100 * ($cpu - $prevCpu) / (($now - $prevAt).TotalSeconds) / $cores
            $samples += [pscustomobject]@{ Cpu = [math]::Max(0, $pct); Ws = $ws }
        }
        $prevCpu = $cpu; $prevAt = $now
    }
    if (-not $samples) { throw "no samples collected; use -Minutes greater than 1" }
    $avg = ($samples | Measure-Object Cpu -Average).Average
    $maxWs = ($samples | Measure-Object Ws -Maximum).Maximum
    $failed = $false
    foreach ($r in @(
        @{ Name = 'average CPU'; Value = $avg; Limit = $MaxCpuPercent; Unit = '%' },
        @{ Name = 'peak working set'; Value = $maxWs; Limit = $MaxWorkingSetMB; Unit = ' MB' })) {
        $ok = $r.Value -lt $r.Limit
        if (-not $ok) { $failed = $true }
        '{0}: {1} {2:N2}{3} (limit {4}{3}, {5} samples)' -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $r.Name, $r.Value, $r.Unit, $r.Limit, $samples.Count
    }
    if ($failed) { exit 1 }
}
finally {
    if ($rec -and -not $rec.HasExited) { Stop-Process -Id $rec.Id -Force }
    Start-Sleep -Milliseconds 500
    Remove-Item $data -Recurse -Force -ErrorAction SilentlyContinue
}
