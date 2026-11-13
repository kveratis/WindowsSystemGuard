# Spike: can a logman counter collector set survive a USB pull with <= 15 s loss?
# Usage: logman-spike.ps1 -Start | -Stop | -Remove   (run elevated)
param([switch]$Start, [switch]$Stop, [switch]$Remove)

$ErrorActionPreference = 'Stop'
$Name = 'wsg-spike'
$Dir = 'E:\wsg-spike'

if (-not ($Start -or $Stop -or $Remove)) { throw 'Specify one of -Start, -Stop, -Remove.' }

if ($Start) {
    if (-not (Test-Path 'E:\')) { throw 'E: drive not found. Connect the USB drive and retry.' }
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $counters = @(
        '\Processor(_Total)\% Processor Time',
        '\Memory\Available MBytes',
        '\Memory\Pool Nonpaged Bytes',
        '\PhysicalDisk(*)\Avg. Disk sec/Read',
        '\PhysicalDisk(*)\Avg. Disk sec/Write',
        '\PhysicalDisk(*)\Current Disk Queue Length',
        '\Network Interface(*)\Bytes Total/sec'
    )
    logman create counter $Name -si 00:00:05 -f bincirc -max 256 -o "$Dir\$Name" -c $counters
    if ($LASTEXITCODE) { throw "logman create failed ($LASTEXITCODE)" }
    logman start $Name
    if ($LASTEXITCODE) { throw "logman start failed ($LASTEXITCODE)" }
    Write-Host "Started $Name. Pull the E: cable after 30 minutes and note the clock time."
}
if ($Stop) { logman stop $Name; if ($LASTEXITCODE) { throw "logman stop failed ($LASTEXITCODE)" } }
if ($Remove) { logman delete $Name; if ($LASTEXITCODE) { throw "logman delete failed ($LASTEXITCODE)" } }
