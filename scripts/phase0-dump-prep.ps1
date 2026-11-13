# Phase 0: verify (and with -Apply, set) crash-dump prerequisites. Read-only without -Apply.
# Never touches the pagefile; it only reports what to change.
param([switch]$Apply)

$cc  = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$kbd = 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters'
$ps2 = 'HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters'
$script:fail = 0

function Result($ok, $name, $detail) {
    if ($ok) { "PASS  $name  $detail" } else { "FAIL  $name  $detail"; $script:fail++ }
}
function RegVal($path, $name) {
    try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null }
}
function Check($name, $block) {
    try { & $block } catch { Result $false $name "could not check: $($_.Exception.Message)" }
}

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Apply -and -not $elevated) { Write-Host 'FAIL  -Apply needs an elevated shell'; exit 1 }
if (-not $elevated) { Write-Host 'NOTE  shell not elevated; some reads may fail' }

if ($Apply) {
    if ((RegVal $cc 'CrashDumpEnabled') -notin 1, 2) { Set-ItemProperty $cc CrashDumpEnabled 1 -Type DWord }
    Set-ItemProperty $cc NMICrashDump 1 -Type DWord
    New-Item $kbd -Force | Out-Null
    Set-ItemProperty $kbd CrashOnCtrlScroll 1 -Type DWord
    New-Item $ps2 -Force | Out-Null
    Set-ItemProperty $ps2 CrashOnCtrlScroll 1 -Type DWord
    Write-Host 'APPLIED registry values. REBOOT REQUIRED. Pagefile is never changed by this script.'
}

$dump = RegVal $cc 'CrashDumpEnabled'
Check 'CrashDumpEnabled' {
    Result ($dump -in 1, 2) 'CrashDumpEnabled' "= $dump (need 1 complete or 2 kernel); set $cc\CrashDumpEnabled"
}

Check 'pagefile' {
    $sysDrive = $env:SystemDrive
    $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1GB)
    $needGB = if ($dump -eq 2) { 16 } else { $ramGB }   # RAM = 64 GB on the target box
    $pf = @(Get-CimInstance Win32_PageFileSetting -ErrorAction Stop | Where-Object { $_.Name -like "$sysDrive*" })
    if (-not $pf) {
        Result $false 'pagefile' "no explicit pagefile on $sysDrive (automatic or absent); set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PagingFiles to '$sysDrive\pagefile.sys $($needGB*1024) $($needGB*1024)'"
    } else {
        $maxMB = ($pf | Measure-Object MaximumSize -Maximum).Maximum
        Result ($maxMB -ge $needGB * 1024) 'pagefile' "max ${maxMB} MB on $sysDrive (need >= $($needGB*1024) MB); fix Memory Management\PagingFiles"
    }
    $freeGB = [math]::Round((Get-PSDrive ($sysDrive.TrimEnd(':')) -ErrorAction Stop).Free / 1GB, 1)
    Result ($freeGB -ge $needGB) 'free-space' "$freeGB GB free on $sysDrive (need >= $needGB GB)"
}

Check 'kbdhid' {
    Result ((RegVal $kbd 'CrashOnCtrlScroll') -eq 1) 'kbdhid CrashOnCtrlScroll' "= $(RegVal $kbd 'CrashOnCtrlScroll') (need 1); set $kbd\CrashOnCtrlScroll"
}

Check 'i8042prt' {
    $hasPs2 = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object { $_.Service -eq 'i8042prt' -and $_.PNPClass -eq 'Keyboard' -and $_.Present }).Count -gt 0
    if ($hasPs2) {
        Result ((RegVal $ps2 'CrashOnCtrlScroll') -eq 1) 'i8042prt CrashOnCtrlScroll' "= $(RegVal $ps2 'CrashOnCtrlScroll') (need 1); set $ps2\CrashOnCtrlScroll"
    } else { Result $true 'i8042prt CrashOnCtrlScroll' 'no PS/2 keyboard present, skipped' }
}

Check 'NMICrashDump' {
    Result ((RegVal $cc 'NMICrashDump') -eq 1) 'NMICrashDump' "= $(RegVal $cc 'NMICrashDump') (need 1); set $cc\NMICrashDump"
}

exit ([int]($script:fail -gt 0))
