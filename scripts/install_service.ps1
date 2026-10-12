<#
SentinelAI - install the engine as a self-restarting Windows service and lock down its files.

What it does (Administrator PowerShell, from the repo root):
  1. Generates the trusted integrity manifest in %PROGRAMDATA%\SentinelAI (HMAC key + manifest + API token).
  2. Hardens ACLs: install folder -> SYSTEM/Administrators full, Users read+execute only;
     data folder -> SYSTEM/Administrators only, plus read access to api_token for the desktop user.
  3. Registers service "SentinelAI" with NSSM running soar\supervisor.py (which restarts the backend),
     and sets Windows service recovery to restart on failure.

Requires NSSM (https://nssm.cc) on PATH or -Nssm C:\path\nssm.exe.

  .\scripts\install_service.ps1
  .\scripts\install_service.ps1 -Uninstall
  .\scripts\install_service.ps1 -SkipAcl          # keep folder permissions (dev machines)

Notes:
  * After intentionally updating models / policies / code, re-run:
      $env:SENTINEL_DATA_DIR="$env:ProgramData\SentinelAI"; .venv\Scripts\python -m config.integrity generate
  * The service runs as LocalSystem. The browser credential (file) sensor resolves the profile of the account
    it runs under, so on a service install keep the desktop app (user context) for that sensor.
  * Kernel-level self-protection (Protected Process Light, ELAM drivers, minifilter callbacks) needs a signed
    driver and Microsoft-issued certificates and is out of scope; an Administrator can still stop the service.
#>
#Requires -RunAsAdministrator
param(
    [string]$Nssm = "nssm.exe",
    [string]$ServiceName = "SentinelAI",
    [switch]$Uninstall,
    [switch]$SkipAcl
)
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$DataDir = Join-Path $env:ProgramData "SentinelAI"
$LogDir = Join-Path $DataDir "logs"
$DesktopUser = "$env:USERDOMAIN\$env:USERNAME"

if (-not (Get-Command $Nssm -ErrorAction SilentlyContinue)) {
    Write-Error "NSSM not found. Download it from https://nssm.cc and pass -Nssm C:\path\to\nssm.exe"
}

if ($Uninstall) {
    & $Nssm stop $ServiceName 2>$null | Out-Null
    & $Nssm remove $ServiceName confirm
    Write-Host "Service removed. Folder permissions were left as they are."
    return
}

if (-not (Test-Path $Python)) { Write-Error "Python venv not found at $Python" }
New-Item -ItemType Directory -Force -Path $DataDir, $LogDir | Out-Null

Write-Host "[1/4] Generating trusted integrity manifest in $DataDir"
$env:SENTINEL_DATA_DIR = $DataDir
Push-Location $Root
try { & $Python -m config.integrity generate } finally { Pop-Location }

if (-not $SkipAcl) {
    Write-Host "[2/4] Hardening folder permissions"
    # Install folder: only SYSTEM / Administrators can change code, models and rules.
    icacls $Root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /T /C /Q | Out-Null
    # Data folder: secrets readable by SYSTEM / Administrators; the desktop user may read the API token only.
    icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
    $env:SENTINEL_DATA_DIR = $DataDir
    & $Python -c "import sys; sys.path.insert(0, r'$Root'); from config import security; security.api_token()"
    icacls (Join-Path $DataDir "api_token") /grant "${DesktopUser}:R" /C /Q | Out-Null
} else {
    Write-Host "[2/4] Skipping ACL hardening (-SkipAcl)"
}

Write-Host "[3/4] Registering service $ServiceName"
& $Nssm stop $ServiceName 2>$null | Out-Null
& $Nssm remove $ServiceName confirm 2>$null | Out-Null
& $Nssm install $ServiceName $Python "supervisor.py"
& $Nssm set $ServiceName AppDirectory (Join-Path $Root "soar")
& $Nssm set $ServiceName AppEnvironmentExtra "SENTINEL_DATA_DIR=$DataDir" "PYTHONUNBUFFERED=1"
& $Nssm set $ServiceName DisplayName "SentinelAI Protection Engine"
& $Nssm set $ServiceName Description "SentinelAI HIDS/NIDS SOAR engine (supervised, self-restarting)"
& $Nssm set $ServiceName Start SERVICE_AUTO_START
& $Nssm set $ServiceName AppExit Default Restart
& $Nssm set $ServiceName AppRestartDelay 5000
& $Nssm set $ServiceName AppStdout (Join-Path $LogDir "service.log")
& $Nssm set $ServiceName AppStderr (Join-Path $LogDir "service.log")
& $Nssm set $ServiceName AppRotateFiles 1
& $Nssm set $ServiceName AppRotateBytes 10485760
# Windows service recovery as a second layer: restart after 5 s, 5 s, then 30 s; reset the counter daily.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null

Write-Host "[4/4] Starting service"
& $Nssm start $ServiceName
Write-Host ""
Write-Host "Done. Engine: http://127.0.0.1:8000  Token: $DataDir\api_token"
Write-Host "Check integrity any time:  `$env:SENTINEL_DATA_DIR='$DataDir'; .venv\Scripts\python -m config.integrity verify"
