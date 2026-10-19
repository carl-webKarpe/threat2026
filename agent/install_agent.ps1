<#
.SYNOPSIS
    Installs the MalDetect agent on this PC and starts it automatically, hidden, whenever someone logs in.

.DESCRIPTION
    Run in PowerShell **as Administrator**, from the folder that contains MalDetectAgent.exe
    (built with build_exe.bat) or maldetect_agent.py (needs Python on this PC):

        powershell -ExecutionPolicy Bypass -File .\install_agent.ps1 -ServerUrl http://192.168.1.87/threat2026 -Token mdt_...

    Running it again updates the agent and its settings (for example a new token or server address).
    To remove the agent, run uninstall_agent.ps1.

.PARAMETER ServerUrl
    Address of the MalDetect server, for example http://192.168.1.87/threat2026 (or https://... with -CaFile).
.PARAMETER Token
    The device token from Admin > Devices (starts with mdt_).
.PARAMETER CaFile
    Optional. The MalDetect CA certificate for HTTPS (maldetect-ca.crt, made by tools\setup_https.ps1).
    When the server URL starts with https:// and maldetect-ca.crt is next to this script, it is used automatically.
.PARAMETER InstallDir
    Where to install. Default: C:\MalDetectAgent
#>
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$CaFile = '',
    [string]$InstallDir = 'C:\MalDetectAgent'
)

$ErrorActionPreference = 'Stop'
$TaskName = 'MalDetect Agent'
$SourceDir = $PSScriptRoot

function Write-Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }

# --- Checks -------------------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw 'Please run PowerShell as Administrator (right-click PowerShell > Run as administrator), then run this script again.'
}
if ($Token -notmatch '^mdt_[0-9a-f]{64}$') {
    throw 'The token does not look right. Copy the full token from Admin > Devices (it starts with mdt_ and has 68 characters).'
}
$ServerUrl = $ServerUrl.TrimEnd('/')
if ($ServerUrl -notmatch '^https?://') {
    throw 'ServerUrl must start with http:// or https://, for example http://192.168.1.87/threat2026'
}

if (-not $CaFile -and $ServerUrl -like 'https://*' -and (Test-Path (Join-Path $SourceDir 'maldetect-ca.crt'))) {
    $CaFile = Join-Path $SourceDir 'maldetect-ca.crt'
}

$exe = Join-Path $SourceDir 'MalDetectAgent.exe'
$script = Join-Path $SourceDir 'maldetect_agent.py'
if (Test-Path $exe) {
    $mode = 'exe'
} elseif (Test-Path $script) {
    $mode = 'python'
    $pythonw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $pythonw) {
        throw 'MalDetectAgent.exe was not found next to this script, and Python (pythonw.exe) is not installed. Build the .exe with build_exe.bat, or install Python with "Add python.exe to PATH".'
    }
} else {
    throw "Neither MalDetectAgent.exe nor maldetect_agent.py is in $SourceDir. Run this script from the agent folder."
}

# --- Stop a running copy so its files can be replaced ----------------------------------------------
Write-Step 'Stopping the agent if it is already running'
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
Get-Process -Name 'MalDetectAgent' -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name = 'pythonw.exe' OR Name = 'python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*maldetect_agent.py*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1

# --- Copy files ---------------------------------------------------------------------------------
Write-Step "Copying the agent to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$sameFolder = (Resolve-Path $SourceDir).Path.TrimEnd('\') -ieq (Resolve-Path $InstallDir).Path.TrimEnd('\')
if (-not $sameFolder) {
    if ($mode -eq 'exe') { Copy-Item $exe $InstallDir -Force } else { Copy-Item $script $InstallDir -Force }
    foreach ($extra in 'config.example.json', 'uninstall_agent.ps1', 'change_server.ps1') {
        if (Test-Path (Join-Path $SourceDir $extra)) { Copy-Item (Join-Path $SourceDir $extra) $InstallDir -Force }
    }
}
if ($CaFile) {
    if (-not (Test-Path $CaFile)) { throw "Certificate file not found: $CaFile" }
    $caTarget = Join-Path $InstallDir 'maldetect-ca.crt'
    if ((Resolve-Path $CaFile).Path -ine $caTarget) { Copy-Item $CaFile $caTarget -Force }
}

# --- config.json (keeps other settings when it already exists) -----------------------------------
Write-Step 'Writing config.json'
$configPath = Join-Path $InstallDir 'config.json'
$templatePath = Join-Path $InstallDir 'config.example.json'
if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
} elseif (Test-Path $templatePath) {
    $config = Get-Content $templatePath -Raw | ConvertFrom-Json
} else {
    $config = New-Object PSObject
}
$settings = @{ server_url = $ServerUrl; device_token = $Token }
if ($CaFile) { $settings['ca_file'] = 'maldetect-ca.crt' }
foreach ($key in $settings.Keys) {
    if ($config.PSObject.Properties[$key]) { $config.$key = $settings[$key] }
    else { $config | Add-Member -NotePropertyName $key -NotePropertyValue $settings[$key] }
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding UTF8

# Every user who logs in runs the agent, so normal users must be able to write its state and log files.
& icacls.exe $InstallDir /grant '*S-1-5-32-545:(OI)(CI)M' /T /Q | Out-Null

# --- Check that the server can be reached ------------------------------------------------------
Write-Step "Checking the connection to $ServerUrl"
try {
    Invoke-WebRequest -Uri "$ServerUrl/loginform.php" -UseBasicParsing -TimeoutSec 10 | Out-Null
    Write-Host '    The server is reachable.' -ForegroundColor Green
} catch {
    Write-Host "    Could not open $ServerUrl/loginform.php from this PC: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host '    The agent is installed anyway and keeps retrying. Check the server IP, the firewall rule and that both PCs are on the same network.' -ForegroundColor Yellow
    if ($ServerUrl -like 'https://*') {
        Write-Host '    (With your own HTTPS certificate this check can fail even though the agent works; check the Devices page.)' -ForegroundColor Yellow
    }
}

# --- Start at every login, hidden -------------------------------------------------------------
Write-Step "Creating the scheduled task '$TaskName' (starts at every login)"
if ($mode -eq 'exe') {
    $action = New-ScheduledTaskAction -Execute (Join-Path $InstallDir 'MalDetectAgent.exe') -WorkingDirectory $InstallDir
} else {
    $action = New-ScheduledTaskAction -Execute $pythonw -Argument ('"' + (Join-Path $InstallDir 'maldetect_agent.py') + '"') -WorkingDirectory $InstallDir
}
$trigger = New-ScheduledTaskTrigger -AtLogOn
# Runs as whoever logs in (group BUILTIN\Users), so it watches that person's Downloads folder.
$usersGroup = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value
$principal = New-ScheduledTaskPrincipal -GroupId $usersGroup -RunLevel Limited
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $taskSettings `
    -Description 'Reports new downloads to the MalDetect server.' -Force | Out-Null

Write-Step 'Starting the agent now'
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 5

$logPath = Join-Path $InstallDir 'agent.log'
Write-Host ''
Write-Host 'MalDetect agent installed.' -ForegroundColor Green
Write-Host "  Folder:   $InstallDir"
Write-Host "  Server:   $ServerUrl"
Write-Host "  Starts:   automatically and hidden, every time someone logs in to this PC"
Write-Host "  Log file: $logPath"
if (Test-Path $logPath) {
    Write-Host ''
    Write-Host 'Last lines of the log:'
    Get-Content $logPath -Tail 5 | ForEach-Object { Write-Host "  $_" }
}
Write-Host ''
Write-Host 'Check the Devices page on the server: this PC should show Online within a few seconds.'
Write-Host 'If it does not, sign out of Windows and sign in again (the agent starts at login), then check the log file.'
