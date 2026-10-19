<#
.SYNOPSIS
    Points an installed MalDetect agent to a new server address (for example after the server's IP changed)
    and restarts it. The token is kept.

.DESCRIPTION
    Run on the monitored PC in PowerShell **as Administrator**:

        powershell -ExecutionPolicy Bypass -File C:\MalDetectAgent\change_server.ps1 -ServerUrl http://192.168.1.50/threat2026

    For HTTPS, use https://... and put the new maldetect-ca.crt next to this script or in C:\MalDetectAgent first
    (only needed if the CA itself changed; after an IP change the CA stays the same).
#>
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [string]$InstallDir = 'C:\MalDetectAgent'
)

$ErrorActionPreference = 'Stop'
$TaskName = 'MalDetect Agent'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Please run PowerShell as Administrator, then run this script again.' }

$ServerUrl = $ServerUrl.TrimEnd('/')
if ($ServerUrl -notmatch '^https?://[^/]+/') {
    throw 'ServerUrl must look like http://192.168.1.50/threat2026'
}
$configPath = Join-Path $InstallDir 'config.json'
if (-not (Test-Path $configPath)) {
    throw "No agent found: $configPath does not exist. Install it first with install_agent.ps1."
}

# Update config.json, keeping every other setting (including the token).
$config = Get-Content $configPath -Raw | ConvertFrom-Json
$oldUrl = $config.server_url
$config.server_url = $ServerUrl
if ($ServerUrl -like 'https://*') {
    $caInFolder = Join-Path $InstallDir 'maldetect-ca.crt'
    $caNextToScript = Join-Path $PSScriptRoot 'maldetect-ca.crt'
    if ((Test-Path $caNextToScript) -and ((Resolve-Path $caNextToScript).Path -ine $caInFolder)) {
        Copy-Item $caNextToScript $caInFolder -Force
    }
    if (Test-Path $caInFolder) {
        if ($config.PSObject.Properties['ca_file']) { $config.ca_file = 'maldetect-ca.crt' }
        else { $config | Add-Member -NotePropertyName ca_file -NotePropertyValue 'maldetect-ca.crt' }
    } else {
        Write-Host 'Warning: HTTPS address but no maldetect-ca.crt found; the agent will refuse the server certificate.' -ForegroundColor Yellow
    }
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding UTF8
Write-Host "Server address changed:`n  from $oldUrl`n  to   $ServerUrl"

# Check the new address from this PC.
try {
    Invoke-WebRequest -Uri "$ServerUrl/loginform.php" -UseBasicParsing -TimeoutSec 10 | Out-Null
    Write-Host 'The server is reachable at the new address.' -ForegroundColor Green
} catch {
    Write-Host "Could not open $ServerUrl/loginform.php: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host 'Check the IP (ipconfig on the server), that both PCs are on the same network, and the server firewall.' -ForegroundColor Yellow
}

# Restart the agent so it uses the new address.
Get-Process -Name 'MalDetectAgent' -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name = 'pythonw.exe' OR Name = 'python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*maldetect_agent.py*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Start-ScheduledTask -TaskName $TaskName
    Write-Host 'Agent restarted. Check the Devices page on the server: this PC should show Online within a few seconds.' -ForegroundColor Green
} else {
    Write-Host 'The agent is not installed as a task. Start it again by hand: python maldetect_agent.py' -ForegroundColor Yellow
}
