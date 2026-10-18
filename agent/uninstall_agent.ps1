<#
.SYNOPSIS
    Stops and removes the MalDetect agent from this PC.

.DESCRIPTION
    Run in PowerShell as Administrator:

        powershell -ExecutionPolicy Bypass -File C:\MalDetectAgent\uninstall_agent.ps1

    Add -RemoveFiles to also delete C:\MalDetectAgent (settings, token, log).
    The device stays on the server's Devices page; delete it there if it is no longer needed.
#>
param(
    [string]$InstallDir = 'C:\MalDetectAgent',
    [switch]$RemoveFiles
)

$ErrorActionPreference = 'Stop'
$TaskName = 'MalDetect Agent'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw 'Please run PowerShell as Administrator, then run this script again.'
}

# Tell the server the agent is stopping, so the device shows Offline right away.
$configPath = Join-Path $InstallDir 'config.json'
if (Test-Path $configPath) {
    try {
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        $body = @{ stopping = $true } | ConvertTo-Json
        Invoke-RestMethod -Uri ($config.server_url.TrimEnd('/') + '/api/agent/heartbeat.php') -Method Post -Body $body `
            -ContentType 'application/json' -Headers @{ 'X-Device-Token' = $config.device_token } -TimeoutSec 5 | Out-Null
        Write-Host 'Told the server the agent is stopping.'
    } catch {
        Write-Host "Could not reach the server ($($_.Exception.Message)); the device turns Offline within 3 minutes." -ForegroundColor Yellow
    }
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed the scheduled task '$TaskName'."
}
Get-Process -Name 'MalDetectAgent' -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name = 'pythonw.exe' OR Name = 'python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*maldetect_agent.py*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Write-Host 'Stopped the agent.'

if ($RemoveFiles) {
    Start-Sleep -Seconds 1
    # The script itself may live in this folder; Windows still allows deleting it while it runs.
    Remove-Item -Recurse -Force $InstallDir
    Write-Host "Deleted $InstallDir."
}
Write-Host 'MalDetect agent uninstalled.' -ForegroundColor Green
