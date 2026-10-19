<#
.SYNOPSIS
    Shows the MalDetect server's current IP address(es) and checks what the monitored PCs need to reach it.

.DESCRIPTION
    Run on the server PC (Administrator is not required, but some checks are more complete with it):

        cd C:\xampp1\htdocs\threat2026
        powershell -ExecutionPolicy Bypass -File .\tools\check_network.ps1

    Run it every time the server joins a different network (other Wi-Fi, LAN cable, hotspot).
#>
param([string]$ProjectPath = '/threat2026')

function Write-Ok([string]$Text) { Write-Host "  [OK]   $Text" -ForegroundColor Green }
function Write-Bad([string]$Text) { Write-Host "  [FIX]  $Text" -ForegroundColor Yellow }

Write-Host ''
Write-Host 'MalDetect network check' -ForegroundColor Cyan
Write-Host '======================='

# Connected adapters with an IPv4 address and a gateway (a real network, not virtual ones).
$adapters = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object {
    $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway
})
# Windows Mobile Hotspot shares a network without a gateway on 192.168.137.1.
$hotspot = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq '192.168.137.1' })

if (-not $adapters -and -not $hotspot) {
    Write-Bad 'This PC is not connected to a network. Connect Wi-Fi or the LAN cable, then run this again.'
    exit 1
}

$urls = @()
foreach ($adapter in $adapters) {
    $ip = $adapter.IPv4Address[0].IPAddress
    $profile = Get-NetConnectionProfile -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host "Connection: $($adapter.InterfaceAlias)  ($($adapter.NetAdapter.InterfaceDescription))"
    Write-Host "  Server IP:  $ip" -ForegroundColor White
    if ($profile) {
        if ($profile.NetworkCategory -eq 'Public') {
            Write-Bad "Network '$($profile.Name)' is Public. Settings > Network & internet > $($adapter.InterfaceAlias) > set to Private (or allow the firewall rule on Public)."
        } else {
            Write-Ok "Network '$($profile.Name)' is $($profile.NetworkCategory)."
        }
    }
    $urls += $ip
}
foreach ($address in $hotspot) {
    Write-Host ''
    Write-Host "Connection: Windows Mobile Hotspot ($($address.InterfaceAlias))"
    Write-Host '  Server IP:  192.168.137.1' -ForegroundColor White
    Write-Bad 'Hotspot networks are often Public: allow the firewall rule on all profiles (see NETWORK-GUIDE.md).'
    $urls += '192.168.137.1'
}

Write-Host ''
Write-Host 'Firewall'
foreach ($rule in 'MalDetect Apache', 'MalDetect Apache HTTPS') {
    $found = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    if ($found) { Write-Ok "Rule '$rule' exists (profiles: $($found.Profile))." }
    elseif ($rule -eq 'MalDetect Apache') { Write-Bad "Rule '$rule' is missing. See NETWORK-GUIDE.md, Step 3." }
}

Write-Host ''
Write-Host 'Apache'
foreach ($port in 80, 443) {
    $listening = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($listening) { Write-Ok "Listening on port $port." }
    elseif ($port -eq 80) { Write-Bad 'Nothing listens on port 80. Start Apache in the XAMPP Control Panel.' }
}

Write-Host ''
Write-Host 'Give the monitored PCs this address' -ForegroundColor Cyan
foreach ($ip in ($urls | Select-Object -Unique)) {
    Write-Host "  http://$ip$ProjectPath   (https://$ip$ProjectPath if HTTPS is set up)" -ForegroundColor White
    Write-Host '  On each PC with the installed agent (PowerShell as Administrator):'
    Write-Host "    powershell -ExecutionPolicy Bypass -File C:\MalDetectAgent\change_server.ps1 -ServerUrl http://$ip$ProjectPath"
}
Write-Host ''
Write-Host 'Test from a monitored PC: open the address + /login.php in its browser. If the login page opens, the agent can connect.'
