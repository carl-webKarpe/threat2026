<#
.SYNOPSIS
    Turns on HTTPS for MalDetect on the XAMPP server, with a certificate for the server's LAN IP address.

.DESCRIPTION
    Run once on the server PC in PowerShell **as Administrator**:

        cd C:\xampp1\htdocs\threat2026
        powershell -ExecutionPolicy Bypass -File .\tools\setup_https.ps1 -ServerIp 192.168.1.87

    What it does:
      1. Creates a private "MalDetect Local CA" (only the first time; kept in apache\conf\maldetect-ca).
      2. Creates a server certificate for the IP address (and localhost), signed by that CA.
      3. Points XAMPP's Apache (conf\extra\httpd-ssl.conf) at the new certificate. A backup is kept.
      4. Opens TCP port 443 in the Windows Firewall for private networks.
      5. Trusts the CA on this PC, so browsers here show the padlock without a warning.
      6. Copies the CA certificate to agent\maldetect-ca.crt for the agents.
    Then restart Apache in the XAMPP Control Panel.

    Run it again when the server's IP address changes: the CA stays the same, so agents keep working
    (only their server_url needs the new IP).

.PARAMETER ServerIp
    The server's LAN IPv4 address (ipconfig > IPv4 Address), for example 192.168.1.87.
.PARAMETER XamppDir
    The XAMPP folder. Default: the folder three levels above this script (htdocs\threat2026\tools).
#>
param(
    [Parameter(Mandatory = $true)][string]$ServerIp,
    [string]$XamppDir = ''
)

$ErrorActionPreference = 'Stop'
$onWindows = $env:OS -eq 'Windows_NT'
function Write-Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }

if ($ServerIp -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$' -or ($Matches[1..4] | Where-Object { [int]$_ -gt 255 })) {
    throw "ServerIp must be an IPv4 address such as 192.168.1.87 (see ipconfig). Got: $ServerIp"
}
if ($onWindows) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw 'Please run PowerShell as Administrator, then run this script again.' }
}

$projectDir = Split-Path -Parent $PSScriptRoot
if (-not $XamppDir) { $XamppDir = Split-Path -Parent (Split-Path -Parent $projectDir) }
$apacheDir = Join-Path $XamppDir 'apache'
$openssl = Join-Path $apacheDir 'bin\openssl.exe'
$sslConf = Join-Path $apacheDir 'conf\extra\httpd-ssl.conf'
foreach ($required in $openssl, $sslConf) {
    if (-not (Test-Path $required)) { throw "Not found: $required. Use -XamppDir to point to your XAMPP folder (for example C:\xampp1)." }
}
$certDir = Join-Path $apacheDir 'conf\maldetect-ca'
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$caKey = Join-Path $certDir 'maldetect-ca.key'
$caCrt = Join-Path $certDir 'maldetect-ca.crt'
$serverKey = Join-Path $certDir 'maldetect-server.key'
$serverCsr = Join-Path $certDir 'maldetect-server.csr'
$serverCrt = Join-Path $certDir 'maldetect-server.crt'
$reqConf = Join-Path $certDir 'openssl-req.cnf'
$caExt = Join-Path $certDir 'ca.ext'
$serverExt = Join-Path $certDir 'server.ext'

function Invoke-OpenSsl([string[]]$Arguments) {
    $env:OPENSSL_CONF = $reqConf
    & $openssl @Arguments 2>&1 | ForEach-Object { Write-Verbose "$_" }
    if ($LASTEXITCODE -ne 0) { throw "openssl failed: $($Arguments -join ' ')" }
}

# Minimal OpenSSL settings (XAMPP's default openssl.cnf path often does not exist).
Set-Content -Path $reqConf -Encoding ASCII -Value @(
    '[req]', 'distinguished_name = dn', 'prompt = no', '[dn]', 'CN = MalDetect'
)

# --- 1. The CA (created once, reused afterwards) -----------------------------------------------------
if ((Test-Path $caKey) -and (Test-Path $caCrt)) {
    Write-Step "Using the existing MalDetect Local CA in $certDir"
} else {
    Write-Step 'Creating the MalDetect Local CA'
    Set-Content -Path $caExt -Encoding ASCII -Value @(
        'basicConstraints = critical, CA:TRUE, pathlen:0',
        'keyUsage = critical, keyCertSign, cRLSign',
        'subjectKeyIdentifier = hash'
    )
    Invoke-OpenSsl @('genrsa', '-out', $caKey, '2048')
    Invoke-OpenSsl @('req', '-new', '-key', $caKey, '-subj', '/CN=MalDetect Local CA/O=MalDetect', '-out', "$caCrt.csr")
    Invoke-OpenSsl @('x509', '-req', '-in', "$caCrt.csr", '-signkey', $caKey, '-days', '3650', '-sha256', '-extfile', $caExt, '-out', $caCrt)
    Remove-Item "$caCrt.csr" -Force
}

# --- 2. The server certificate for this IP -------------------------------------------------------
Write-Step "Creating the server certificate for $ServerIp"
Set-Content -Path $serverExt -Encoding ASCII -Value @(
    'basicConstraints = critical, CA:FALSE',
    'keyUsage = critical, digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth',
    'subjectKeyIdentifier = hash',
    'authorityKeyIdentifier = keyid, issuer',
    $(if ($ServerIp -eq '127.0.0.1') { 'subjectAltName = IP:127.0.0.1, DNS:localhost' } else { "subjectAltName = IP:$ServerIp, IP:127.0.0.1, DNS:localhost" })
)
Invoke-OpenSsl @('genrsa', '-out', $serverKey, '2048')
Invoke-OpenSsl @('req', '-new', '-key', $serverKey, '-subj', "/CN=$ServerIp/O=MalDetect", '-out', $serverCsr)
Invoke-OpenSsl @('x509', '-req', '-in', $serverCsr, '-CA', $caCrt, '-CAkey', $caKey, '-CAcreateserial', '-days', '825', '-sha256', '-extfile', $serverExt, '-out', $serverCrt)
Remove-Item $serverCsr -Force

# --- 3. Apache configuration ---------------------------------------------------------------------
Write-Step "Updating $sslConf"
$backup = "$sslConf.maldetect-backup"
if (-not (Test-Path $backup)) { Copy-Item $sslConf $backup }
$apacheCrt = ($serverCrt -replace '\\', '/')
$apacheKey = ($serverKey -replace '\\', '/')
$lines = Get-Content $sslConf
$foundCert = $false
$foundKey = $false
$lines = foreach ($line in $lines) {
    if ($line -match '^\s*SSLCertificateFile\s') { $foundCert = $true; "SSLCertificateFile `"$apacheCrt`"" }
    elseif ($line -match '^\s*SSLCertificateKeyFile\s') { $foundKey = $true; "SSLCertificateKeyFile `"$apacheKey`"" }
    else { $line }
}
if (-not ($foundCert -and $foundKey)) {
    throw "Could not find the SSLCertificateFile / SSLCertificateKeyFile lines in $sslConf. Nothing was changed."
}
Set-Content -Path $sslConf -Value $lines -Encoding ASCII

# --- 4 and 5. Firewall and trust on this PC (Windows only) ---------------------------------------------
if ($onWindows) {
    Write-Step 'Opening port 443 in the Windows Firewall (private networks)'
    if (-not (Get-NetFirewallRule -DisplayName 'MalDetect Apache HTTPS' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'MalDetect Apache HTTPS' -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Private | Out-Null
    }
    Write-Step 'Trusting the MalDetect Local CA on this PC (no browser warning here)'
    Import-Certificate -FilePath $caCrt -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
}

# --- 6. Give the CA certificate to the agents ------------------------------------------------------
$agentCa = Join-Path $projectDir 'agent\maldetect-ca.crt'
Copy-Item $caCrt $agentCa -Force

Write-Host ''
Write-Host 'HTTPS is set up.' -ForegroundColor Green
Write-Host '  Next: in the XAMPP Control Panel, click Stop and then Start next to Apache.'
Write-Host "  Then open https://$ServerIp/threat2026/login.php"
Write-Host "  Agents: use server_url https://$ServerIp/threat2026 and the file $agentCa"
Write-Host "  (install_agent.ps1 picks it up automatically when it is in the same folder)."
Write-Host "  Apache config backup: $backup"
