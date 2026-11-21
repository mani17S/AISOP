<#
.SYNOPSIS
    Start (or stop) the AISOP local TLS reverse proxy beside the running demo stack. Lab use, localhost only, no billing.
.DESCRIPTION
    - Creates a self-signed certificate for localhost and 127.0.0.1 OUTSIDE the repository (D:\AISOP-Local\tls) if none exists (valid 30 days).
    - Runs the official nginx image as container aisop-proxy: read-only filesystem, all capabilities dropped except CHOWN, SETUID and SETGID, which the worker switch
      needs, no-new-privileges, bound to 127.0.0.1 only, config and certificate mounted read-only, built frontend (frontend\dist) mounted read-only.
    - Leaves the existing stack (backend :8010, frontend dev server :3010, database) untouched: if the proxy fails the demo keeps working.
.PARAMETER Port   Host port for HTTPS (default 8443).
.PARAMETER Down   Stop and remove the proxy container.
.EXAMPLE
    pwsh -File scripts\proxy_up.ps1            # start
    pwsh -File scripts\proxy_up.ps1 -Down      # stop
#>
[CmdletBinding()]
param([int]$Port = 8443, [switch]$Down)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:MSYS_NO_PATHCONV = "1"
$root = Split-Path -Parent $PSScriptRoot
$tls = "D:\AISOP-Local\tls"
$name = "aisop-proxy"

if ($Down) { docker rm -f $name 2>$null | Out-Null; "proxy stopped"; return }
if (-not (Test-Path (Join-Path $root "frontend\dist\index.html"))) { throw "frontend\dist is missing; run 'npm run build' in frontend first." }

New-Item -ItemType Directory -Force $tls | Out-Null
if (-not (Test-Path "$tls\local.crt")) {
    $openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
    if (-not $openssl) { throw "openssl not found (Git for Windows ships one)." }
    & $openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tls\local.key" -out "$tls\local.crt" -days 30 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>&1 | Out-Null
    "certificate created (self-signed, 30 days): $tls\local.crt"
}

docker rm -f $name 2>$null | Out-Null
docker run -d --name $name --restart unless-stopped `
    --read-only --tmpfs /tmp --security-opt no-new-privileges `
    --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID `
    --add-host host.docker.internal:host-gateway `
    -p "127.0.0.1:${Port}:8443" `
    -v "$root\deploy\nginx\nginx.local.conf:/etc/nginx/nginx.conf:ro" `
    -v "$tls\local.crt:/etc/nginx/tls/local.crt:ro" `
    -v "$tls\local.key:/etc/nginx/tls/local.key:ro" `
    -v "$root\frontend\dist:/usr/share/nginx/html:ro" `
    nginx:alpine | Out-Null
Start-Sleep 3
$state = docker inspect $name --format '{{.State.Status}}'
"proxy container: $state; https://127.0.0.1:$Port (self-signed: trust $tls\local.crt or use --cacert)"
if ($state -ne "running") { docker logs $name 2>&1 | Select-Object -Last 8; exit 1 }
