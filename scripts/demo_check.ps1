<#
.SYNOPSIS
  "Is the demo up?" check. Run it before every rehearsal and before the show. Prints OK or FAIL per item; exit code 1 if any FAIL.

.DESCRIPTION
  Checks: Docker Postgres container healthy, backend health and readiness (database, pgvector, model), the demo analyst token is
  accepted (status code only, never printed), the frontend dev server answers and proxies to the backend, the supervisor is alive.
  -Start   : starts everything that is not already running: the database container, Ollama (with the demo model folder), the frontend dev
             server, and, if the backend is not answering, the supervisor (scripts/demo_backend.ps1) DETACHED from this shell, so closing
             a terminal or a tool session does not stop it, and wait for it. Does not touch the database or the tokens.
  -Stop    : stop the supervisor and its backend (use after the show).
  -WarmUp  : load the language model into memory and keep it there for 30 minutes (run before every rehearsal and before the show;
             the first AI call after a cold start measured about 4 seconds slower, 2026-11-20). Prints the load time.
  -Port / -FrontendPort : default 8010 / 3010.
#>
param([switch]$Start, [switch]$Stop, [switch]$WarmUp, [int]$Port = 8010, [int]$FrontendPort = 3010,
      [string]$LogDir = "D:\AISOP-Backups\AISOP_Dev_Logs_20261120")
$fail = 0
function Item($name, $ok, $detail = "") { if ($ok) { "OK    $name $detail" } else { $script:fail++; "FAIL  $name $detail" } }
function Code($url, $headers = @{}) { try { (Invoke-WebRequest $url -Headers $headers -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 8).StatusCode } catch { 0 } }
$pidFile = "$LogDir\supervisor_$Port.pid"

if ($Stop) {
  if (Test-Path $pidFile) { $sp = [int](Get-Content $pidFile); Stop-Process -Id $sp -Force -ErrorAction SilentlyContinue; Remove-Item $pidFile -ErrorAction SilentlyContinue }
  Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
  "Stopped supervisor and backend on :$Port"; return
}

if ($Start -and (Code "http://127.0.0.1:$Port/api/v1/health") -ne 200) {
  # Win32_Process.Create starts the process outside this shell's job object, so it survives the shell closing.
  $cmd = "pwsh -NoProfile -ExecutionPolicy Bypass -File D:\AISOP\scripts\demo_backend.ps1 -Port $Port -LogDir `"$LogDir`""
  $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd; CurrentDirectory = "D:\AISOP" }
  "Supervisor launch: return code $($r.ReturnValue), pid $($r.ProcessId)"
  for ($i = 0; $i -lt 40; $i++) { Start-Sleep 1; if ((Code "http://127.0.0.1:$Port/api/v1/health") -eq 200) { break } }
}

if ($Start) {
  # Everything the demo needs, each started detached from this shell (Win32_Process.Create) and only if it is not already listening.
  function Listening($p) { [bool](Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue) }
  if (-not (docker inspect aisop-postgres --format '{{.State.Running}}' 2>$null) -or (docker inspect aisop-postgres --format '{{.State.Running}}' 2>$null) -ne 'true') { docker start aisop-postgres 2>&1 | Out-Null; Start-Sleep 8 }
  if (-not (Listening 11434)) {
    # The demo models (qwen2.5:1.5b, nomic-embed-text) live in this folder, not in the default Ollama model folder.
    $ollama = (Get-Command ollama -ErrorAction SilentlyContinue).Source
    $null = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "cmd.exe /c `"set OLLAMA_MODELS=D:\AISOP-External\ollama-models&& `"$ollama`" serve > $LogDir\ollama_serve.log 2>&1`""; CurrentDirectory = "D:\AISOP" }
    for ($i = 0; $i -lt 20 -and -not (Listening 11434); $i++) { Start-Sleep 1 }
  }
  if (-not (Listening $FrontendPort)) {
    $null = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "cmd.exe /c `"cd /d D:\AISOP\frontend && set AISOP_API_PROXY=http://127.0.0.1:$Port&& npm run dev -- --port $FrontendPort > $LogDir\vite$FrontendPort.log 2>&1`""; CurrentDirectory = "D:\AISOP\frontend" }
    for ($i = 0; $i -lt 30 -and -not (Listening $FrontendPort); $i++) { Start-Sleep 1 }
  }
}

$db = (docker inspect aisop-postgres --format '{{.State.Health.Status}}' 2>$null)
Item "postgres container healthy" ($db -eq "healthy") $db
$h = Code "http://127.0.0.1:$Port/api/v1/health"
Item "backend :$Port health" ($h -eq 200) "status $h"
try { $resp = Invoke-WebRequest "http://127.0.0.1:$Port/api/v1/health/ready" -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 20
      $ready = $resp.Content | ConvertFrom-Json
      if ($ready.detail) { $ready = $ready.detail }   # a degraded readiness (HTTP 503) wraps the checks in "detail"
      Item "backend readiness (database, pgvector)" ($ready.checks.database.status -eq "ok" -and $ready.checks.database.pgvector.status -eq "ok") "db=$($ready.checks.database.status) pgvector=$($ready.checks.database.pgvector.version)"
      if ($ready.checks.llm_provider) { Item "language model (optional, AI path only)" ($ready.checks.llm_provider.status -eq "healthy") "model=$($ready.checks.llm_provider.model)" }
} catch { Item "backend readiness" $false "not reachable" }
$tokFile = "$LogDir\demo_tokens_DO_NOT_COMMIT.txt"
if (Test-Path $tokFile) {
  $t = ((Get-Content $tokFile | Where-Object { $_ -like "analyst=*" }) -replace "^analyst=", "")
  $c = Code "http://127.0.0.1:$Port/api/v1/cases" @{ Authorization = "Bearer $t" }
  Item "demo analyst token accepted" ($c -eq 200) "status $c"
  $c2 = Code "http://127.0.0.1:$FrontendPort/api/v1/cases" @{ Authorization = "Bearer $t" }
  Item "frontend :$FrontendPort proxies to the backend" ($c2 -eq 200) "status $c2"
} else { Item "demo token file present" $false $tokFile }
Item "frontend :$FrontendPort answers" ((Code "http://127.0.0.1:$FrontendPort/") -eq 200)
if ($WarmUp) {
  try {
    $m = (Invoke-RestMethod "http://127.0.0.1:$Port/api/v1/health/ready" -TimeoutSec 15).checks.llm_provider.model
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Invoke-RestMethod "http://127.0.0.1:11434/api/generate" -Method Post -ContentType "application/json" -Body (@{ model = $m; prompt = ""; keep_alive = "30m"; options = @{ num_ctx = 8192 } } | ConvertTo-Json) -TimeoutSec 180 | Out-Null
    Item "language model warm ($m, kept 30 min)" $true ("loaded in {0:N1} s" -f $sw.Elapsed.TotalSeconds)
  } catch { Item "language model warm-up" $false "Ollama not reachable on 127.0.0.1:11434" }
}
$sup = if (Test-Path $pidFile) { Get-Process -Id ([int](Get-Content $pidFile)) -ErrorAction SilentlyContinue } else { $null }
Item "supervisor running (restarts the backend if it exits)" ($null -ne $sup) $(if ($sup) { "pid $($sup.Id)" } else { "not running; use -Start" })
if ($fail -gt 0) { "$fail check(s) FAILED. Fix before rehearsing or presenting."; exit 1 } else { "All checks OK." }
