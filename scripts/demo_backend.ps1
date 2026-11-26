<#
.SYNOPSIS
  Supervisor for the demo backend: runs it, restarts it if it exits, and records every exit with a time and exit code.

.DESCRIPTION
  Why it exists: on 2026-11-20 the demo backend on :8010 stopped without a traceback, a Windows error report or a memory-exhaustion
  event (see docs/11_Deployment/Demo_Runbook.md). This wrapper makes a repeat visible (exit code and time in the supervisor log) and
  recovers from it within seconds. Start it with scripts/demo_check.ps1 -Start, which launches it detached from the calling shell.

  It never resets the database and never changes tokens. Database password: the file written by scripts/demo_up.ps1
  (aisop_app_db_password_DO_NOT_COMMIT.txt in the log folder). Nothing secret is printed or logged.
  Stops after 5 exits within 60 seconds (a crash loop) and says so in the log.
#>
param(
  [int]$Port = 8010,
  [string]$Db = "aisop_demo",
  [string]$Model = "qwen2.5:1.5b",
  [string]$LogDir = "D:\AISOP-Backups\AISOP_Dev_Logs_20261120"
)
$ErrorActionPreference = "Stop"
if (-not $LogDir.StartsWith("D:\")) { throw "LogDir must be on D:" }
if ($Db -in @("aisop_dev","aisop","aisop_test","postgres")) { throw "Refusing protected database $Db" }
$root = "D:\AISOP"; $py = "$root\.venv\Scripts\python.exe"
$sup = "$LogDir\supervisor_$Port.log"
$pidFile = "$LogDir\supervisor_$Port.pid"
Set-Content $pidFile $PID
function Log($m) { Add-Content $sup ("{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $m) }

$pw = (Get-Content "$LogDir\aisop_app_db_password_DO_NOT_COMMIT.txt" -Raw).Trim()
$env:DATABASE_URL = "postgresql+psycopg://aisop_app:$pw@127.0.0.1:5433/$Db"
$env:API_AUTH_ENABLED = "true"; $env:API_AUTH_ALLOW_LEGACY_KEYS = "false"; $env:ENVIRONMENT = "development"
$env:ATTACK_REFERENCE_PATH = "D:\AISOP-Reference-Data\MITRE-ATT&CK\Enterprise\v20.1\enterprise-attack-20.1.json"
$env:LLM_ENABLED = "true"; $env:OLLAMA_MODEL = $Model
# Demo AI settings (measured 2026-11-20, day4d_ai_latency_measurement.json): keep the model resident between runs, give one hard
# deadline per model call, and do not retry a slow call (a retry would multiply the wait). The deterministic result never depends on this.
$env:OLLAMA_KEEP_ALIVE = "30m"; $env:OLLAMA_TIMEOUT_SECONDS = "60"; $env:OLLAMA_MAX_RETRIES = "1"
# One worker process runs the deterministic investigation analysis so the server stays responsive during a large investigation (ADR-018, approved 2026-11-26;
# benchmark: docs/05_Backend/Investigation_Responsiveness_Profiling_2026-11-25.md section 13). Costs about 75 MB more memory and 2 to 3 s at start-up.
# Set to "0" to return to the thread behaviour. The AI explanation path never uses the worker.
$env:ANALYSIS_WORKER_PROCESSES = "1"
# Shorter garbage-collection pauses: freeze the long-lived start-up objects once (record section 22). Affects pause times only; set "false" to switch off.
$env:GC_FREEZE_AT_STARTUP = "true"
$env:CORS_ORIGINS = '["http://localhost:3010","http://127.0.0.1:3010"]'; $env:AISOP_PORT = "$Port"

$starts = New-Object System.Collections.Generic.List[datetime]
Log "supervisor started (pid $PID), port $Port, database $Db"
while ($true) {
  $now = Get-Date
  $starts.Add($now) | Out-Null
  $recent = @($starts | Where-Object { ($now - $_).TotalSeconds -le 60 })
  if ($recent.Count -gt 5) { Log "crash loop: more than 5 starts in 60 s, supervisor stopping"; break }
  $stamp = $now.ToString("HHmmss")
  $p = Start-Process -FilePath $py -ArgumentList "backend\run_local.py" -WorkingDirectory $root -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput "$LogDir\backend${Port}_$stamp.out.log" -RedirectStandardError "$LogDir\backend${Port}_$stamp.err.log"
  Log "backend started, pid $($p.Id), logs backend${Port}_$stamp.*.log"
  $p.WaitForExit()
  Log "backend exited, pid $($p.Id), exit code $($p.ExitCode)"
  Start-Sleep -Seconds 3
}
Remove-Item $pidFile -ErrorAction SilentlyContinue
