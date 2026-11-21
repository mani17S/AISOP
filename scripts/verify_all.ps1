<#
.SYNOPSIS
    One command that runs every offline suite and writes a dated log folder plus a summary (the numbers the README quotes come from here).
.DESCRIPTION
    Runs, from the repository root: backend unit, backend offline integration, the PostgreSQL suite (needs the aisop-postgres container),
    and the frontend typecheck, tests and build. Never changes data in the demo database, never calls an external service, and never prints
    a secret. Exit code 0 only if every suite passed.
.PARAMETER LogRoot
    Where the log folder is created (default D:\AISOP-Backups\AISOP_Verify_Logs). Must be on D:.
.PARAMETER SkipPostgres
    Skip the PostgreSQL suite when the container is not running.
.EXAMPLE
    pwsh -File scripts\verify_all.ps1
#>
[CmdletBinding()]
param(
    [string]$LogRoot = "D:\AISOP-Backups\AISOP_Verify_Logs",
    [switch]$SkipPostgres
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
if (-not $LogRoot.ToUpper().StartsWith("D:\")) { throw "LogRoot must be on drive D:." }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$dir = Join-Path $LogRoot (Get-Date -Format "yyyyMMdd_HHmmss")
New-Item -ItemType Directory -Force $dir | Out-Null
$py = Join-Path $root ".venv\Scripts\python.exe"
$summary = @()

function Run-Suite([string]$Name, [scriptblock]$Command, [string]$Log, [string]$Pattern) {
    $path = Join-Path $dir $Log
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $Command *> $path
    $code = $LASTEXITCODE
    $sw.Stop()
    $line = (Select-String -Path $path -Pattern $Pattern -ErrorAction SilentlyContinue | Select-Object -Last 1)
    $text = if ($line) { $line.Line.Trim() } else { "(no result line found)" }
    $script:summary += [pscustomobject]@{ suite = $Name; exit = $code; seconds = [int]$sw.Elapsed.TotalSeconds; result = $text; log = $Log }
    "{0,-34} exit={1} {2}s  {3}" -f $Name, $code, [int]$sw.Elapsed.TotalSeconds, $text
}

Run-Suite "backend unit" { & $py -m pytest backend/tests/unit -q -p no:cacheprovider } "unit.log" "passed|failed|error"
Run-Suite "backend offline integration" { & $py -m pytest backend/tests/integration -m "not postgres and not ollama" -q -p no:cacheprovider } "integration_offline.log" "passed|failed|error"
if (-not $SkipPostgres) {
    $up = (docker inspect aisop-postgres --format '{{.State.Health.Status}}' 2>$null)
    if ($up -eq "healthy") { Run-Suite "PostgreSQL suite" { pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\pg_verify.ps1") -LogDir (Join-Path $dir "pg") } "pg_console.log" "passed|failed|error" }
    else { "PostgreSQL suite: SKIPPED (container not healthy; start it or pass -SkipPostgres)"; $summary += [pscustomobject]@{ suite = "PostgreSQL suite"; exit = 1; seconds = 0; result = "not run: container not healthy"; log = "" } }
}
Push-Location (Join-Path $root "frontend")
Run-Suite "frontend typecheck" { npm run typecheck } "fe_typecheck.log" "error|tsc"
Run-Suite "frontend tests" { npm test } "fe_test.log" "pass [0-9]+"
Run-Suite "frontend build" { npm run build } "fe_build.log" "built in|error"
Pop-Location

$summary | ConvertTo-Json | Set-Content (Join-Path $dir "summary.json") -Encoding UTF8
$bad = @($summary | Where-Object { $_.exit -ne 0 }).Count
"----"
"Logs: $dir"
if ($bad -eq 0) { "ALL SUITES PASSED" } else { "$bad suite(s) FAILED or did not run" }
exit $(if ($bad -eq 0) { 0 } else { 1 })
