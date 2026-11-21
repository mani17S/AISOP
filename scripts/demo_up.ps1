<#
.SYNOPSIS
  One-command AISOP demo bring-up on PostgreSQL (local deployment runbook step; owner-authorized 2026-11-20).

.DESCRIPTION
  1. (-Reset) drops and recreates the demo database `aisop_demo` in the approved `aisop-postgres` container (never aisop_dev),
  2. migrates it to Alembic head, 3. provisions the synthetic demo identities (tokens written to a file on D:, not printed),
  4. ingests knowledge_base/ into pgvector (needs Ollama + nomic-embed-text), 5. (re)starts the backend on -Port.
  Frontend (separate terminal):  cd frontend; $env:AISOP_API_PROXY='http://127.0.0.1:<Port>'; npm run dev -- --port 3010
  Passwords: POSTGRES_PASSWORD env var if set, else the documented local-dev default from docker-compose.yml.
#>
param(
  [switch]$Reset,
  [int]$Port = 8010,
  [string]$Db = "aisop_demo",
  [string]$OutDir = "D:\AISOP-Backups\AISOP_Dev_Logs_20261120",
  [string]$Model = "qwen2.5:1.5b",
  [switch]$NoLlm
)
$ErrorActionPreference = "Stop"
if ($Db -in @("aisop_dev","aisop","aisop_test","postgres")) { throw "Refusing to touch protected database $Db" }
if (-not $OutDir.StartsWith("D:\")) { throw "OutDir must be on D:" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$root = "D:\AISOP"; $py = "$root\.venv\Scripts\python.exe"; $C = "aisop-postgres"
$pw = if ($env:POSTGRES_PASSWORD) { $env:POSTGRES_PASSWORD } else { "aisop" }
$url = "postgresql+psycopg://aisop:$pw@127.0.0.1:5433/$Db"

# stop a previous backend on this port
Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

if ($Reset) {
  docker exec $C psql -U aisop -d postgres -c "DROP DATABASE IF EXISTS $Db WITH (FORCE)" | Out-Null
}
$exists = docker exec $C psql -U aisop -d postgres -Atc "select 1 from pg_database where datname='$Db'"
if (-not $exists) { docker exec $C psql -U aisop -d postgres -c "CREATE DATABASE $Db" | Out-Null }

$env:DATABASE_URL = $url
& $py -m alembic -c "$root\backend\alembic.ini" upgrade head 2>&1 | Select-Object -Last 1

# Least privilege (OWASP A01/A05; probe-suite finding SEC-F2): the backend must not run as the container superuser.
# `aisop_app` can connect, read and write rows; it cannot create databases or roles, is not a superuser, and owns no objects.
$appPwFile = "$OutDir\aisop_app_db_password_DO_NOT_COMMIT.txt"
$appPw = if (Test-Path $appPwFile) { (Get-Content $appPwFile -Raw).Trim() } else { -join ((48..57 + 97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ }) }
Set-Content -Path $appPwFile -Value $appPw
$roleExists = docker exec $C psql -U aisop -d postgres -Atc "select 1 from pg_roles where rolname='aisop_app'"
$roleVerb = if ($roleExists) { "ALTER ROLE aisop_app WITH LOGIN PASSWORD '$appPw' NOSUPERUSER NOCREATEDB NOCREATEROLE" } else { "CREATE ROLE aisop_app LOGIN PASSWORD '$appPw' NOSUPERUSER NOCREATEDB NOCREATEROLE" }
docker exec $C psql -U aisop -d postgres -c $roleVerb | Out-Null
docker exec $C psql -U aisop -d $Db -c "GRANT CONNECT ON DATABASE $Db TO aisop_app; GRANT USAGE ON SCHEMA public TO aisop_app; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO aisop_app; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO aisop_app;" | Out-Null
$env:DATABASE_URL = "postgresql+psycopg://aisop_app:$appPw@127.0.0.1:5433/$Db"   # everything below runs as the non-superuser

$prov = & $py "$root\backend\scripts\provision_demo_identities.py" --yes --expires-in-hours 168 2>&1
$tok = @($prov | Select-String -Pattern 'aisop_live_[0-9a-f]+_[0-9a-f]+' -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -Unique)
if ($tok.Count -eq 2) {
  Set-Content "$OutDir\demo_tokens_DO_NOT_COMMIT.txt" ("analyst=" + $tok[0] + "`r`nsensor=" + $tok[1])
  "Demo tokens written to $OutDir\demo_tokens_DO_NOT_COMMIT.txt (rotate after the demo; never commit)"
} else { "Identities already existed or output unexpected; run provision_demo_identities.py --rotate if tokens are needed." }

Set-Location $root
& $py "$root\backend\scripts\ingest_knowledge_base.py" 2>&1 | Where-Object { $_ -match '^(success|skipped|failed|unchanged)' }

$env:API_AUTH_ENABLED = "true"; $env:API_AUTH_ALLOW_LEGACY_KEYS = "false"; $env:ENVIRONMENT = "development"
$env:ATTACK_REFERENCE_PATH = "D:\AISOP-Reference-Data\MITRE-ATT&CK\Enterprise\v20.1\enterprise-attack-20.1.json"
$env:LLM_ENABLED = if ($NoLlm) { "false" } else { "true" }; $env:OLLAMA_MODEL = $Model
$env:CORS_ORIGINS = '["http://localhost:3010","http://127.0.0.1:3010"]'; $env:AISOP_PORT = "$Port"
Start-Process -FilePath $py -ArgumentList "backend\run_local.py" -WorkingDirectory $root -RedirectStandardOutput "$OutDir\backend$Port.out.log" -RedirectStandardError "$OutDir\backend$Port.err.log" -WindowStyle Hidden
Start-Sleep 8
(Invoke-WebRequest "http://127.0.0.1:$Port/api/v1/health/ready" -UseBasicParsing -SkipHttpErrorCheck).Content
