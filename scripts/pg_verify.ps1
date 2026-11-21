<#
.SYNOPSIS
  AISOP PostgreSQL verification launcher (Stage 7B plan, owner-authorized 2026-11-20).

.DESCRIPTION
  Touches ONLY the disposable database `aisop_stage7b_verify_disposable` inside the approved `aisop-postgres` container.
  It never connects to, migrates or modifies aisop_dev, aisop_test or any other database.

  Steps: (1) verify the container identity (name, image, volume) and refuse on mismatch; (2) create the disposable DB if absent
  and set the disposable-target marker comment; (3) `alembic upgrade head` against that DB only; (4) export the identity
  variables for the test guard (values are never printed); (5) run the PostgreSQL-marked tests.

  The DB password is taken from the POSTGRES_PASSWORD environment variable when set, otherwise the documented local-dev default
  from docker-compose.yml. No secret file is read.

.PARAMETER Marker  Pytest marker expression. Default: "postgres and not ollama".
.PARAMETER LogDir  Where the logs are written (must be on D:).
#>
param(
  [string]$Marker = "postgres and not ollama",
  [string]$LogDir = "D:\AISOP-Backups\AISOP_Dev_Logs_20261120"
)
$ErrorActionPreference = "Stop"
$Container = "aisop-postgres"; $Image = "pgvector/pgvector:pg17"; $Volume = "aisop_postgres_data"
$Db = "aisop_stage7b_verify_disposable"; $Marker_ = "aisop-disposable-test-target:$Db"
if (-not $LogDir.StartsWith("D:\")) { throw "LogDir must be on D:" }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# 1. identity
$inspect = docker inspect $Container | ConvertFrom-Json
if ($inspect[0].Config.Image -ne $Image) { throw "Container image mismatch" }
if (-not ($inspect[0].Mounts | Where-Object { $_.Name -eq $Volume })) { throw "Container volume mismatch" }
if ($inspect[0].State.Health.Status -ne "healthy") { throw "Container not healthy" }

# 2. disposable DB + marker (via the container's local socket; nothing else is touched)
$exists = docker exec $Container psql -U aisop -d postgres -Atc "select 1 from pg_database where datname='$Db'"
if (-not $exists) { docker exec $Container psql -U aisop -d postgres -c "CREATE DATABASE $Db" | Out-Null }
docker exec $Container psql -U aisop -d postgres -c "COMMENT ON DATABASE $Db IS '$Marker_'" | Out-Null

# 3. migrate that DB only
$pw = if ($env:POSTGRES_PASSWORD) { $env:POSTGRES_PASSWORD } else { "aisop" }
$url = "postgresql+psycopg://aisop:$pw@127.0.0.1:5433/$Db"
$env:DATABASE_URL = $url
& "D:\AISOP\.venv\Scripts\python.exe" -m alembic -c "D:\AISOP\backend\alembic.ini" upgrade head 2>&1 | Tee-Object -FilePath "$LogDir\pg_alembic.log"
Remove-Item Env:\DATABASE_URL

# 4. identity for the guard
$env:TEST_DATABASE_URL = $url
$env:ALLOW_DESTRUCTIVE_POSTGRES_TESTS = "1"
$env:AISOP_PG_VERIFIED_CONTAINER = $Container
$env:AISOP_PG_VERIFIED_IMAGE = $Image
$env:AISOP_PG_VERIFIED_VOLUME = $Volume
$env:AISOP_PG_DISPOSABLE_MARKER = $Marker_

# 5. tests
Set-Location "D:\AISOP"
& "D:\AISOP\.venv\Scripts\python.exe" -m pytest -p no:cacheprovider -m $Marker -q 2>&1 | Tee-Object -FilePath "$LogDir\pg_tests.log"
