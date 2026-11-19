<#
.SYNOPSIS
    Automated PostgreSQL custom-format backup script for AISOP.
.DESCRIPTION
    Performs a consistent, self-verifying logical backup of the AISOP PostgreSQL database
    using PostgreSQL's custom archive format (pg_dump -Fc).
    Preserves all schemas, pgvector embeddings, audit triggers, foreign keys, and indexes.
    Calculates SHA-256 checksums and emits sidecar metadata records.
.PARAMETER ContainerName
    Name of the Docker container hosting PostgreSQL. Default: 'aisop-postgres'.
.PARAMETER DatabaseName
    Target database name to back up. Default: 'aisop_dev'.
.PARAMETER Username
    Database user for pg_dump execution. Default: 'aisop'.
.PARAMETER BackupDir
    Destination directory on host for backup artifacts. Default: '<repo_root>/backups'.
.PARAMETER CustomTag
    Optional identifier appended to the backup filename.
.PARAMETER DryRun
    If set, validates parameters and container status without executing pg_dump.
.PARAMETER MockExecutor
    Internal scriptblock hook for deterministic unit testing without live Docker.
.EXAMPLE
    pwsh -File ./scripts/backup_postgres.ps1
.EXAMPLE
    pwsh -File ./scripts/backup_postgres.ps1 -BackupDir "D:\backups\aisop" -CustomTag "pre-upgrade"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ContainerName = "aisop-postgres",

    [Parameter(Mandatory = $false)]
    [string]$DatabaseName = "aisop_dev",

    [Parameter(Mandatory = $false)]
    [string]$Username = "aisop",

    [Parameter(Mandatory = $false)]
    [string]$BackupDir = "",

    [Parameter(Mandatory = $false)]
    [string]$CustomTag = "",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [scriptblock]$MockExecutor = $null
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helper: Invoke Docker or Mock ──────────────────────────────────────────
function Invoke-Docker {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CommandArgs
    )
    if ($null -ne $MockExecutor) {
        return & $MockExecutor $CommandArgs
    } else {
        $output = & docker @CommandArgs 2>&1
        return [PSCustomObject]@{
            ExitCode = $LASTEXITCODE
            Output   = ($output -join "`n").Trim()
        }
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AISOP PostgreSQL Backup Utility (pg_dump -Fc)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ── 1. Resolve Paths ───────────────────────────────────────────────────────
$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BackupDir)) {
    $BackupDir = Join-Path $RepoRoot "backups"
}

Write-Host "[1/6] Validating backup destination..." -ForegroundColor Gray
Write-Host "      Host Destination: $BackupDir"
if (-not (Test-Path -Path $BackupDir)) {
    try {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        Write-Host "      Created directory: $BackupDir" -ForegroundColor Green
    } catch {
        Write-Error "Failed to create backup directory '$BackupDir': $_"
        exit 1
    }
}

# ── 2. Pre-Flight Container & Environment Check ───────────────────────────
Write-Host "[2/6] Inspecting container state ($ContainerName)..." -ForegroundColor Gray
if ($null -eq $MockExecutor) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "Prerequisite Failure: 'docker' CLI is not installed or not in PATH."
        exit 1
    }
}

$inspectResult = Invoke-Docker -CommandArgs @("inspect", "--format", "{{.State.Running}}", $ContainerName)
if ($inspectResult.ExitCode -ne 0 -or $inspectResult.Output -ne "true") {
    Write-Error "Container Check Failed: Container '$ContainerName' is not running or does not exist. Exit code: $($inspectResult.ExitCode)"
    exit 1
}
Write-Host "      Container '$ContainerName' is running." -ForegroundColor Green

# Safely query PostgreSQL server version
$versionResult = Invoke-Docker -CommandArgs @("exec", $ContainerName, "psql", "-U", $Username, "-d", $DatabaseName, "-t", "-A", "-c", "SHOW server_version;")
$postgresVersion = "unknown"
if ($versionResult.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($versionResult.Output)) {
    $postgresVersion = $versionResult.Output.Trim()
    Write-Host "      PostgreSQL Server Version: $postgresVersion" -ForegroundColor Green
}

# ── 3. Generate Timestamped Artifact Names ─────────────────────────────────
$timestampUtc = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
$tagPart = if ([string]::IsNullOrWhiteSpace($CustomTag)) { "" } else { "_$CustomTag" }
$baseName = "aisop_${DatabaseName}${tagPart}_${timestampUtc}"
$dumpFileName = "${baseName}.dump"
$metaFileName = "${baseName}.meta.json"
$checksumFileName = "${baseName}.dump.sha256"

$dumpFilePath = Join-Path $BackupDir $dumpFileName
$metaFilePath = Join-Path $BackupDir $metaFileName
$checksumFilePath = Join-Path $BackupDir $checksumFileName

Write-Host "[3/6] Prepared backup artifact identity:" -ForegroundColor Gray
Write-Host "      Backup File:   $dumpFileName"
Write-Host "      Metadata File: $metaFileName"
Write-Host "      Checksum File: $checksumFileName"

# ── 4. Overwrite Guard ────────────────────────────────────────────────────
if (Test-Path -Path $dumpFilePath) {
    Write-Error "Safety Violation: Target backup file '$dumpFilePath' already exists. Aborting to avoid overwrite."
    exit 1
}

if ($DryRun) {
    Write-Host "[DRY RUN] Pre-flight validation succeeded. Skipping pg_dump execution." -ForegroundColor Yellow
    return [PSCustomObject]@{
        Status         = "DRY_RUN_SUCCESS"
        DumpFile       = $dumpFileName
        ContainerName  = $ContainerName
        DatabaseName   = $DatabaseName
        BackupDir      = $BackupDir
    }
}

# ── 5. Execute Custom-Format pg_dump ───────────────────────────────────────
Write-Host "[4/6] Executing custom-format dump (pg_dump -Fc)..." -ForegroundColor Gray
$containerTempPath = "/tmp/$dumpFileName"

# Execute pg_dump inside container writing to local container temporary storage
$pgDumpArgs = @(
    "exec",
    $ContainerName,
    "pg_dump",
    "-U", $Username,
    "-d", $DatabaseName,
    "-Fc",
    "--no-owner",
    "--no-privileges",
    "-f", $containerTempPath
)

$dumpResult = Invoke-Docker -CommandArgs $pgDumpArgs
if ($dumpResult.ExitCode -ne 0) {
    Write-Error "pg_dump Execution Failed with exit code $($dumpResult.ExitCode). Output: $($dumpResult.Output)"
    # Attempt cleanup of container temporary file
    Invoke-Docker -CommandArgs @("exec", $ContainerName, "rm", "-f", $containerTempPath) | Out-Null
    exit 1
}

# Copy backup archive from container to host destination
Write-Host "      Copying archive from container to host..." -ForegroundColor Gray
$cpResult = Invoke-Docker -CommandArgs @("cp", "${ContainerName}:${containerTempPath}", $dumpFilePath)
# Clean up temporary container file
Invoke-Docker -CommandArgs @("exec", $ContainerName, "rm", "-f", $containerTempPath) | Out-Null

if ($cpResult.ExitCode -ne 0) {
    Write-Error "Failed to copy backup artifact from container: $($cpResult.Output)"
    if (Test-Path -Path $dumpFilePath) {
        Remove-Item -Path $dumpFilePath -Force -ErrorAction SilentlyContinue
    }
    exit 1
}

# ── 6. Post-Backup Integrity & File Verification ──────────────────────────
Write-Host "[5/6] Verifying backup artifact integrity..." -ForegroundColor Gray
if (-not (Test-Path -Path $dumpFilePath)) {
    Write-Error "Integrity Check Failed: Expected backup file '$dumpFilePath' was not created."
    exit 1
}

$fileItem = Get-Item -Path $dumpFilePath
if ($fileItem.Length -le 0) {
    Remove-Item -Path $dumpFilePath -Force -ErrorAction SilentlyContinue
    Write-Error "Integrity Check Failed: Backup file '$dumpFilePath' is 0 bytes. Corrupt artifact removed."
    exit 1
}

Write-Host "      Artifact exists. Size: $($fileItem.Length) bytes ($([math]::Round($fileItem.Length / 1MB, 2)) MB)" -ForegroundColor Green

# ── 7. Generate SHA-256 Checksum ──────────────────────────────────────────
Write-Host "[6/6] Computing cryptographic SHA-256 checksum..." -ForegroundColor Gray
$hashResult = Get-FileHash -Path $dumpFilePath -Algorithm SHA256
$sha256Hash = $hashResult.Hash.ToLowerInvariant()
"$sha256Hash *$dumpFileName" | Set-Content -Path $checksumFilePath -Encoding utf8 -NoNewline

Write-Host "      SHA-256: $sha256Hash" -ForegroundColor Green

# ── 8. Emit Metadata Sidecar ──────────────────────────────────────────────
$metadata = [ordered]@{
    schema_version   = "1.0"
    timestamp_utc    = (Get-Date).ToUniversalTime().ToString("o")
    database_name    = $DatabaseName
    container_name   = $ContainerName
    postgres_version = $postgresVersion
    format           = "PostgreSQL Custom Archive (pg_dump -Fc)"
    backup_file      = $dumpFileName
    file_size_bytes  = $fileItem.Length
    sha256_checksum  = $sha256Hash
    status           = "COMPLETED_AND_VERIFIED"
}

$metadataJson = $metadata | ConvertTo-Json -Depth 4
$metadataJson | Set-Content -Path $metaFilePath -Encoding utf8

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " BACKUP SUCCESSFUL (REQ-3.7 Artifact Created)" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Dump:     $dumpFilePath"
Write-Host " SHA-256:  $checksumFilePath"
Write-Host " Metadata: $metaFilePath"
Write-Host " Size:     $($fileItem.Length) bytes"
Write-Host " Hash:     $sha256Hash"

exit 0
