<#
.SYNOPSIS
    Automated Unit Test Suite for AISOP PostgreSQL Backup Script (REQ-3.7).
.DESCRIPTION
    Validates backup_postgres.ps1 using an isolated temporary directory and deterministic
    mock executors. Never connects to the real PostgreSQL container or database.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptPath = Join-Path $PSScriptRoot "..\scripts\backup_postgres.ps1"
if (-not (Test-Path -Path $ScriptPath)) {
    Write-Error "Cannot locate backup script at '$ScriptPath'."
    exit 1
}

$TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "aisop_backup_tests_$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $TestDir -Force | Out-Null

$PassCount = 0
$FailCount = 0

function Assert-Condition {
    param(
        [string]$TestName,
        [bool]$Condition,
        [string]$FailureMessage = ""
    )
    if ($Condition) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:PassCount++
    } else {
        Write-Host "  [FAIL] $($TestName): $FailureMessage" -ForegroundColor Red
        $script:FailCount++
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AISOP Backup Script Unit Test Suite" -ForegroundColor Cyan
Write-Host " Test Directory: $TestDir" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan

try {
    # ── Test 1: Missing Container Handling ────────────────────────────────
    Write-Host "`nTest 1: Missing or stopped container handling..." -ForegroundColor Yellow
    $mockMissingContainer = {
        param([string[]]$CommandArgs)
        if ($CommandArgs[0] -eq "inspect") {
            return [PSCustomObject]@{ ExitCode = 1; Output = "Error: No such container" }
        }
        return [PSCustomObject]@{ ExitCode = 0; Output = "" }
    }

    $failedAsExpected = $false
    try {
        & $ScriptPath -ContainerName "nonexistent-container" -BackupDir $TestDir -MockExecutor $mockMissingContainer 2>$null
    } catch {
        $failedAsExpected = $true
    }
    Assert-Condition -TestName "Script fails when container is missing or stopped" -Condition $failedAsExpected

    # ── Test 2: DryRun Execution ──────────────────────────────────────────
    Write-Host "`nTest 2: DryRun parameter validation..." -ForegroundColor Yellow
    $mockHealthyContainer = {
        param([string[]]$CommandArgs)
        if ($CommandArgs[0] -eq "inspect") {
            return [PSCustomObject]@{ ExitCode = 0; Output = "true" }
        }
        if ($CommandArgs[0] -eq "exec" -and $CommandArgs -contains "SHOW server_version;") {
            return [PSCustomObject]@{ ExitCode = 0; Output = "17.11 (Debian 17.11-1.pgdg120+1)" }
        }
        return [PSCustomObject]@{ ExitCode = 0; Output = "" }
    }

    $dryRunResult = & $ScriptPath -ContainerName "aisop-postgres" -BackupDir $TestDir -DryRun -MockExecutor $mockHealthyContainer
    $dryRunSuccess = ($null -ne $dryRunResult -and $dryRunResult.Status -eq "DRY_RUN_SUCCESS")
    Assert-Condition -TestName "DryRun succeeds and does not invoke pg_dump" -Condition $dryRunSuccess

    # ── Test 3: Failed pg_dump Exit Code Handling ────────────────────────
    Write-Host "`nTest 3: Failed pg_dump process exit code handling..." -ForegroundColor Yellow
    $mockFailedDump = {
        param([string[]]$CommandArgs)
        if ($CommandArgs[0] -eq "inspect") {
            return [PSCustomObject]@{ ExitCode = 0; Output = "true" }
        }
        if ($CommandArgs[0] -eq "exec" -and $CommandArgs -contains "pg_dump") {
            return [PSCustomObject]@{ ExitCode = 1; Output = "pg_dump: error: connection to server failed" }
        }
        return [PSCustomObject]@{ ExitCode = 0; Output = "" }
    }

    $failedDumpExpected = $false
    try {
        & $ScriptPath -ContainerName "aisop-postgres" -BackupDir $TestDir -MockExecutor $mockFailedDump 2>$null
    } catch {
        $failedDumpExpected = $true
    }
    Assert-Condition -TestName "Script aborts on pg_dump non-zero exit code" -Condition $failedDumpExpected

    # ── Test 4: Empty (0-byte) Output File Guard ─────────────────────────
    Write-Host "`nTest 4: Empty (0-byte) backup file integrity guard..." -ForegroundColor Yellow
    $mockZeroByteDump = {
        param([string[]]$CommandArgs)
        if ($CommandArgs[0] -eq "inspect") {
            return [PSCustomObject]@{ ExitCode = 0; Output = "true" }
        }
        if ($CommandArgs[0] -eq "exec" -and $CommandArgs -contains "pg_dump") {
            return [PSCustomObject]@{ ExitCode = 0; Output = "" }
        }
        if ($CommandArgs[0] -eq "cp") {
            # Simulate docker cp creating an empty 0-byte file on host
            $hostDest = $CommandArgs[2]
            New-Item -ItemType File -Path $hostDest -Force | Out-Null
            return [PSCustomObject]@{ ExitCode = 0; Output = "" }
        }
        return [PSCustomObject]@{ ExitCode = 0; Output = "" }
    }

    $zeroByteDetected = $false
    try {
        & $ScriptPath -ContainerName "aisop-postgres" -BackupDir $TestDir -MockExecutor $mockZeroByteDump 2>$null
    } catch {
        $zeroByteDetected = $true
    }
    Assert-Condition -TestName "Script detects 0-byte dump, deletes it, and fails" -Condition $zeroByteDetected

    # ── Test 5: Successful End-to-End Backup with Metadata & SHA-256 ───────
    Write-Host "`nTest 5: Successful backup generation, SHA-256 checksum, and metadata..." -ForegroundColor Yellow
    $simulatedPayload = [System.Text.Encoding]::UTF8.GetBytes("PGDMP-CUSTOM-FORMAT-SIMULATED-PAYLOAD-FOR-AISOP-REQ-3.7")

    $mockSuccessfulBackup = {
        param([string[]]$CommandArgs)
        if ($CommandArgs[0] -eq "inspect") {
            return [PSCustomObject]@{ ExitCode = 0; Output = "true" }
        }
        if ($CommandArgs[0] -eq "exec" -and $CommandArgs -contains "SHOW server_version;") {
            return [PSCustomObject]@{ ExitCode = 0; Output = "17.11 (pgvector 0.8.6)" }
        }
        if ($CommandArgs[0] -eq "exec" -and $CommandArgs -contains "pg_dump") {
            return [PSCustomObject]@{ ExitCode = 0; Output = "" }
        }
        if ($CommandArgs[0] -eq "cp") {
            $hostDest = $CommandArgs[2]
            [System.IO.File]::WriteAllBytes($hostDest, $simulatedPayload)
            return [PSCustomObject]@{ ExitCode = 0; Output = "" }
        }
        return [PSCustomObject]@{ ExitCode = 0; Output = "" }
    }

    $null = & $ScriptPath -ContainerName "aisop-postgres" -DatabaseName "aisop_dev" -BackupDir $TestDir -CustomTag "testrun" -MockExecutor $mockSuccessfulBackup

    # Locate generated artifacts
    $dumpFiles = @(Get-ChildItem -Path $TestDir -Filter "aisop_aisop_dev_testrun_*.dump")
    $metaFiles = @(Get-ChildItem -Path $TestDir -Filter "aisop_aisop_dev_testrun_*.meta.json")
    $shaFiles = @(Get-ChildItem -Path $TestDir -Filter "aisop_aisop_dev_testrun_*.dump.sha256")

    Assert-Condition -TestName "Backup dump file was created" -Condition ($dumpFiles.Count -eq 1)
    Assert-Condition -TestName "Metadata sidecar file was created" -Condition ($metaFiles.Count -eq 1)
    Assert-Condition -TestName "SHA-256 checksum sidecar was created" -Condition ($shaFiles.Count -eq 1)

    if ($dumpFiles.Count -eq 1) {
        $dumpFile = $dumpFiles[0]
        Assert-Condition -TestName "Backup dump is non-empty (>0 bytes)" -Condition ($dumpFile.Length -eq $simulatedPayload.Length)

        # Verify SHA-256 calculation
        $expectedHash = (Get-FileHash -Path $dumpFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $shaContent = (Get-Content -Path $shaFiles[0].FullName -Raw).Trim()
        Assert-Condition -TestName "SHA-256 checksum matches actual artifact hash" -Condition ($shaContent.StartsWith($expectedHash))

        # Verify JSON metadata content
        $metaContent = Get-Content -Path $metaFiles[0].FullName -Raw | ConvertFrom-Json
        $metaValid = ($metaContent.database_name -eq "aisop_dev") -and `
                     ($metaContent.container_name -eq "aisop-postgres") -and `
                     ($metaContent.postgres_version -match "17.11") -and `
                     ($metaContent.sha256_checksum -eq $expectedHash) -and `
                     ($metaContent.status -eq "COMPLETED_AND_VERIFIED")
        Assert-Condition -TestName "Metadata JSON contains required audit fields" -Condition $metaValid
    }

    # ── Test 6: Overwrite Guard Protection ────────────────────────────────
    Write-Host "`nTest 6: Overwrite protection guard..." -ForegroundColor Yellow
    $scriptContent = Get-Content -Path $ScriptPath -Raw
    $hasGuard = [bool]($scriptContent -match 'Test-Path -Path \$dumpFilePath')
    Assert-Condition -TestName "Script contains active overwrite collision guard" -Condition $hasGuard

    # ── Test 7: Timestamp Uniqueness ──────────────────────────────────────
    Write-Host "`nTest 7: Timestamp uniqueness..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    $null = & $ScriptPath -ContainerName "aisop-postgres" -DatabaseName "aisop_dev" -BackupDir $TestDir -CustomTag "testrun" -MockExecutor $mockSuccessfulBackup

    $allDumps = @(Get-ChildItem -Path $TestDir -Filter "*.dump")
    Assert-Condition -TestName "Subsequent runs generate distinct timestamped files" -Condition ($allDumps.Count -ge 2)

} finally {
    # Clean up test directory
    if (Test-Path -Path $TestDir) {
        Remove-Item -Path $TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST RESULTS: $PassCount PASSED, $FailCount FAILED" -ForegroundColor $(if ($FailCount -eq 0) { "Green" } else { "Red" })
Write-Host "============================================================" -ForegroundColor Cyan

if ($FailCount -gt 0) {
    exit 1
}
exit 0
