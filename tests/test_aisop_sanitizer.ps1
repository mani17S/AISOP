<#
.SYNOPSIS
    Automated test suite for aisop.ps1 credential sanitization (AISOP-DEVTOOLS-002).
.DESCRIPTION
    Validates Protect-DiagnosticText redaction rules using ONLY synthetic fake secrets.
    Includes unit assertions for all regex categories and an end-to-end report check.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path
$AisopScript = Join-Path $RepoRoot 'aisop.ps1'

if (-not (Test-Path -LiteralPath $AisopScript)) {
    Write-Error "aisop.ps1 not found at $AisopScript"
    exit 1
}

# Dot-source aisop.ps1 to import Protect-DiagnosticText
. $AisopScript

$testsPassed = 0
$testsFailed = 0

function Assert-Redaction {
    param(
        [Parameter(Mandatory)][string]$TestName,
        [Parameter(Mandatory)][string]$InputText,
        [AllowEmptyCollection()][string[]]$ForbiddenSecrets = @(),
        [AllowEmptyCollection()][string[]]$RequiredStrings = @()
    )

    $output = Protect-DiagnosticText $InputText
    $hasLeak = $false
    $hasMissing = $false

    foreach ($secret in $ForbiddenSecrets) {
        if ($output.Contains($secret)) {
            Write-Host "  [FAIL] $TestName - Leak detected: secret '$secret' present in sanitized output." -ForegroundColor Red
            $hasLeak = $true
        }
    }

    foreach ($required in $RequiredStrings) {
        if (-not $output.Contains($required)) {
            Write-Host "  [FAIL] $TestName - Corruption detected: expected string '$required' missing from sanitized output." -ForegroundColor Red
            $hasMissing = $true
        }
    }

    if (-not $hasLeak -and -not $hasMissing) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:testsPassed++
    }
    else {
        Write-Host "         Raw Input: $InputText" -ForegroundColor DarkGray
        Write-Host "         Sanitized: $output" -ForegroundColor DarkGray
        $script:testsFailed++
    }
}

Write-Host "`n=== AISOP Developer Tool Sanitizer Test Suite (AISOP-DEVTOOLS-002) ===" -ForegroundColor Cyan

# 1. Private Keys
Assert-Redaction `
    -TestName "1. PEM RSA Private Key" `
    -InputText "-----BEGIN RSA PRIVATE KEY-----`nMIIEowIBAAKCAQEA0mSyntheticKeyLine1`nLine2SyntheticPrivateKeyData==`n-----END RSA PRIVATE KEY-----" `
    -ForbiddenSecrets @("MIIEowIBAAKCAQEA0mSyntheticKeyLine1", "Line2SyntheticPrivateKeyData==") `
    -RequiredStrings @("[REDACTED PRIVATE KEY]")

Assert-Redaction `
    -TestName "1b. PEM Generic/EC Private Key" `
    -InputText "-----BEGIN EC PRIVATE KEY-----`nMHcCAQEEISyntheticEcKeyData1234567890abcdef`n-----END EC PRIVATE KEY-----" `
    -ForbiddenSecrets @("ISyntheticEcKeyData1234567890abcdef") `
    -RequiredStrings @("[REDACTED PRIVATE KEY]")

# 2. Authorization Headers
Assert-Redaction `
    -TestName "2a. Authorization Bearer header" `
    -InputText "Authorization: Bearer syntheticToken123.header.payload" `
    -ForbiddenSecrets @("syntheticToken123.header.payload") `
    -RequiredStrings @("Authorization: Bearer [REDACTED]")

Assert-Redaction `
    -TestName "2b. Authorization Basic header" `
    -InputText "Authorization: Basic c3ludGhldGljVXNlcjpzeW50aGV0aWNQYXNz" `
    -ForbiddenSecrets @("c3ludGhldGljVXNlcjpzeW50aGV0aWNQYXNz") `
    -RequiredStrings @("Authorization: Basic [REDACTED]")

# 3. Standalone Bearer Tokens
Assert-Redaction `
    -TestName "3. Standalone Bearer token in log line" `
    -InputText "Request authenticated via Bearer syntheticStandaloneBearerToken999." `
    -ForbiddenSecrets @("syntheticStandaloneBearerToken999") `
    -RequiredStrings @("Bearer [REDACTED]")

# 4. URL Credentials
Assert-Redaction `
    -TestName "4a. PostgreSQL URL credentials" `
    -InputText "postgresql://postgres:SyntheticDbPassword123!@localhost:5433/aisop_db" `
    -ForbiddenSecrets @("SyntheticDbPassword123!") `
    -RequiredStrings @("postgresql://postgres:[REDACTED]@localhost:5433/aisop_db")

Assert-Redaction `
    -TestName "4b. AsyncPG URL credentials" `
    -InputText "postgresql+asyncpg://aisop_user:SyntheticAsyncSecret456@db.internal:5432/aisop" `
    -ForbiddenSecrets @("SyntheticAsyncSecret456") `
    -RequiredStrings @("postgresql+asyncpg://aisop_user:[REDACTED]@db.internal:5432/aisop")

Assert-Redaction `
    -TestName "4c. HTTPS URL credentials" `
    -InputText "https://admin:SyntheticWebPass789@auth.corp.internal/api/v1" `
    -ForbiddenSecrets @("SyntheticWebPass789") `
    -RequiredStrings @("https://admin:[REDACTED]@auth.corp.internal/api/v1")

# 5. Connection Strings
Assert-Redaction `
    -TestName "5a. Connection string Password=..." `
    -InputText "Server=sql.internal;Database=aisop;User ID=sa;Password=SyntheticSqlPass123!;MultipleActiveResultSets=True;" `
    -ForbiddenSecrets @("SyntheticSqlPass123!") `
    -RequiredStrings @("Password=[REDACTED];", "Server=sql.internal")

Assert-Redaction `
    -TestName "5b. Connection string Pwd=..." `
    -InputText "Server=sql.internal;Uid=sa;Pwd=SyntheticPwd456;Option=1" `
    -ForbiddenSecrets @("SyntheticPwd456") `
    -RequiredStrings @("Pwd=[REDACTED];")

# 6. CLI Flags
Assert-Redaction `
    -TestName "6a. CLI flag --password with quotes" `
    -InputText "aisop-tool.exe --password ""SyntheticCliSecret123!"" --verbose" `
    -ForbiddenSecrets @("SyntheticCliSecret123!") `
    -RequiredStrings @("--password [REDACTED]", "--verbose")

Assert-Redaction `
    -TestName "6b. CLI flag --api-key=" `
    -InputText "cli.exe --api-key=SyntheticApiKey999 --format json" `
    -ForbiddenSecrets @("SyntheticApiKey999") `
    -RequiredStrings @("--api-key=[REDACTED]", "--format json")

# 7. Key-Value Assignments
Assert-Redaction `
    -TestName "7a. Environment variable POSTGRES_PASSWORD" `
    -InputText "POSTGRES_PASSWORD=SyntheticEnvPassword123!" `
    -ForbiddenSecrets @("SyntheticEnvPassword123!") `
    -RequiredStrings @("POSTGRES_PASSWORD=[REDACTED]")

Assert-Redaction `
    -TestName "7b. Quoted JWT_SECRET" `
    -InputText "JWT_SECRET=""SyntheticJwtSecretKey2026!""" `
    -ForbiddenSecrets @("SyntheticJwtSecretKey2026!") `
    -RequiredStrings @("JWT_SECRET=""[REDACTED]""")

Assert-Redaction `
    -TestName "7c. YAML/JSON key-value api_key" `
    -InputText "api_key: ""SyntheticYamlKey456""" `
    -ForbiddenSecrets @("SyntheticYamlKey456") `
    -RequiredStrings @("api_key: ""[REDACTED]""")

# 8. Known Token Prefixes
Assert-Redaction `
    -TestName "8a. OpenAI API token (sk-...)" `
    -InputText "Generated key: sk-synthetic1234567890abcdef1234567890abcdef for model" `
    -ForbiddenSecrets @("sk-synthetic1234567890abcdef1234567890abcdef") `
    -RequiredStrings @("sk-[REDACTED]", "Generated key:", "for model")

Assert-Redaction `
    -TestName "8b. GitHub personal access token (ghp_...)" `
    -InputText "Token created: ghp_synthetic123456789012345678901234567890" `
    -ForbiddenSecrets @("ghp_synthetic123456789012345678901234567890") `
    -RequiredStrings @("ghp_[REDACTED]")

Assert-Redaction `
    -TestName "8c. AWS Access Key ID (AKIA...)" `
    -InputText "AWS caller ID: AKIAIOSFODNN7EXAMPLE checked." `
    -ForbiddenSecrets @("AKIAIOSFODNN7EXAMPLE") `
    -RequiredStrings @("AKIA[REDACTED]")

Assert-Redaction `
    -TestName "8d. JWT Token (eyJ...)" `
    -InputText "Session: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c active" `
    -ForbiddenSecrets @("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") `
    -RequiredStrings @("[REDACTED JWT]")

# 9. Non-Sensitive Information Preservation
Assert-Redaction `
    -TestName "9a. Preservation of non-sensitive strings" `
    -InputText "URL: http://localhost:5433/health | Host: 127.0.0.1 | Port: 5433 | Git: a1b2c3d4 | Code: exit code 0" `
    -ForbiddenSecrets @() `
    -RequiredStrings @(
        "http://localhost:5433/health",
        "Host: 127.0.0.1",
        "Port: 5433",
        "Git: a1b2c3d4",
        "Code: exit code 0"
    )

Assert-Redaction `
    -TestName "9b. Preservation of schema keywords" `
    -InputText "Schema definition: primary_key = id, foreign_key = user_id, dict_key = name" `
    -ForbiddenSecrets @() `
    -RequiredStrings @(
        "primary_key = id",
        "foreign_key = user_id",
        "dict_key = name"
    )

# 10. Null / Empty Handling
$nullResult = Protect-DiagnosticText $null
if ($nullResult -eq $null -or $nullResult -eq '') {
    Write-Host "  [PASS] 10a. Null input handling" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "  [FAIL] 10a. Null input did not return null or empty" -ForegroundColor Red
    $testsFailed++
}

$emptyResult = Protect-DiagnosticText ""
if ($emptyResult -eq "") {
    Write-Host "  [PASS] 10b. Empty string handling" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "  [FAIL] 10b. Empty string did not return empty string" -ForegroundColor Red
    $testsFailed++
}

# 11. End-to-End Report Verification
Write-Host "`n--- End-to-End Report Verification ---" -ForegroundColor Cyan
$testReportRoot = Join-Path $env:LOCALAPPDATA 'AISOP\reports'
$preReportFiles = if (Test-Path -LiteralPath $testReportRoot) { Get-ChildItem -LiteralPath $testReportRoot -Filter '*.md' } else { @() }

# Run aisop.ps1 in Audit mode
$auditRun = pwsh -NoProfile -ExecutionPolicy Bypass -File $AisopScript -Mode Audit 2>&1
$postReportFiles = Get-ChildItem -LiteralPath $testReportRoot -Filter '*.md' | Sort-Object LastWriteTime -Descending
$latestReport = $postReportFiles | Select-Object -First 1

if ($latestReport -and (Test-Path -LiteralPath $latestReport.FullName)) {
    $reportContent = Get-Content -LiteralPath $latestReport.FullName -Raw
    # Verify report header and structure exist
    if ($reportContent -match '# AISOP Local Developer Check' -and $reportContent -match 'Repository identity') {
        Write-Host "  [PASS] 11a. Generated report file exists and contains valid audit header: $($latestReport.Name)" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "  [FAIL] 11a. Generated report file missing expected content" -ForegroundColor Red
        $testsFailed++
    }

    # Verify no private keys or authorization headers leaked into the report
    if ($reportContent -match 'BEGIN [A-Z0-9_-]+ PRIVATE KEY' -or $reportContent -match 'Authorization:\s*(?:Bearer|Basic)\s+[A-Za-z0-9]') {
        Write-Host "  [FAIL] 11b. Report file contains unredacted credentials!" -ForegroundColor Red
        $testsFailed++
    } else {
        Write-Host "  [PASS] 11b. Report file confirmed free of unredacted credential patterns" -ForegroundColor Green
        $testsPassed++
    }
} else {
    Write-Host "  [FAIL] 11a. No report file generated at $testReportRoot" -ForegroundColor Red
    $testsFailed++
}

Write-Host "`n=== Test Summary: $testsPassed passed, $testsFailed failed ===" -ForegroundColor $(if ($testsFailed -eq 0) { 'Green' } else { 'Red' })

if ($testsFailed -gt 0) {
    exit 1
}
exit 0
