[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Health', 'TestUnit', 'TestIntegration', 'Report', 'FullCheck')]
    [string]$Mode = 'Audit',

    # Integration tests may require PostgreSQL/pgvector and/or a running Ollama service.
    # FullCheck skips integration tests unless this switch is supplied.
    [switch]$IncludeIntegration,

    # Optional explicit pytest path, relative to the repository root.
    [string]$TestPath,

    # Optional override for the PostgreSQL host port used by this project.
    [ValidateRange(1, 65535)]
    [int]$PostgresPort = 5433,

    # Optional override for the Ollama host port.
    [ValidateRange(1, 65535)]
    [int]$OllamaPort = 11434
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This script is intended to live at the AISOP repository root.
$RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ReportRoot = Join-Path $env:LOCALAPPDATA 'AISOP\reports'
$ReportPath = Join-Path $ReportRoot "aisop-$Mode-$Timestamp.md"
$script:ReportLines = [System.Collections.Generic.List[string]]::new()
$script:Passes = 0
$script:Failures = 0
$script:Warnings = 0
$script:Blocked = 0
$script:Skips = 0
$script:Infos = 0
$script:Checks = 0

function Protect-DiagnosticText {
    param([AllowEmptyString()][AllowNull()][string]$Text = '')
    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $sanitized = $Text

    # 1. Private key blocks (PEM: RSA, EC, OPENSSH, DSA, or generic)
    $sanitized = [regex]::Replace(
        $sanitized,
        '-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----',
        '[REDACTED PRIVATE KEY]'
    )

    # 2. Authorization headers (Bearer / Basic)
    $sanitized = [regex]::Replace(
        $sanitized,
        '(?i)(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\r\n]+',
        '${1}[REDACTED]'
    )

    # 3. Standalone Bearer tokens
    $sanitized = [regex]::Replace(
        $sanitized,
        '(?i)\b(Bearer\s+)[A-Za-z0-9\-._~+/]+=*',
        '${1}[REDACTED]'
    )

    # 4. Standard URL credentials: scheme://user:pass@host
    $sanitized = [regex]::Replace(
        $sanitized,
        '([a-zA-Z][a-zA-Z0-9+.-]*://[^:\s/@]+:)([^@\s]+)(@)',
        '${1}[REDACTED]${3}'
    )

    # 5. Connection string keyword pairs: Password=...; or Pwd=...;
    $sanitized = [regex]::Replace(
        $sanitized,
        '(?i)\b(password|pwd)\s*=\s*([^;\r\n]+)',
        '${1}=[REDACTED]'
    )

    # 6. CLI flags: --password=val, --token val, --api-key=val, etc.
    $sanitized = [regex]::Replace(
        $sanitized,
        '(?i)(--(?:password|passwd|token|api[-_]?key|secret|client[-_]?secret)[=\s]+)(?:''[^'']*''|"[^"]*"|\S+)',
        '${1}[REDACTED]'
    )

    # 7. Known token prefixes: sk-, ghp_, AKIA, JWT (eyJ...)
    $sanitized = [regex]::Replace(
        $sanitized,
        '\bsk-[A-Za-z0-9_-]{20,}\b',
        'sk-[REDACTED]'
    )
    $sanitized = [regex]::Replace(
        $sanitized,
        '\bgh[pousr]_[A-Za-z0-9]{30,}\b',
        'ghp_[REDACTED]'
    )
    $sanitized = [regex]::Replace(
        $sanitized,
        '\bAKIA[0-9A-Z]{16}\b',
        'AKIA[REDACTED]'
    )
    $sanitized = [regex]::Replace(
        $sanitized,
        '\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
        '[REDACTED JWT]'
    )

    # 8a. Quoted key-value secret assignments: password = "my secret pass"
    $sanitized = [regex]::Replace(
        $sanitized,
        '(?i)\b([a-zA-Z0-9_]*(?:password|passwd|secret|api[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token)[a-zA-Z0-9_]*)(\s*)([:=])(\s*)([''"])[^\r\n]*?\5',
        '${1}${2}${3}${4}${5}[REDACTED]${5}'
    )

    # 8b. Unquoted key-value secret assignments: POSTGRES_PASSWORD=my_secret_pass
    $sanitized = [regex]::Replace(
        $sanitized,
        '(?i)\b([a-zA-Z0-9_]*(?:password|passwd|secret|api[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token)[a-zA-Z0-9_]*)(\s*)([:=])(\s*)([^\s''",;]+)',
        '${1}${2}${3}${4}[REDACTED]'
    )

    return $sanitized
}

function Add-ReportLine {
    param([AllowEmptyString()][string]$Text = "")
    $script:ReportLines.Add((Protect-DiagnosticText $Text))
}

function Write-Section {
    param([Parameter(Mandatory)][string]$Title)
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
    Add-ReportLine ''
    Add-ReportLine "## $Title"
}

function Write-Result {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS', 'INFO', 'WARN', 'FAIL', 'BLOCKED', 'SKIP')]
        [string]$Status,
        [Parameter(Mandatory)][string]$Message,
        [string]$Details
    )
    $script:Checks++
    $colour = switch ($Status) {
        'PASS'    { 'Green' }
        'INFO'    { 'Gray' }
        'WARN'    { 'Yellow' }
        'FAIL'    { 'Red' }
        'BLOCKED' { 'Magenta' }
        'SKIP'    { 'DarkGray' }
    }
    $sanitizedMessage = Protect-DiagnosticText $Message
    $sanitizedDetails = if ($Details) { Protect-DiagnosticText $Details } else { $Details }

    Write-Host "[$Status] $sanitizedMessage" -ForegroundColor $colour
    if ($sanitizedDetails) {
        Write-Host "        $sanitizedDetails"
    }
    $safeMessage = $sanitizedMessage.Replace('|', '\|')
    Add-ReportLine "- **$Status** — $safeMessage"
    if ($sanitizedDetails) {
        $safeDetails = ($sanitizedDetails -replace "`r?`n", ' ') -replace '\|', '\|'
        Add-ReportLine "  - $safeDetails"
    }
    switch ($Status) {
        'PASS'    { $script:Passes++ }
        'WARN'    { $script:Warnings++ }
        'FAIL'    { $script:Failures++ }
        'BLOCKED' { $script:Blocked++ }
        'SKIP'    { $script:Skips++ }
        'INFO'    { $script:Infos++ }
    }
}

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Description,
        [switch]$AllowFailure
    )
    $safeCmd = Protect-DiagnosticText "$FilePath $($Arguments -join ' ')"
    Write-Host "`n> $safeCmd" -ForegroundColor DarkGray
    try {
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        $rawText = ($output | Out-String).TrimEnd()
        $text = Protect-DiagnosticText $rawText
        if ($text) {
            Write-Host $text
            Add-ReportLine ''
            Add-ReportLine '```text'
            Add-ReportLine $text
            Add-ReportLine '```'
        }
        if ($exitCode -eq 0) {
            Write-Result -Status 'PASS' -Message "$Description (exit code 0)"
        }
        elseif ($AllowFailure) {
            Write-Result -Status 'WARN' -Message "$Description (exit code $exitCode)" -Details 'Command returned a non-zero exit code; inspect the captured output.'
        }
        else {
            Write-Result -Status 'FAIL' -Message "$Description (exit code $exitCode)" -Details 'Command returned a non-zero exit code.'
        }
        return [pscustomobject]@{ ExitCode = $exitCode; Output = $text }
    }
    catch {
        $errMsg = Protect-DiagnosticText $_.Exception.Message
        Write-Result -Status 'BLOCKED' -Message "$Description could not execute" -Details $errMsg
        return [pscustomobject]@{ ExitCode = -1; Output = $errMsg }
    }
}

function Get-GitExecutable {
    $cmd = Get-Command git -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Get-PythonExecutable {
    $venvPython = Join-Path $RepoRoot '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
        return $venvPython
    }
    $backendVenv = Join-Path $RepoRoot 'backend\.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $backendVenv -PathType Leaf) {
        return $backendVenv
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { return $py.Source }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) { return $python.Source }
    return $null
}

function Invoke-Python {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $pythonExe = Get-PythonExecutable
    if (-not $pythonExe) {
        Write-Result -Status 'BLOCKED' -Message 'Python executable not found' -Details 'Expected .venv\Scripts\python.exe, py launcher, or python on PATH.'
        return [pscustomobject]@{ ExitCode = -1; Output = 'Python not found' }
    }
    if ((Split-Path -Leaf $pythonExe) -eq 'py.exe' -and $pythonExe -notlike '*\.venv\*') {
        return Invoke-CapturedCommand -FilePath $pythonExe -Arguments (@('-3.12') + $Arguments) -Description 'Python command'
    }
    return Invoke-CapturedCommand -FilePath $pythonExe -Arguments $Arguments -Description 'Python command'
}

function Test-TcpPort {
    param([Parameter(Mandatory)][int]$Port)
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
            $connected = $async.AsyncWaitHandle.WaitOne(1200, $false)
            if ($connected -and $client.Connected) {
                $client.EndConnect($async)
                return $true
            }
            return $false
        }
        finally {
            $client.Dispose()
        }
    }
    catch {
        return $false
    }
}

function Invoke-Audit {
    Write-Section 'Repository identity'
    Write-Result -Status 'INFO' -Message "Repository root: $RepoRoot"
    Write-Result -Status 'INFO' -Message "Mode: $Mode"
    Write-Result -Status 'INFO' -Message "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"

    $git = Get-GitExecutable
    if (-not $git) {
        Write-Result -Status 'BLOCKED' -Message 'Git executable not found'
        return
    }

    $inside = Invoke-CapturedCommand -FilePath $git -Arguments @('-C', $RepoRoot, 'rev-parse', '--show-toplevel') -Description 'Git repository root'
    if ($inside.ExitCode -ne 0) {
        Write-Result -Status 'BLOCKED' -Message 'This directory is not a valid Git repository' -Details $RepoRoot
        return
    }

    Write-Section 'Branch and recent history'
    Invoke-CapturedCommand -FilePath $git -Arguments @('-C', $RepoRoot, 'branch', '--show-current') -Description 'Current branch'
    Invoke-CapturedCommand -FilePath $git -Arguments @('-C', $RepoRoot, 'log', '-5', '--oneline') -Description 'Recent commits' -AllowFailure

    Write-Section 'Working tree and diffs'
    Invoke-CapturedCommand -FilePath $git -Arguments @('-C', $RepoRoot, 'status', '--short') -Description 'Git status'
    Invoke-CapturedCommand -FilePath $git -Arguments @('-C', $RepoRoot, 'diff', '--stat') -Description 'Unstaged tracked diff statistics' -AllowFailure
    Invoke-CapturedCommand -FilePath $git -Arguments @('-C', $RepoRoot, 'diff', '--cached', '--stat') -Description 'Staged diff statistics' -AllowFailure
    Invoke-CapturedCommand -FilePath $git -Arguments @('-C', $RepoRoot, 'ls-files', '--others', '--exclude-standard') -Description 'Untracked non-ignored files' -AllowFailure

    Write-Section 'Expected project files'
    foreach ($relative in @(
        'pyproject.toml',
        'backend',
        'backend\tests',
        'backend\app\models',
        'backend\app\modules\ai'
    )) {
        $full = Join-Path $RepoRoot $relative
        if (Test-Path -LiteralPath $full) {
            Write-Result -Status 'PASS' -Message "Found $relative"
        }
        else {
            Write-Result -Status 'WARN' -Message "Not found: $relative" -Details 'Repository layouts can vary; verify whether this path is expected.'
        }
    }

    Write-Section 'Database migrations (files on disk)'
    $candidateMigrationDirs = @(
        (Join-Path $RepoRoot 'backend\app\db\migrations\versions'),
        (Join-Path $RepoRoot 'backend\alembic\versions')
    )
    $alembicDir = $candidateMigrationDirs | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($alembicDir) {
        $migrations = Get-ChildItem -LiteralPath $alembicDir -Filter '*.py' | Where-Object { $_.Name -ne '__init__.py' } | Sort-Object Name
        Write-Result -Status 'INFO' -Message "Found $($migrations.Count) migration file(s) in $alembicDir"
        foreach ($m in $migrations) {
            $content = Get-Content -LiteralPath $m.FullName -Raw
            $revMatch = [regex]::Match($content, 'revision(?:\s*:\s*str)?\s*=\s*["''](?<val>[^"'']+)["'']')
            $downMatch = [regex]::Match($content, 'down_revision(?:\s*:\s*[^=]+)?\s*=\s*(?:["''](?<val>[^"'']+)["'']|(?<val>None))')
            $revId = if ($revMatch.Success) { $revMatch.Groups['val'].Value } else { "Unknown" }
            $downVal = if ($downMatch.Success) { $downMatch.Groups['val'].Value } else { '' }
            $downId = if ($downVal -and $downVal -ne 'None') { $downVal } else { "None (Root)" }
            Write-Result -Status 'INFO' -Message "Migration $($m.Name)" -Details "revision: $revId | down_revision: $downId"
        }
        Write-Result -Status 'INFO' -Message 'Applied revision note' -Details 'Migration files above reflect source tree. Applied revision in database requires PostgreSQL query against alembic_version.'
    }
    else {
        Write-Result -Status 'WARN' -Message "Alembic versions directory not found in candidate paths: $($candidateMigrationDirs -join '; ')"
    }
}

function Invoke-Health {
    Write-Section 'Runtime versions'
    $pythonExe = Get-PythonExecutable
    if ($pythonExe) {
        if ((Split-Path -Leaf $pythonExe) -eq 'py.exe' -and $pythonExe -notlike '*\.venv\*') {
            Invoke-CapturedCommand -FilePath $pythonExe -Arguments @('-3.12', '--version') -Description 'Python 3.12 version'
        }
        else {
            Invoke-CapturedCommand -FilePath $pythonExe -Arguments @('--version') -Description 'Selected Python version'
        }
    }
    else {
        Write-Result -Status 'BLOCKED' -Message 'Python unavailable'
    }

    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($docker) {
        $dockerResult = Invoke-CapturedCommand -FilePath $docker.Source -Arguments @('info', '--format', '{{.ServerVersion}}') -Description 'Docker daemon availability' -AllowFailure
        if ($dockerResult.ExitCode -ne 0) {
            Write-Result -Status 'BLOCKED' -Message 'Docker daemon is not confirmed available'
        }
        else {
            Invoke-CapturedCommand -FilePath $docker.Source -Arguments @('ps', '--format', 'table {{.Names}}\t{{.Status}}\t{{.Ports}}') -Description 'Running Docker containers' -AllowFailure
        }
    }
    else {
        Write-Result -Status 'BLOCKED' -Message 'Docker CLI not found'
    }

    if (Test-TcpPort -Port $PostgresPort) {
        Write-Result -Status 'PASS' -Message "TCP connection available on localhost:$PostgresPort" -Details 'TCP reachability does not prove PostgreSQL authentication, schema, or pgvector readiness.'
    }
    else {
        Write-Result -Status 'BLOCKED' -Message "No TCP listener confirmed on localhost:$PostgresPort" -Details 'PostgreSQL may be stopped, configured on another port, or inaccessible.'
    }

    if (Test-TcpPort -Port $OllamaPort) {
        Write-Result -Status 'PASS' -Message "TCP connection available on localhost:$OllamaPort" -Details 'TCP reachability does not prove the requested embedding model is installed or usable.'
    }
    else {
        Write-Result -Status 'WARN' -Message "No TCP listener confirmed on localhost:$OllamaPort" -Details 'Live Ollama tests may be unavailable; this does not block offline unit tests.'
    }

    $python = Get-PythonExecutable
    if ($python) {
        $args = @('-c', 'import importlib.util; print("pytest=" + str(importlib.util.find_spec("pytest") is not None)); print("sqlalchemy=" + str(importlib.util.find_spec("sqlalchemy") is not None)); print("pgvector=" + str(importlib.util.find_spec("pgvector") is not None))')
        if ((Split-Path -Leaf $python) -eq 'py.exe' -and $python -notlike '*\.venv\*') {
            Invoke-CapturedCommand -FilePath $python -Arguments (@('-3.12') + $args) -Description 'Python dependency availability'
        }
        else {
            Invoke-CapturedCommand -FilePath $python -Arguments $args -Description 'Python dependency availability'
        }
    }
}

function Invoke-TestSuite {
    param(
        [Parameter(Mandatory)][ValidateSet('Unit', 'Integration')]
        [string]$Suite
    )

    Write-Section "$Suite tests"
    $relativePath = if ($TestPath) {
        $TestPath
    }
    elseif ($Suite -eq 'Unit') {
        'backend\tests\unit'
    }
    else {
        'backend\tests\integration'
    }
    $target = Join-Path $RepoRoot $relativePath
    if (-not (Test-Path -LiteralPath $target)) {
        Write-Result -Status 'BLOCKED' -Message "Test path not found: $relativePath"
        return
    }

    $python = Get-PythonExecutable
    if (-not $python) {
        Write-Result -Status 'BLOCKED' -Message 'Cannot run tests because Python was not found'
        return
    }

    if ($Suite -eq 'Integration') {
        if (-not (Test-TcpPort -Port $PostgresPort)) {
            Write-Result -Status 'BLOCKED' -Message "Integration tests blocked: PostgreSQL port $PostgresPort unreachable" -Details "PostgreSQL service is not accessible on localhost:$PostgresPort. Ensure Docker and the postgres container are running before running integration tests."
            return
        }
    }

    $pytestArgs = if ($Suite -eq 'Unit' -and -not $TestPath) {
        @('-m', 'pytest', $target, '-v', '-m', 'not postgres and not ollama')
    }
    elseif ($Suite -eq 'Integration' -and -not $TestPath) {
        @('-m', 'pytest', $target, '-v', '-m', 'postgres')
    }
    else {
        @('-m', 'pytest', $target, '-v')
    }

    if ((Split-Path -Leaf $python) -eq 'py.exe' -and $python -notlike '*\.venv\*') {
        $pythonArgs = @('-3.12') + $pytestArgs
    }
    else {
        $pythonArgs = $pytestArgs
    }

    $result = Invoke-CapturedCommand -FilePath $python -Arguments $pythonArgs -Description "$Suite pytest suite"
    if ($result.ExitCode -ne 0) {
        Write-Result -Status 'FAIL' -Message "$Suite tests did not pass" -Details 'Review the full pytest output above; failures may include environment prerequisites.'
    }
}

function Save-Report {
    Write-Section 'Summary'
    Add-ReportLine "- Checks recorded: $script:Checks"
    Add-ReportLine "- Passed: $script:Passes"
    Add-ReportLine "- Warnings: $script:Warnings"
    Add-ReportLine "- Failures: $script:Failures"
    Add-ReportLine "- Blocked checks: $script:Blocked"
    Add-ReportLine "- Skipped checks: $script:Skips"
    Add-ReportLine "- Info items: $script:Infos"
    Add-ReportLine ''
    Add-ReportLine '> This is a local diagnostic report, not proof that all AISOP acceptance criteria pass.'
    Add-ReportLine '> Git and environment inspection is read-only. Test modes execute tests, which may create normal test artifacts.'
    New-Item -ItemType Directory -Path $ReportRoot -Force | Out-Null
    [System.IO.File]::WriteAllLines($ReportPath, $script:ReportLines, [System.Text.UTF8Encoding]::new($false))
    Write-Host "`nReport saved to: $ReportPath" -ForegroundColor Cyan
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

Add-ReportLine '# AISOP Local Developer Check'
Add-ReportLine ''
Add-ReportLine "- Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
Add-ReportLine "- Repository: $RepoRoot"
Add-ReportLine "- Mode: $Mode"
Add-ReportLine ''
Add-ReportLine '> Generated by aisop.ps1. Results reflect only the checks actually executed.'

Push-Location $RepoRoot
try {
    switch ($Mode) {
        'Audit' {
            Invoke-Audit
        }
        'Health' {
            Invoke-Health
        }
        'TestUnit' {
            Invoke-TestSuite -Suite Unit
        }
        'TestIntegration' {
            Invoke-Health
            Invoke-TestSuite -Suite Integration
        }
        'Report' {
            Invoke-Audit
            Invoke-Health
        }
        'FullCheck' {
            Invoke-Audit
            Invoke-Health
            Invoke-TestSuite -Suite Unit
            if ($IncludeIntegration) {
                Invoke-TestSuite -Suite Integration
            }
            else {
                Write-Section 'Integration tests'
                Write-Result -Status 'SKIP' -Message 'Integration tests not run by default' -Details 'Use -IncludeIntegration after confirming required services and test configuration.'
            }
        }
    }
}
finally {
    Pop-Location
    Save-Report
}

Write-Host ("`nSummary: {0} checks ({1} pass, {2} warn, {3} fail, {4} blocked, {5} skip, {6} info)." -f $script:Checks, $script:Passes, $script:Warnings, $script:Failures, $script:Blocked, $script:Skips, $script:Infos) -ForegroundColor Cyan
Write-Host 'No Git staging, commit, reset, clean, migration, or source-code edit is performed by this script.' -ForegroundColor Green

if ($script:Failures -gt 0) {
    exit 1
}
if ($script:Blocked -gt 0) {
    exit 2
}
exit 0
