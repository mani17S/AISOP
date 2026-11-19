# AISOP Developer Utility Guide (`aisop.ps1`)

The `aisop.ps1` script is a local developer automation utility designed to streamline common engineering audits, environment health checks, and test execution without altering repository state or database schemas.

---

## 1. Safety Invariants & Architecture

- **Strictly Read-Only Git**: Every Git command uses `git -C $RepoRoot` to ensure path independence. It never stages, commits, resets, stashes, or cleans working tree files.
- **Zero Database Modification**: The utility never triggers Alembic migrations, database cleanup, or schema modifications.
- **Diagnostic Output Safety (`AISOP-DEVTOOLS-002`)**: Intercepts command stdout, stderr, exception messages, and test summaries via `Protect-DiagnosticText`. Automatically redacts credentials and tokens before console rendering or Markdown report persistence.
- **External Report Artifacts**: All generated diagnostic reports are written outside the repository to `$env:LOCALAPPDATA\AISOP\reports\`.
- **Accurate Statuses**: Differentiates `PASS`, `FAIL`, `WARN`, `BLOCKED`, `SKIP`, and `INFO`. TCP socket reachability is never reported as proof of database authentication or model inference.

---

## 2. Available Modes & Usage Examples

Run commands from PowerShell 7 (`pwsh`):

### Mode: `Audit`
Performs a read-only audit of Git repository identity, branch, recent commits, status, diff statistics, untracked non-ignored files, expected architectural directories, and on-disk Alembic migration metadata.
```powershell
pwsh -ExecutionPolicy Bypass -File .\aisop.ps1 -Mode Audit
```

### Mode: `Health`
Checks the local development environment: PowerShell version, repository virtual environment (`.venv\Scripts\python.exe`), Python version, pytest/SQLAlchemy/pgvector dependencies, Docker daemon status, and TCP listeners on port 5433 (PostgreSQL) and port 11434 (Ollama).
```powershell
pwsh -ExecutionPolicy Bypass -File .\aisop.ps1 -Mode Health
```

### Mode: `TestUnit`
Executes the offline unit test suite (`backend/tests/unit`) using the project's virtual environment, explicitly excluding tests requiring live external services (`-m "not postgres and not ollama"`).
```powershell
pwsh -ExecutionPolicy Bypass -File .\aisop.ps1 -Mode TestUnit
```

### Mode: `TestIntegration`
Runs live PostgreSQL integration tests (`backend/tests/integration -m postgres`). Probes port 5433 first; if PostgreSQL is unreachable, immediately marks the check as `BLOCKED` and exits without wasting minutes waiting for connection timeouts.
```powershell
pwsh -ExecutionPolicy Bypass -File .\aisop.ps1 -Mode TestIntegration
```

### Mode: `Report`
Combines `Audit` and `Health` checks and exports a timestamped Markdown report to `$env:LOCALAPPDATA\AISOP\reports\aisop-Report-<timestamp>.md`.
```powershell
pwsh -ExecutionPolicy Bypass -File .\aisop.ps1 -Mode Report
```

### Mode: `FullCheck`
Runs `Audit`, `Health`, and `TestUnit`. Integration tests are skipped by default to preserve fast feedback loops, but can be explicitly included via the `-IncludeIntegration` switch:
```powershell
# Standard fast check
pwsh -ExecutionPolicy Bypass -File .\aisop.ps1 -Mode FullCheck

# Complete check including live PostgreSQL integration
pwsh -ExecutionPolicy Bypass -File .\aisop.ps1 -Mode FullCheck -IncludeIntegration
```

---

## 3. Exit Code Convention

`aisop.ps1` returns explicit process exit codes for automated CI/CD and developer hooks:

| Exit Code | Meaning | Condition |
| :---: | :--- | :--- |
| `0` | **Success** | All executed checks passed (or passed with warnings/skips/info). |
| `1` | **Failure** | One or more tests or commands returned a failure (`FAIL`). |
| `2` | **Blocked** | One or more required prerequisites are missing or unreachable (`BLOCKED`). |

---

## 4. Diagnostic Output Safety & Credential Redaction (`AISOP-DEVTOOLS-002`)

To prevent accidental credential leaks into developer terminals or generated Markdown diagnostic reports, `aisop.ps1` integrates automated sanitization via the internal `Protect-DiagnosticText` function.

### Interception Points
1. **Command Echo**: Command line invocations are sanitized before being echoed to the console.
2. **Standard Output & Error**: Process stdout and stderr captured by `Invoke-CapturedCommand` are sanitized prior to console display and report inclusion.
3. **Execution Exceptions**: Script exceptions and process launch errors are sanitized before reporting.
4. **Markdown Report Persistence**: All report lines passed to `Add-ReportLine` and `Write-Result` are validated through `Protect-DiagnosticText`.

### Covered Redaction Patterns
- **Private Key Blocks**: PEM-encoded RSA, EC, OpenSSH, DSA, or generic private keys (`-----BEGIN ... PRIVATE KEY-----`) are replaced with `[REDACTED PRIVATE KEY]`.
- **HTTP Authorization Headers**: `Authorization: Bearer <token>` and `Authorization: Basic <base64>` values are replaced with `[REDACTED]`.
- **Standalone Bearer Tokens**: Log lines containing `Bearer <token>` are sanitized to `Bearer [REDACTED]`.
- **URL Embedded Credentials**: Database and HTTP connection URLs (`scheme://user:password@host:port/path`) retain schema, username, host, and path while redacting the secret: `scheme://user:[REDACTED]@host:port/path`.
- **Connection Strings**: ADO.NET and ODBC style parameters (`Password=...;`, `Pwd=...;`) are sanitized to `Password=[REDACTED];`.
- **Command-Line Secret Flags**: CLI parameters such as `--password`, `--passwd`, `--token`, `--api-key`, `--secret`, and `--client-secret` have their values replaced with `[REDACTED]`.
- **Key-Value Secret Assignments**: Common secret environment variables and config fields (e.g. `POSTGRES_PASSWORD=...`, `JWT_SECRET="..."`, `api_key: "..."`) are cleanly redacted while preserving assignment syntax and quotes.
- **Known Token Formats**: Specific token prefixes are matched and neutralized:
  - `sk-[A-Za-z0-9_-]{20,}` (OpenAI and generic API tokens)
  - `gh[pousr]_[A-Za-z0-9]{30,}` (GitHub personal, OAuth, and server tokens)
  - `AKIA[0-9A-Z]{16}` (AWS Access Key IDs)
  - `eyJ...` (JWT tokens: header.payload.signature)

### Non-Destructive Preservation
The sanitization rules are targeted to prevent corruption of benign operational metadata:
- Standard URLs without credentials (e.g. `http://localhost:5433/health`) remain untouched.
- Git commit hashes (`a1b2c3d`), exit codes (`exit code 0`), and local file paths are preserved.
- Database schema keywords (`primary_key`, `foreign_key`, `dict_key`) are not falsely flagged.

### Realistic Limitations (Defense-in-Depth)
> [!IMPORTANT]
> Regex-based diagnostic sanitization is a defensive, best-effort safeguard. It cannot mathematically guarantee detection of every secret permutation (e.g., non-standard variable naming conventions, deeply nested custom serialization formats, or credentials broken across unusual line splits).
> 
> **Developer Invariant**: Developers and automated tests must NEVER output live production secrets, real API keys, or actual credentials into console output, logging statements, or tracked repository files. Always use synthetic fake secrets (e.g. `SyntheticPassword123!`) in test fixtures.

### Running Sanitizer Verification Tests
Automated tests validate all redaction rules against synthetic fake secrets. Two test harnesses are provided:

1. **PowerShell Native Test Suite**:
   ```powershell
   pwsh -NoProfile -ExecutionPolicy Bypass -File .\tests\test_aisop_sanitizer.ps1
   ```
2. **Pytest Integration**:
   ```powershell
   .venv\Scripts\python.exe -m pytest backend\tests\unit\test_aisop_sanitizer.py -v
   ```
   *(Note: The pytest suite is automatically executed when running `aisop.ps1 -Mode TestUnit` or `aisop.ps1 -Mode FullCheck`)*.
