"""
Unit tests for AISOP developer tool credential sanitization (AISOP-DEVTOOLS-002).

Validates that aisop.ps1 redacts sensitive credentials from console output
and generated Markdown diagnostic reports using synthetic fake secrets only.
"""

import shutil
import subprocess
import sys
from pathlib import Path
import pytest

# aisop.ps1 is a Windows tool: loading it needs %LOCALAPPDATA%. The parse check above runs everywhere.
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="aisop.ps1 needs %LOCALAPPDATA% (Windows)")


def get_pwsh_executable() -> str | None:
    """Find pwsh or powershell on system PATH."""
    for exe in ("pwsh", "powershell"):
        found = shutil.which(exe)
        if found:
            return found
    return None


@pytest.fixture(scope="module")
def pwsh_exe():
    exe = get_pwsh_executable()
    if not exe:
        pytest.skip("PowerShell (pwsh or powershell) not available on this system")
    return exe


@pytest.fixture(scope="module")
def repo_root() -> Path:
    # backend/tests/unit -> repository root
    return Path(__file__).resolve().parents[3]


def test_aisop_script_exists_and_parses(pwsh_exe: str, repo_root: Path):
    """Verify aisop.ps1 exists at repository root and passes AST syntax check."""
    aisop_script = repo_root / "aisop.ps1"
    assert aisop_script.is_file(), f"aisop.ps1 not found at {aisop_script}"

    cmd = [
        pwsh_exe,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"$errors = @(); [System.Management.Automation.Language.Parser]::ParseFile('{aisop_script}', [ref]$null, [ref]$errors); if ($errors.Count -eq 0) {{ 'SYNTAX_OK' }} else {{ $errors | ForEach-Object {{ $_.Message }} }}",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "SYNTAX_OK" in result.stdout


@windows_only
def test_aisop_sanitizer_powershell_suite(pwsh_exe: str, repo_root: Path):
    """Run tests/test_aisop_sanitizer.ps1 and verify 100% pass rate."""
    suite_script = repo_root / "tests" / "test_aisop_sanitizer.ps1"
    assert suite_script.is_file(), f"Test suite not found at {suite_script}"

    cmd = [
        pwsh_exe,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(suite_script),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"Sanitizer test suite failed:\n{result.stdout}\n{result.stderr}"
    assert "0 failed" in result.stdout


@windows_only
def test_protect_diagnostic_text_synthetic_secrets(pwsh_exe: str, repo_root: Path):
    """Test Protect-DiagnosticText via dot-sourcing with multiple synthetic secret patterns."""
    aisop_script = repo_root / "aisop.ps1"

    ps_code = (
        f". '{aisop_script}'\n"
        "$inputData = @'\n"
        "POSTGRES_PASSWORD=SyntheticPassword123!\n"
        "DATABASE_URL=postgresql://postgres:SyntheticDbPass@localhost:5433/db\n"
        "JWT_SECRET=\"SyntheticJwtKey2026!\"\n"
        "OPENAI_API_KEY=sk-synthetic1234567890abcdef1234567890\n"
        "GITHUB_TOKEN=ghp_synthetic123456789012345678901234567890\n"
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        "Authorization: Bearer mySyntheticBearerToken999\n"
        "Authorization: Basic dXNlcjpwYXNzMTIz\n"
        "primary_key = id\n"
        "HOST=127.0.0.1\n"
        "'@\n"
        "Protect-DiagnosticText $inputData\n"
    )

    cmd = [
        pwsh_exe,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        ps_code,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert result.returncode == 0
    sanitized = result.stdout

    # Verify synthetic secrets are NOT present
    forbidden = [
        "SyntheticPassword123!",
        "SyntheticDbPass",
        "SyntheticJwtKey2026!",
        "sk-synthetic1234567890abcdef1234567890",
        "ghp_synthetic123456789012345678901234567890",
        "AKIAIOSFODNN7EXAMPLE",
        "mySyntheticBearerToken999",
        "dXNlcjpwYXNzMTIz",
    ]
    for secret in forbidden:
        assert secret not in sanitized, f"Secret leaked: {secret}"

    # Verify non-sensitive strings are preserved
    assert "primary_key = id" in sanitized
    assert "HOST=127.0.0.1" in sanitized
