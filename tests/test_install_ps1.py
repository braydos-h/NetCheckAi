"""Static contract tests for install.ps1 (no PowerShell execution needed).

Mirrors the style of tests/test_install_sh.py: hermetic, file-based checks
that fail loudly when the installer contract drifts — required parameters,
exit-code documentation, security prohibitions, metadata/state filenames, and
the Pester suite's presence. Behavioral coverage lives in
tests/Test-InstallHelpers.ps1 (run by .github/workflows/installer-windows.yml).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_PS1 = REPO_ROOT / "install.ps1"
PESTER_SUITE = REPO_ROOT / "tests" / "Test-InstallHelpers.ps1"


@pytest.fixture()
def script() -> str:
    assert INSTALL_PS1.exists(), "install.ps1 missing from repo root"
    return INSTALL_PS1.read_text(encoding="utf-8")


REQUIRED_PARAMS = [
    "Yes",
    "Check",
    "Update",
    "Repair",
    "Uninstall",
    "NoLaunch",
    "SkipWebUI",
    "SkipDocker",
    "SkipOllama",
    "InstallDir",
    "Version",
    "Channel",
    "Force",
    "Offline",
    "GitHubToken",
    "LogPath",
    "NoPath",
    "KeepBackup",
    "Help",
]

EXIT_CODES = {
    0: "success",
    1: "installation failure",
    2: "invalid arguments",
    3: "unsupported platform",
    4: "dependency failure",
    5: "download/version resolution failure",
    6: "validation/integrity failure",
    7: "doctor failed",
    8: "update rollback completed",
    9: "reboot/re-login required",
    10: "action required",
}


def test_all_required_params_present(script: str) -> None:
    for name in REQUIRED_PARAMS:
        assert re.search(rf"\[\w+\]\${name}\b", script), f"param -{name} missing"


def test_cmdlet_binding_and_channel_validation(script: str) -> None:
    assert "[CmdletBinding()]" in script
    assert 'ValidateSet("Stable", "Prerelease", "Main")' in script


def test_exit_codes_documented_and_defined(script: str) -> None:
    for name in (
        "ExitSuccess",
        "ExitFailure",
        "ExitInvalidArgs",
        "ExitUnsupported",
        "ExitDependency",
        "ExitDownload",
        "ExitValidation",
        "ExitDoctor",
        "ExitRolledBack",
        "ExitReboot",
        "ExitActionRequired",
    ):
        assert f"$script:{name}" in script, f"exit code ${name} not defined"
    assert "Exit codes:" in script, "exit codes not documented in help"
    for code in EXIT_CODES:
        assert str(code) in script, f"exit code {code} not referenced"


def test_strict_mode_and_stop(script: str) -> None:
    assert "Set-StrictMode -Version Latest" in script
    assert '$ErrorActionPreference = "Stop"' in script


def test_security_prohibitions(script: str) -> None:
    lowered = script.lower()
    assert "set-executionpolicy unrestricted" not in lowered
    # "Invoke-Expression" may appear in prohibition *documentation* but never
    # as an executed command. Strip block comments (<#...#>) and # lines,
    # then forbid any use.
    no_block = re.sub(r"<#.*?#>", "", lowered, flags=re.DOTALL)
    code_lines = [line for line in no_block.splitlines() if not line.lstrip().startswith("#")]
    code = "\n".join(code_lines)
    assert "invoke-expression" not in code, "Invoke-Expression must not be used"
    assert not re.search(r"(?<![a-z-])iex(?![a-z-])", code), "iex alias must not be used"
    assert 'powershell.exe -c "[string]([text.encoding]' not in script
    # TLS must never be weakened: no ServerCertificateValidationCallback hacks.
    assert "servercertificatevalidationcallback" not in lowered
    assert "securityprotocoltype::ssl3" not in lowered
    # No Defender/SmartScreen/firewall weakening commands. (The words may
    # appear in prohibition *documentation*; only actual cmdlets count.)
    assert "set-mppreference" not in lowered
    assert "add-mppreference" not in lowered
    assert "exclusionpath" not in lowered
    assert "new-netfirewallrule" not in lowered
    assert "set-netfirewallprofile" not in lowered
    assert "uninstall-windowsfeature" not in lowered.replace("do not install or enable windows optional features", "")


def test_https_only_downloads(script: str) -> None:
    assert "http://localhost:11434" in script  # loopback probe only
    for m in re.finditer(r"https?://[^\s\"']+", script):
        url = m.group(0)
        if url.startswith("http://localhost") or url.startswith("http://127.0.0.1"):
            continue
        assert url.startswith("https://"), f"non-HTTPS URL: {url}"


def test_metadata_and_state_filenames(script: str) -> None:
    assert '".breachpilot-install.json"' in script
    assert '".breachpilot-install.state"' in script
    assert "braydos-h" in script and "BreachPilot" in script


def test_no_secrets_in_metadata_writer(script: str) -> None:
    m = re.search(r"function Write-InstallMetadata.*?\n\}", script, re.DOTALL)
    assert m, "Write-InstallMetadata not found"
    body = m.group(0)
    assert "Never store secrets here" in body
    for secret in ("GitHubToken", "OLLAMA_API_KEY", "BREACHPILOT_API_TOKEN"):
        assert secret not in body, f"secret {secret} must not enter metadata"


def test_pester_suite_exists_and_covers_contract() -> None:
    assert PESTER_SUITE.exists(), "tests/Test-InstallHelpers.ps1 missing"
    text = PESTER_SUITE.read_text(encoding="utf-8")
    for topic in (
        "Compare-SemVersion",
        "Select-GitHubRelease",
        "Test-ZipEntrySafe",
        "Join-NormalizedPath",
        "Test-PythonVersionSupported",
        "Node",
        "Test-InterruptedInstall",
        "Protect-SecretText",
        "Get-PropValue",
    ):
        assert topic in text, f"Pester suite missing coverage: {topic}"


def test_install_bat_is_wrapper_not_installer() -> None:
    bat = REPO_ROOT / "install.bat"
    assert bat.exists(), "install.bat missing"
    text = bat.read_text(encoding="utf-8", errors="replace")
    assert "install.ps1" in text, "install.bat must delegate to install.ps1"
    # A wrapper is small; the old ~770-line batch installer must be gone.
    assert len(text.splitlines()) < 150, (
        f"install.bat has {len(text.splitlines())} lines — it should be a thin "
        "wrapper, with install.ps1 the single source of truth"
    )
