@echo off
REM ============================================================================
REM  BreachPilot — Windows installer entry point (compatibility wrapper)
REM ============================================================================
REM  This file is a thin wrapper. The real installer is install.ps1, the ONE
REM  source of truth for Windows installation. This wrapper only:
REM    1. locates a usable PowerShell (Windows PowerShell 5.1 or PowerShell 7+)
REM    2. invokes install.ps1 with all arguments passed through untouched
REM    3. propagates its exit code
REM
REM  Usage: install.bat [any install.ps1 flags]
REM    install.bat                 interactive install (recommended)
REM    install.bat -Yes            non-interactive install
REM    install.bat -Check          read-only diagnostics, changes nothing
REM    install.bat -Update         safe upgrade preserving user data
REM    install.bat -Repair         repair without deleting user data
REM    install.bat -Uninstall      remove BreachPilot-owned components
REM    install.bat -Help           full installer help
REM
REM  install.ps1 -ExecutionPolicy Bypass applies to THIS process only; it does
REM  not change any system execution policy. To run install.ps1 directly:
REM    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Check
REM  Never pipe downloaded scripts to Invoke-Expression; download install.ps1,
REM  inspect it if desired, then execute it.
REM ============================================================================
setlocal

REM --- locate repo root (dir of this script) --------------------------------
set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"
if not exist "%REPO_ROOT%\install.ps1" (
    echo [FAIL] install.ps1 not found next to install.bat at %REPO_ROOT%
    echo        Re-download the BreachPilot release or clone:
    echo        https://github.com/braydos-h/BreachPilot
    exit /b 5
)

REM --- locate PowerShell: prefer pwsh 7+ when present, else Windows PowerShell
set "PS_EXE="
where pwsh >nul 2>&1 && set "PS_EXE=pwsh"
if not defined PS_EXE where powershell >nul 2>&1 && set "PS_EXE=powershell"
if not defined PS_EXE (
    echo [FAIL] No PowerShell found. BreachPilot requires Windows PowerShell 5.1+
    echo        (preinstalled on Windows 10/11) or PowerShell 7+ from:
    echo        https://aka.ms/powershell
    exit /b 3
)

REM --- invoke the real installer; -NoProfile -NonInteractive keep it clean.
REM     -ExecutionPolicy Bypass is process-scoped (this launch only).
"%PS_EXE%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%REPO_ROOT%\install.ps1" %*
set "INSTALL_RC=%ERRORLEVEL%"

endlocal & exit /b %INSTALL_RC%
