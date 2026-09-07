<#
.SYNOPSIS
    BreachPilot Windows installer/updater — production-grade, idempotent, upgrade-aware.

.DESCRIPTION
    Installs, updates, repairs, checks, or uninstalls BreachPilot on Windows 10/11
    (and Windows Server where practical) from the GitHub repository
    braydos-h/BreachPilot. Safe to re-run: every operation first answers
    "does this already exist and is it already correct?" before changing anything.

    ONE source of truth for Windows installation (install.bat is a thin wrapper
    that locates PowerShell and invokes this script, propagating the exit code).

    Default install scope is per-user: %LOCALAPPDATA%\BreachPilot. No Administrator
    rights required unless a machine-wide install is explicitly requested.

    Security posture: never disables Defender/SmartScreen/firewall, never weakens
    TLS validation, never sets Unrestricted execution policy, never Invoke-Expression
    on downloaded content, HTTPS only, official vendor/package-manager sources only.

.PARAMETER Yes
    Non-interactive mode. Auto-approves package-manager installs that would
    otherwise prompt. Required for unattended installs.

.PARAMETER Check
    Diagnostic report only. Makes ZERO machine changes (no installs, no downloads
    beyond read-only GitHub API/version probes, no PATH writes, no venv changes).

.PARAMETER Update
    Upgrade an existing installation to the resolved channel/version, preserving
    user data/config/secrets, with backup + rollback on critical failure.

.PARAMETER Repair
    Verify required files and repair launcher/venv/deps/WebUI/PATH without
    deleting user data.

.PARAMETER Uninstall
    Remove BreachPilot-owned components only (launcher, PATH entry, shortcuts,
    install dir when approved). Never uninstalls shared deps (Python/Node/Docker/
    Nmap/Ollama/Git).

.PARAMETER NoLaunch
    Do not offer to launch BreachPilot at the end (default in -Yes mode anyway).

.PARAMETER SkipWebUI
    Skip the WebUI npm build phase.

.PARAMETER SkipDocker
    Skip Docker/sandbox checks and image build. The resulting native-fallback
    execution mode is stated prominently, never silently.

.PARAMETER SkipOllama
    Skip Ollama detection/install/model-pull. Use when running a non-Ollama
    provider (e.g. models.provider: opencode_go with embeddings.provider: none).

.PARAMETER InstallDir
    Target installation directory. Default: $env:LOCALAPPDATA\BreachPilot.
    Must not point inside $env:TEMP.

.PARAMETER Version
    Install exactly this tag/version (e.g. v0.68.4 or 0.68.4). Verified to exist
    via the GitHub API; fails with exit code 5 if it does not.

.PARAMETER Channel
    Stable (newest non-draft non-prerelease release), Prerelease (newest non-draft
    release including prereleases), or Main (current default-branch HEAD SHA).
    Default: Stable. Ignored when -Version is supplied.

.PARAMETER Force
    Redo work that would otherwise be skipped as already-correct (re-download,
    rebuild WebUI, recreate venv, rebuild sandbox image).

.PARAMETER Offline
    Never access the network. Fails fast with a precise error if any step would
    require network access (version resolution beyond local metadata, downloads,
    package-manager installs, pip/npm pulls).

.PARAMETER GitHubToken
    Token for authenticated GitHub API requests (raises rate limit 60/hr to
    5000/hr). Also read from $env:GITHUB_TOKEN. Never printed or logged.

.PARAMETER LogPath
    Explicit installer log file path. Default:
    %LOCALAPPDATA%\BreachPilot\logs\installer-YYYYMMDD-HHMMSS.log

.PARAMETER NoPath
    Do not modify user PATH and do not install the bp/breachpilot launchers
    to a PATH directory (launchers are still written inside the install dir).

.PARAMETER KeepBackup
    Keep the pre-update backup directory even after a successful update
    (default: deleted after critical validation passes).

.EXAMPLE
    .\install.ps1
    Interactive fresh install to %LOCALAPPDATA%\BreachPilot.

.EXAMPLE
    .\install.ps1 -Yes
    Non-interactive install (auto-approves winget installs).

.EXAMPLE
    .\install.ps1 -Check
    Read-only diagnostic report; changes nothing.

.EXAMPLE
    .\install.ps1 -Update
    Safe in-place upgrade preserving config/secrets/data, with rollback.

.EXAMPLE
    .\install.ps1 -Repair
    Repair launcher/venv/deps/WebUI/PATH without deleting user data.

.EXAMPLE
    .\install.ps1 -Uninstall
    Remove BreachPilot-owned components (prompts before deleting user data).

.NOTES
    Exit codes:
      0  success
      1  installation failure (generic)
      2  invalid arguments (bad flag combo, bad version format, bad path)
      3  unsupported platform (OS/arch/PowerShell/TEMP/disk)
      4  dependency failure (Python unusable and could not be remediated)
      5  download/version-resolution failure (GitHub API, archive, pre-resolve)
      6  validation/integrity failure (ZIP traversal, missing files, SHA problems)
      7  doctor failed (critical health check after install/update/repair)
      8  update rolled back (update failed but previous install was restored)
      9  reboot/re-login required (Docker Desktop/WSL/PATH needs a new session)
      10 action required (provider key missing, optional component absent — install
         itself is sound but the operator must act; see final screen)

    Installer version: 1.0.0
    Repository truth this installer derives from (verified 2026-09-07):
      - Python >= 3.11, no upper bound (pyproject.toml requires-python; doctor
        rejects < 3.11; CI matrix 3.11-3.13). CI: .github/workflows/ci.yml
      - Canonical deps: pyproject.toml; install method: pip install -r
        requirements.txt (== pip install -e ".[ollama,dev]" per its header).
      - WebUI: webui/package.json (no engines field; docs/getting-started.md says
        Node 18+), lockfileVersion 3 present -> prefer `npm ci`, build
        `tsc -b && vite build` -> webui/dist/index.html.
      - Sandbox: image breachpilot-sandbox:latest via
        `docker build -t breachpilot-sandbox:latest docker/sandbox`
        (browser variant breachpilot-sandbox:browser from Dockerfile.browser).
        Code default is fail-closed (fallback_native: false in schema/models and
        shipped config.yaml); README stale `true` claim is NOT honored.
      - Ollama is OPTIONAL (one of ollama|opencode_go|chatgpt; lab config.yaml
        ships models.provider: opencode_go + embeddings.provider: none).
        Doctor probes only the active provider.
      - Nmap required for recon (doctor honors nmap.path else PATH).
      - Health: `<venv-python> main.py --doctor` (exit 0/1, --json supported);
        optional smoke: `<venv-python> main.py --self-test` (localhost only).
      - Secrets: secr.json (--setup-api-keys, gitignored), .env (gitignored, NOT
        auto-loaded), .webui_secret_key (api.token_file). Never overwritten.
      - Preserve on update: config.yaml, mission.yaml, secr.json, .env,
        .webui_secret_key, reports/, exploit_workspace/, research_workspace/,
        swarm_workspace/, *.db, *.log.
#>
[CmdletBinding()]
param(
    [switch]$Yes,
    [switch]$Check,
    [switch]$Update,
    [switch]$Repair,
    [switch]$Uninstall,
    [switch]$NoLaunch,
    [switch]$SkipWebUI,
    [switch]$SkipDocker,
    [switch]$SkipOllama,
    [string]$InstallDir = "",
    [string]$Version = "",
    [ValidateSet("Stable", "Prerelease", "Main")]
    [string]$Channel = "Stable",
    [switch]$Force,
    [switch]$Offline,
    [string]$GitHubToken = "",
    [string]$LogPath = "",
    [switch]$NoPath,
    [switch]$KeepBackup,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Captured at script scope: inside functions $MyInvocation describes the
# function, not the script, so every path reference below uses this.
$script:ScriptPath = $MyInvocation.MyCommand.Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$script:InstallerVersion = "1.0.0"
$script:SourceOwner = "braydos-h"
$script:SourceRepo = "BreachPilot"
$script:SourceFull = "$script:SourceOwner/$script:SourceRepo"
$script:GitHubApiBase = "https://api.github.com"
$script:GitHubRawBase = "https://raw.githubusercontent.com"
$script:UserAgent = "BreachPilot-Windows-Installer/1.0.0 (https://github.com/braydos-h/BreachPilot)"
$script:MetadataFileName = ".breachpilot-install.json"
$script:StateFileName = ".breachpilot-install.state"

# Exit codes (documented in .NOTES above).
$script:ExitSuccess = 0
$script:ExitFailure = 1
$script:ExitInvalidArgs = 2
$script:ExitUnsupported = 3
$script:ExitDependency = 4
$script:ExitDownload = 5
$script:ExitValidation = 6
$script:ExitDoctor = 7
$script:ExitRolledBack = 8
$script:ExitReboot = 9
$script:ExitActionRequired = 10

# Files that MUST exist in a valid source tree (validated after staging).
$script:RequiredSourceFiles = @(
    "main.py",
    "config.yaml",
    "pyproject.toml",
    "requirements.txt",
    "mcp_exploit_server.py",
    "mcp_server.py"
)

# User-generated / runtime state: preserved across update/repair, never blindly
# overwritten. Explicit per-item handling beats blanket Copy-Item.
$script:PreserveNames = @(
    "config.yaml",
    "mission.yaml",
    "secr.json",
    ".env",
    ".webui_secret_key",
    "reports",
    "exploit_workspace",
    "research_workspace",
    "swarm_workspace"
)

$script:SecretEnvNames = @(
    "OLLAMA_API_KEY",
    "OPENCODE_GO_API_KEY",
    "GITHUB_TOKEN",
    "NVD_API_KEY",
    "SERPAPI_API_KEY",
    "BREACHPILOT_API_TOKEN",
    "TICKETING_TOKEN",
    "CALDERA_API_KEY"
)

$script:SandboxImage = "breachpilot-sandbox:latest"
$script:SandboxDockerfile = "docker/sandbox/Dockerfile"
$script:MinPython = [Version]"3.11.0"
$script:MinNodeMajor = 18
$script:DefaultModelCloud = "glm-5.2:cloud"
$script:DefaultModelEmbed = "nomic-embed-text"

$script:LogFile = ""
$script:PhaseIndex = 0
$script:PhaseTotal = 12
$script:PhaseStart = [DateTime]::UtcNow
$script:HadWarning = $false
$script:ActionItems = New-Object System.Collections.ArrayList
$script:SupportsColor = $true

# ---------------------------------------------------------------------------
# Auth token resolution (env fallback). Never printed or logged (Protect-SecretText).
# ---------------------------------------------------------------------------
$script:GitHubTokenPlain = ""
if (-not [string]::IsNullOrWhiteSpace($GitHubToken)) {
    $script:GitHubTokenPlain = $GitHubToken.Trim()
} elseif (-not [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
    $script:GitHubTokenPlain = $env:GITHUB_TOKEN.Trim()
}

function Join-CommandArguments {
    param([string[]]$Arguments)
    $parts = New-Object System.Collections.ArrayList
    foreach ($a in $Arguments) {
        if ($null -eq $a) { $a = "" }
        if (($a -eq "") -or $a.Contains(" ") -or $a.Contains("`t") -or $a.Contains('"')) {
            $escaped = $a.Replace('"', '\"')
            $null = $parts.Add('"' + $escaped + '"')
        } else {
            $null = $parts.Add($a)
        }
    }
    return ($parts -join " ")
}

function Invoke-ExternalCommand {
    <#
    .SYNOPSIS
        Run a native executable with an argument ARRAY (never a shell string).
    .DESCRIPTION
        Captures stdout/stderr separately via async stream drains (no deadlock on
        large pip/npm output), enforces a timeout (kills on expiry), retains the
        exit code, redacts secrets in logs, and throws on unexpected exit codes
        unless -AllowFailure is given. Never uses Invoke-Expression.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 600,
        [switch]$AllowFailure,
        [switch]$StreamOutput,
        [string]$WorkingDirectory = ""
    )
    $argString = Join-CommandArguments -Arguments $Arguments
    $display = (Protect-SecretText "$Command $argString").Trim()
    Write-Log "RUN: $display (timeout ${TimeoutSeconds}s)" -Level "DEBUG"
    # Resolve via PATH/PATHEXT so bare names (npm, docker, git) map to their
    # real files. .cmd/.bat shims (npm!) cannot be CreateProcess'd directly
    # with UseShellExecute=false — wrap them in cmd.exe /d /s /c.
    $resolvedCmd = $Command
    try {
        $g = Get-Command $Command -ErrorAction SilentlyContinue
        if (($null -ne $g) -and (-not [string]::IsNullOrWhiteSpace($g.Source))) {
            $resolvedCmd = $g.Source
        }
    } catch { }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    if ($resolvedCmd -match "(?i)\.(cmd|bat)$") {
        $comspec = $env:ComSpec
        if ([string]::IsNullOrWhiteSpace($comspec)) { $comspec = "cmd.exe" }
        $psi.FileName = $comspec
        $psi.Arguments = '/d /s /c "' + '"' + $resolvedCmd + '" ' + $argString + '"'
    } else {
        $psi.FileName = $resolvedCmd
        $psi.Arguments = $argString
    }
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        if (-not (Test-Path -LiteralPath $WorkingDirectory)) {
            throw "NONRETRY: Working directory does not exist: $WorkingDirectory"
        }
        $psi.WorkingDirectory = $WorkingDirectory
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    try { $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
    try { $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8 } catch { }
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        try {
            $null = $proc.Start()
        } catch {
            throw "Failed to start '$Command': $($_.Exception.Message)"
        }
        # Start async drains BEFORE waiting: prevents pipe-buffer deadlock.
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        $ms = $TimeoutSeconds * 1000
        if ($ms -le 0) { $ms = 600000 }
        $exited = $proc.WaitForExit($ms)
        if (-not $exited) {
            try { $proc.Kill() } catch { }
            try { $proc.WaitForExit(5000) } catch { }
            throw "Command timed out after ${TimeoutSeconds}s: $display"
        }
        $proc.WaitForExit()
        try { $outText = $outTask.Result } catch { $outText = "" }
        try { $errText = $errTask.Result } catch { $errText = "" }
        if ($null -eq $outText) { $outText = "" }
        if ($null -eq $errText) { $errText = "" }
        $code = $proc.ExitCode
    } finally {
        try { $proc.Close() } catch { }
        try { $proc.Dispose() } catch { }
    }
    if ($StreamOutput) {
        if (-not [string]::IsNullOrWhiteSpace($outText)) { Write-Host $outText }
        if (-not [string]::IsNullOrWhiteSpace($errText)) { Write-Host $errText -ForegroundColor DarkGray }
    }
    Write-Log "EXIT ${code}: $display" -Level "DEBUG"
    if ($outText.Length -gt 0) {
        Write-Log ("stdout: " + $outText.Substring(0, [Math]::Min(4000, $outText.Length))) -Level "DEBUG"
    }
    if ($errText.Length -gt 0) {
        Write-Log ("stderr: " + $errText.Substring(0, [Math]::Min(4000, $errText.Length))) -Level "DEBUG"
    }
    $result = [pscustomobject]@{
        ExitCode = $code
        StdOut   = $outText.TrimEnd()
        StdErr   = $errText.TrimEnd()
        Command  = $display
    }
    if (($code -ne 0) -and (-not $AllowFailure)) {
        $tail = $errText.Trim()
        if ([string]::IsNullOrWhiteSpace($tail)) { $tail = $outText.Trim() }
        if ($tail.Length -gt 2000) { $tail = $tail.Substring($tail.Length - 2000) }
        throw "Command failed (exit $code): $display`n$tail"
    }
    return $result
}

function Test-TransientError {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $true }
    $m = $Message.ToLowerInvariant()
    $transient = @(
        "timed out", "timeout", "connection reset", "connection aborted",
        "connection was closed", "try again", "temporarily unavailable",
        "service unavailable", "bad gateway", "gateway timeout",
        "no such host is known", "name resolution", "could not resolve host",
        "network is unreachable", "operation timed out",
        " 429", "(429)", " 500", "(500)", " 502", "(502)", " 503", "(503)", " 504", "(504)",
        "rate limit", "secondary rate", "please retry", "econnreset", "econnaborted",
        "etimedout", "enotfound", "socket hang up", "tls handshake", "ssl connection"
    )
    foreach ($t in $transient) {
        if ($m.Contains($t)) { return $true }
    }
    return $false
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Script,
        [string]$Operation = "operation",
        [int]$MaxAttempts = 4,
        [int]$BaseDelaySeconds = 2
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return (& $Script)
        } catch {
            $msg = $_.Exception.Message
            $noRetry = ($msg -like "*NONRETRY*")
            if (($attempt -ge $MaxAttempts) -or (-not (Test-TransientError $msg)) -or $noRetry) {
                throw
            }
            $clean = Protect-SecretText $msg
            if ($clean.Length -gt 300) { $clean = $clean.Substring(0, 300) + "..." }
            $delay = $BaseDelaySeconds * [Math]::Pow(2, ($attempt - 1))
            $jitter = (Get-Random -Minimum 0 -Maximum 1000) / 1000.0
            $wait = [Math]::Round($delay + $jitter, 1)
            Write-Warn "$Operation failed (attempt $attempt/$MaxAttempts, appears transient): $clean"
            Write-Prog "Retrying in ${wait}s..."
            Start-Sleep -Seconds $wait
        }
    }
}

function Get-GitHubHeaders {
    $h = @{
        "User-Agent" = $script:UserAgent
        "Accept"     = "application/vnd.github+json"
    }
    if (-not [string]::IsNullOrWhiteSpace($script:GitHubTokenPlain)) {
        $h["Authorization"] = "Bearer $($script:GitHubTokenPlain)"
    }
    return $h
}

function Invoke-GitHubApi {
    <#
    .SYNOPSIS
        Authenticated-optional GitHub REST call with precise error mapping.
    .DESCRIPTION
        Throws errors prefixed NONRETRY for permanent failures (auth, 404,
        malformed JSON) so Invoke-WithRetry never spins on them. Rate-limit
        exhaustion (403 + X-RateLimit-Remaining: 0) throws a message carrying
        the reset time and a GITHUB_TOKEN hint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$TimeoutSeconds = 30
    )
    if ($Offline) {
        throw "NONRETRY: -Offline is set; refusing network access to api.github.com$Path."
    }
    $url = "$script:GitHubApiBase$Path"
    Write-Log "GitHub API: GET $url" -Level "DEBUG"
    try {
        $result = Invoke-RestMethod -Uri $url -Headers (Get-GitHubHeaders) -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        return $result
    } catch {
        $status = 0
        $remaining = ""
        $reset = ""
        try {
            $resp = $_.Exception.Response
            if ($null -ne $resp) {
                $status = [int]$resp.StatusCode
                try { $remaining = $resp.Headers["X-RateLimit-Remaining"] } catch { $remaining = "" }
                try { $reset = $resp.Headers["X-RateLimit-Reset"] } catch { $reset = "" }
            }
        } catch { }
        $body = ""
        try { $body = [string]$_.ErrorDetails.Message } catch { $body = "" }
        if ($body.Length -gt 500) { $body = $body.Substring(0, 500) }
        if ($status -eq 401) {
            throw "NONRETRY: GitHub API authentication failed (401) for $Path. The token is invalid or revoked; check GITHUB_TOKEN / -GitHubToken. Body: $body"
        }
        if ($status -eq 403 -and ($remaining -eq "0" -or $body -match "(?i)rate limit")) {
            $when = ""
            if ($reset -match "^\d+$") {
                try {
                    $epoch = [DateTimeOffset]::FromUnixTimeSeconds([long]$reset)
                    $when = " Rate limit resets at $($epoch.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))."
                } catch { $when = "" }
            }
            throw "NONRETRY: GitHub API rate limit exhausted (403) for $Path.$when Provide -GitHubToken (or set GITHUB_TOKEN) for 5000 req/hr instead of 60/hr, then re-run."
        }
        if ($status -eq 404) {
            throw "NONRETRY: GitHub API returned 404 for $Path. The tag/release/commit does not exist in $script:SourceFull (or was deleted)."
        }
        if ($status -eq 403) {
            throw "NONRETRY: GitHub API forbidden (403) for $Path. Body: $body"
        }
        # Transient (5xx, timeouts, DNS): let the retry wrapper decide.
        throw "GitHub API request failed for $Path`: $($_.Exception.Message) $body"
    }
}

function Resolve-BreachPilotVersion {
    <#
    .SYNOPSIS
        Resolve the exact desired BreachPilot version/commit for a channel or tag.
    .OUTPUTS
        PSCustomObject @{ Channel, Tag, Sha, PublishedAt, IsPrerelease, Name }.
        Tag is "" for Main-channel SHAs.
    #>
    [CmdletBinding()]
    param()
    $wanted = $Version.Trim()
    if (-not [string]::IsNullOrWhiteSpace($wanted)) {
        Write-Prog "Resolving explicit version '$wanted'..."
        $candidates = New-Object System.Collections.ArrayList
        $null = $candidates.Add($wanted)
        if ($wanted.StartsWith("v")) {
            $null = $candidates.Add($wanted.Substring(1))
        } else {
            $null = $candidates.Add("v$wanted")
        }
        foreach ($tag in $candidates) {
            try {
                $rel = Invoke-WithRetry -Operation "fetch release tag $tag" -Script {
                    Invoke-GitHubApi -Path "/repos/$script:SourceFull/releases/tags/$tag"
                }
                $commit = Invoke-WithRetry -Operation "resolve commit for tag $tag" -Script {
                    Invoke-GitHubApi -Path "/repos/$script:SourceFull/commits/$tag"
                }
                $sha = [string](Get-PropValue -Object $commit -Name "sha" -Default "")
                if ([string]::IsNullOrWhiteSpace($sha)) { throw "NONRETRY: GitHub returned an empty commit SHA for tag $tag." }
                Write-Ok "Resolved version $tag (commit $($sha.Substring(0, 12)))"
                return [pscustomobject]@{
                    Channel      = "Explicit"
                    Tag          = $tag
                    Sha          = $sha
                    PublishedAt  = [string](Get-PropValue -Object $rel -Name "published_at" -Default "")
                    IsPrerelease = [bool](Get-PropValue -Object $rel -Name "prerelease" -Default $false)
                    Name         = [string](Get-PropValue -Object $rel -Name "name" -Default "")
                }
            } catch {
                if ($_.Exception.Message -like "*NONRETRY*404*" -or $_.Exception.Message -like "*NONRETRY*404*") {
                    continue
                }
                if ($_.Exception.Message -like "*NONRETRY*") { throw }
                throw
            }
        }
        throw "NONRETRY: Version '$wanted' does not exist in $script:SourceFull (tried tags: $($candidates -join ', ')). List releases at https://github.com/$script:SourceFull/releases or use -Channel Stable|Prerelease|Main."
    }

    if ($Channel -eq "Main") {
        Write-Prog "Resolving default-branch HEAD for channel Main..."
        $repo = Invoke-WithRetry -Operation "fetch repository metadata" -Script {
            Invoke-GitHubApi -Path "/repos/$script:SourceFull"
        }
        $branch = [string](Get-PropValue -Object $repo -Name "default_branch" -Default "main")
        if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "main" }
        $commit = Invoke-WithRetry -Operation "fetch HEAD of $branch" -Script {
            Invoke-GitHubApi -Path "/repos/$script:SourceFull/commits/$branch"
        }
        $sha = [string](Get-PropValue -Object $commit -Name "sha" -Default "")
        if ([string]::IsNullOrWhiteSpace($sha)) { throw "NONRETRY: GitHub returned an empty HEAD SHA for branch $branch." }
        Write-Ok "Resolved Main HEAD $branch@$($sha.Substring(0, 12))"
        return [pscustomobject]@{
            Channel      = "Main"
            Tag          = ""
            Sha          = $sha
            PublishedAt  = ""
            IsPrerelease = $false
            Name         = "$branch@$($sha.Substring(0, 12))"
        }
    }

    $label = $Channel
    Write-Prog "Resolving latest $label release..."
    $releases = Invoke-WithRetry -Operation "list releases" -Script {
        Invoke-GitHubApi -Path "/repos/$script:SourceFull/releases?per_page=100"
    }
    if ($null -eq $releases) { $releases = @() }
    $usable = @($releases | Where-Object { $_ -ne $null -and (-not [bool](Get-PropValue -Object $_ -Name "draft" -Default $false)) } )
    if ($Channel -eq "Stable") {
        $usable = @($usable | Where-Object { $_ -ne $null -and (-not [bool](Get-PropValue -Object $_ -Name "prerelease" -Default $false)) })
    }
    if ($usable.Count -eq 0) {
        if ($Channel -eq "Stable") {
            throw "NONRETRY: No stable (non-draft, non-prerelease) release exists in $script:SourceFull. This is NOT silently substituted: re-run with -Channel Prerelease (newest prerelease/release) or -Channel Main (default-branch HEAD), or pin -Version to an existing tag. See https://github.com/$script:SourceFull/releases."
        }
        throw "NONRETRY: No releases at all (not even prereleases) exist in $script:SourceFull. Re-run with -Channel Main or pin -Version to an existing tag."
    }
    $best = $usable | Sort-Object -Property @{ Expression = { [string](Get-PropValue -Object $_ -Name "published_at" -Default "") } } -Descending | Select-Object -First 1
    $tag = [string](Get-PropValue -Object $best -Name "tag_name" -Default "")
    if ([string]::IsNullOrWhiteSpace($tag)) { throw "NONRETRY: GitHub returned a release with no tag_name." }
    $commit = Invoke-WithRetry -Operation "resolve commit for tag $tag" -Script {
        Invoke-GitHubApi -Path "/repos/$script:SourceFull/commits/$tag"
    }
    $sha = [string](Get-PropValue -Object $commit -Name "sha" -Default "")
    if ([string]::IsNullOrWhiteSpace($sha)) { throw "NONRETRY: GitHub returned an empty commit SHA for tag $tag." }
    $pre = ""
    if ([bool](Get-PropValue -Object $best -Name "prerelease" -Default $false)) { $pre = " (prerelease)" }
    Write-Ok "Resolved $label release $tag$pre (commit $($sha.Substring(0, 12)))"
    return [pscustomobject]@{
        Channel      = $label
        Tag          = $tag
        Sha          = $sha
        PublishedAt  = [string](Get-PropValue -Object $best -Name "published_at" -Default "")
        IsPrerelease = [bool](Get-PropValue -Object $best -Name "prerelease" -Default $false)
        Name         = [string](Get-PropValue -Object $best -Name "name" -Default "")
    }
}

function Get-ArchiveDownloadUrl {
    param([pscustomobject]$Resolved)
    if (-not [string]::IsNullOrWhiteSpace($Resolved.Tag)) {
        return "https://codeload.github.com/$script:SourceOwner/$script:SourceRepo/zip/refs/tags/$($Resolved.Tag)"
    }
    # SHA-pinned: never a moving target (Main channel resolved to an exact SHA above).
    return "https://codeload.github.com/$script:SourceOwner/$script:SourceRepo/zip/$($Resolved.Sha)"
}

function Get-BreachPilotArchive {
    <#
    .SYNOPSIS
        Download the exact resolved source archive with retries and validation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Resolved,
        [Parameter(Mandatory = $true)][string]$DestinationZip
    )
    if ($Offline) {
        throw "NONRETRY: -Offline is set; cannot download the BreachPilot source archive."
    }
    $url = Get-ArchiveDownloadUrl -Resolved $Resolved
    $label = $Resolved.Tag
    if ([string]::IsNullOrWhiteSpace($label)) { $label = $Resolved.Sha }
    Write-Prog "Downloading BreachPilot $label ..."
    Write-Log "Archive URL: $url" -Level "INFO"
    if (Test-Path -LiteralPath $DestinationZip) {
        try { Remove-Item -LiteralPath $DestinationZip -Force -ErrorAction Stop } catch { }
    }
    $downloaded = $false
    try {
        Invoke-WithRetry -Operation "download source archive" -MaxAttempts 4 -BaseDelaySeconds 3 -Script {
            $prev = $ProgressPreference
            try {
                $ProgressPreference = "Continue"
                Invoke-WebRequest -Uri $url -OutFile $DestinationZip -UseBasicParsing -TimeoutSec 300 `
                    -Headers @{ "User-Agent" = $script:UserAgent } -ErrorAction Stop
            } finally {
                $ProgressPreference = $prev
            }
            $fi = Get-Item -LiteralPath $DestinationZip -ErrorAction Stop
            if ($fi.Length -lt 200KB) {
                throw "Downloaded archive is suspiciously small ($($fi.Length) bytes); expected the full repository tree. NONRETRY-marker-removed-below"
            }
        }
        $downloaded = $true
    } catch {
        $m = $_.Exception.Message -replace " NONRETRY-marker-removed-below", ""
        if ($m -like "*suspiciously small*") { throw "NONRETRY: $m The release asset may have been deleted; try -Channel Main or another -Version." }
        throw
    } finally {
        if (-not $downloaded -and (Test-Path -LiteralPath $DestinationZip)) {
            try { Remove-Item -LiteralPath $DestinationZip -Force } catch { }
            Write-Log "Removed partial download: $DestinationZip" -Level "INFO"
        }
    }
    $fi = Get-Item -LiteralPath $DestinationZip
    if (-not $fi.Exists -or $fi.Length -le 0) {
        throw "NONRETRY: Download produced no usable file at $DestinationZip (HTTP status was not 2xx or the connection dropped)."
    }
    $hash = (Get-FileHash -LiteralPath $DestinationZip -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Ok ("Downloaded {0:N1} MB (SHA-256: {1})" -f ($fi.Length / 1MB), $hash)
    Write-Log "Archive SHA-256: $hash SizeBytes=$($fi.Length)" -Level "INFO"
    Confirm-ReleaseChecksum -Resolved $Resolved -ArchiveSha256 $hash
    return $hash
}

function Confirm-ReleaseChecksum {
    param(
        [pscustomobject]$Resolved,
        [string]$ArchiveSha256
    )
    # A locally calculated SHA-256 is NOT proof of authenticity on its own.
    # If the release publishes an official checksum asset, verify against it;
    # otherwise say so plainly and record the calculated hash for diagnostics.
    if ([string]::IsNullOrWhiteSpace($Resolved.Tag)) {
        Write-Log "No release tag (Main-channel SHA); checksum verification = HTTPS + resolved repo/commit identity; calculated SHA-256 recorded." -Level "INFO"
        Write-Skip "No official checksum published for a branch SHA; trusting HTTPS + resolved $script:SourceFull@$($Resolved.Sha.Substring(0, 12)) (hash recorded in metadata)."
        return
    }
    try {
        $rel = Invoke-GitHubApi -Path "/repos/$script:SourceFull/releases/tags/$($Resolved.Tag)"
    } catch {
        Write-Log "Could not list release assets for checksum search: $($_.Exception.Message)" -Level "WARN"
        Write-Skip "Could not list release assets; trusting HTTPS + resolved tag $($Resolved.Tag) (hash recorded in metadata)."
        return
    }
    $assets = @()
    $__assetsRaw = Get-PropValue -Object $rel -Name "assets" -Default $null
    if ($null -ne $__assetsRaw) { $assets = @($__assetsRaw) }
    $sumAsset = $assets | Where-Object { $_ -ne $null -and ([string](Get-PropValue -Object $_ -Name "name" -Default "") -match "(?i)(sha256|sha-256|checksum)") } | Select-Object -First 1
    if ($null -eq $sumAsset) {
        Write-Skip "Release $($Resolved.Tag) publishes no checksum asset; trusting HTTPS + resolved tag identity (SHA-256 recorded in metadata for diagnostics)."
        Write-Log "No checksum asset on release $($Resolved.Tag); calculated SHA-256 recorded." -Level "INFO"
        return
    }
    Write-Prog "Verifying against official checksum asset '$(Get-PropValue -Object $sumAsset -Name "name" -Default "?")'..."
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("bp-checksum-" + [guid]::NewGuid().ToString("N") + ".txt")
    try {
        Invoke-WithRetry -Operation "download checksum asset" -Script {
            Invoke-WebRequest -Uri ([string](Get-PropValue -Object $sumAsset -Name "browser_download_url" -Default "")) -OutFile $tmp -UseBasicParsing `
                -TimeoutSec 60 -Headers @{ "User-Agent" = $script:UserAgent } -ErrorAction Stop
        }
        $archiveName = "codeload-$($Resolved.Tag).zip"
        $matched = $false
        $wanted = ""
        foreach ($line in (Get-Content -LiteralPath $tmp -ErrorAction Stop)) {
            # Formats: "<hash>  <file>" (sha256sum) or "<hash>" alone or "SHA256 (<file>) = <hash>" (BSD).
            $h = ""
            if ($line -match "([A-Fa-f0-9]{64})") { $h = $Matches[1].ToLowerInvariant() }
            if ([string]::IsNullOrWhiteSpace($h)) { continue }
            if ($line -match "(?i)(zip|tar\.gz)") { $wanted = $h; $matched = $true; break }
            if ([string]::IsNullOrWhiteSpace($wanted)) { $wanted = $h }
        }
        if ([string]::IsNullOrWhiteSpace($wanted)) {
            Write-Skip "Checksum asset '$(Get-PropValue -Object $sumAsset -Name "name" -Default "?")' had no parseable SHA-256; trusting HTTPS + tag identity (hash recorded)."
            return
        }
        if ($wanted -ne $ArchiveSha256) {
            throw "NONRETRY: Official checksum mismatch for $($Resolved.Tag): archive SHA-256 $ArchiveSha256 != published $wanted. Deleted partial state; refusing to install."
        }
        if ($matched) { Write-Ok "Official checksum verified ($(Get-PropValue -Object $sumAsset -Name "name" -Default "?"))." }
        else { Write-Skip "Checksum asset has a single hash; matches download ($ArchiveSha256). Treated as verified." }
    } finally {
        if (Test-Path -LiteralPath $tmp) { try { Remove-Item -LiteralPath $tmp -Force } catch { } }
    }
}

function Test-ZipEntrySafe {
    param([string]$EntryName, [string]$StagingRoot)
    if ([string]::IsNullOrWhiteSpace($EntryName)) { return $false }
    $n = $EntryName.Replace("\", "/")
    if ([System.IO.Path]::IsPathRooted($n)) { return $false }
    if ($n -match "^[A-Za-z]:") { return $false }
    $parts = $n -split "/"
    foreach ($p in $parts) {
        if ($p -eq "..") { return $false }
    }
    try {
        $combined = [System.IO.Path]::GetFullPath((Join-Path $StagingRoot $n))
        $root = [System.IO.Path]::GetFullPath($StagingRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
        if (($combined -ne $root) -and (-not $combined.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar))) {
            return $false
        }
    } catch {
        return $false
    }
    return $true
}

function Expand-ValidatedArchive {
    <#
    .SYNOPSIS
        Validate ZIP structure + traversal-guard every entry, then extract.
    .OUTPUTS
        The extracted repository root (handles the single top-level dir layout).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$StagingDir
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = $null
    try {
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        } catch {
            throw "NONRETRY: Downloaded file is not a valid ZIP archive ($($_.Exception.Message)). The download may be an error page; deleted partial state."
        }
        $entries = @($zip.Entries)
        if ($entries.Count -eq 0) {
            throw "NONRETRY: Archive is empty; refusing to install."
        }
        foreach ($e in $entries) {
            if (-not (Test-ZipEntrySafe -EntryName $e.FullName -StagingRoot $StagingDir)) {
                throw "NONRETRY: Archive rejected: entry '$($e.FullName)' escapes the staging directory (path traversal). Refusing to install."
            }
        }
        Write-Log "Archive validated: $($entries.Count) entries, no traversal." -Level "INFO"
        foreach ($e in $entries) {
            $dest = [System.IO.Path]::GetFullPath((Join-Path $StagingDir ($e.FullName.Replace("/", [System.IO.Path]::DirectorySeparatorChar))))
            if ($e.FullName.EndsWith("/")) {
                if (-not (Test-Path -LiteralPath $dest)) {
                    New-Item -ItemType Directory -Path $dest -Force | Out-Null
                }
            } else {
                $parent = Split-Path -Parent $dest
                if (-not (Test-Path -LiteralPath $parent)) {
                    New-Item -ItemType Directory -Path $parent -Force | Out-Null
                }
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dest, $true)
            }
        }
    } finally {
        if ($null -ne $zip) { try { $zip.Dispose() } catch { } }
    }
    # GitHub codeload zips nest everything under one top-level dir.
    $root = $StagingDir
    $topDirs = @(Get-ChildItem -LiteralPath $StagingDir -Directory -ErrorAction SilentlyContinue)
    $topFiles = @(Get-ChildItem -LiteralPath $StagingDir -File -ErrorAction SilentlyContinue)
    if (($topFiles.Count -eq 0) -and ($topDirs.Count -eq 1)) {
        $root = $topDirs[0].FullName
    }
    foreach ($req in $script:RequiredSourceFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $req))) {
            throw "NONRETRY: Extracted tree is not a BreachPilot source tree: missing '$req' under $root."
        }
    }
    Write-Ok "Package validated ($($script:RequiredSourceFiles.Count) required files present)."
    return $root
}

# ---------------------------------------------------------------------------
# Pure helpers (no side effects — covered by Pester tests in tests/Test-*.ps1)
# ---------------------------------------------------------------------------

function Compare-SemVersion {
    <#
    .SYNOPSIS
        Compare two version strings. Returns -1, 0, or 1.
    .DESCRIPTION
        Tolerates a leading 'v', missing minor/patch (treated as 0), and a
        trailing pre-release/build suffix ('-beta', '+build'). Numeric parts
        compare numerically; a release beats its own prerelease
        ('1.2.3' -gt '1.2.3-beta'). Non-numeric garbage returns $null.
    #>
    param([string]$A, [string]$B)
    $parse = {
        param([string]$V)
        $s = $V.Trim()
        if ($s.StartsWith("v") -or $s.StartsWith("V")) { $s = $s.Substring(1) }
        $pre = ""
        $m = [regex]::Match($s, "^(?<core>[0-9][0-9A-Za-z.\s]*?)(?<suffix>[-+].*)?$")
        if (-not $m.Success) { return $null }
        $core = $m.Groups["core"].Value.Trim()
        $suffix = $m.Groups["suffix"].Value
        $nums = @()
        foreach ($tok in ($core -split "\.")) {
            $t = $tok.Trim()
            if ($t -notmatch "^\d+$") { return $null }
            $nums += [long]$t
        }
        while ($nums.Count -lt 3) { $nums += [long]0 }
        return @{ Nums = $nums; Pre = $suffix }
    }
    $pa = & $parse $A
    $pb = & $parse $B
    if ($null -eq $pa -or $null -eq $pb) { return $null }
    for ($i = 0; $i -lt 3; $i++) {
        if ($pa.Nums[$i] -lt $pb.Nums[$i]) { return -1 }
        if ($pa.Nums[$i] -gt $pb.Nums[$i]) { return 1 }
    }
    $aPre = -not [string]::IsNullOrEmpty($pa.Pre)
    $bPre = -not [string]::IsNullOrEmpty($pb.Pre)
    if ($aPre -and -not $bPre) { return -1 }
    if ($bPre -and -not $aPre) { return 1 }
    return [string]::Compare([string]$pa.Pre, [string]$pb.Pre, [StringComparison]::OrdinalIgnoreCase)
}

function Select-GitHubRelease {
    <#
    .SYNOPSIS
        Pick the newest release for a channel from GitHub API release objects.
    .DESCRIPTION
        Stable: newest non-draft, non-prerelease. Prerelease: newest non-draft
        (prereleases included). Drafts never selected; deleted releases never
        appear in the API list. Returns $null when nothing qualifies.
    #>
    param(
        [array]$Releases,
        [ValidateSet("Stable", "Prerelease")][string]$WantedChannel = "Stable"
    )
    if ($null -eq $Releases) { return $null }
    $usable = @($Releases | Where-Object { $_ -ne $null -and (-not [bool](Get-PropValue -Object $_ -Name "draft" -Default $false)) })
    if ($WantedChannel -eq "Stable") {
        $usable = @($usable | Where-Object { $_ -ne $null -and (-not [bool](Get-PropValue -Object $_ -Name "prerelease" -Default $false)) })
    }
    if ($usable.Count -eq 0) { return $null }
    return ($usable | Sort-Object -Property @{ Expression = { [string](Get-PropValue -Object $_ -Name "published_at" -Default "") } } -Descending | Select-Object -First 1)
}

function Test-PythonVersionSupported {
    <#
    .SYNOPSIS
        True when a `python --version`-style string is >= 3.11.
    #>
    param([string]$VersionText)
    if ([string]::IsNullOrWhiteSpace($VersionText)) { return $false }
    $m = [regex]::Match($VersionText, "(\d+)\.(\d+)(?:\.(\d+))?")
    if (-not $m.Success) { return $false }
    try {
        $v = New-Object Version([int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$(if ($m.Groups[3].Success) { $m.Groups[3].Value } else { "0" }))
        return ($v -ge $script:MinPython)
    } catch {
        return $false
    }
}

function Get-NodeMajorVersion {
    <#
    .SYNOPSIS
        Parse `node --version` output ('v22.11.0') to its major number, else -1.
    #>
    param([string]$VersionText)
    if ([string]::IsNullOrWhiteSpace($VersionText)) { return -1 }
    $m = [regex]::Match($VersionText.Trim(), "v?(\d+)\.(\d+)\.(\d+)")
    if (-not $m.Success) { return -1 }
    return [int]$m.Groups[1].Value
}

function Test-NodeVersionSupported {
    param([string]$VersionText)
    return ((Get-NodeMajorVersion -VersionText $VersionText) -ge $script:MinNodeMajor)
}

function Join-NormalizedPath {
    <#
    .SYNOPSIS
        Case-insensitive PATH dedup: append $Entry unless already present.
    .OUTPUTS
        @{ Path = <new PATH string>; Changed = <bool> } ($null on oversize).
    .DESCRIPTION
        Normalizes trailing backslashes, compares case-insensitively (Windows
        PATH semantics), preserves existing entries byte-for-byte, refuses to
        grow PATH past 32767 chars (Windows environment-size sanity).
    #>
    param([string]$CurrentPath, [string]$Entry)
    $clean = $Entry.Trim().TrimEnd("\")
    if ([string]::IsNullOrWhiteSpace($clean)) { return @{ Path = $CurrentPath; Changed = $false } }
    $existing = @()
    if (-not [string]::IsNullOrWhiteSpace($CurrentPath)) {
        $existing = @($CurrentPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    foreach ($e in $existing) {
        if ($e.Trim().TrimEnd("\").Equals($clean, [StringComparison]::OrdinalIgnoreCase)) {
            return @{ Path = ($existing -join ";"); Changed = $false }
        }
    }
    $joined = (($existing + @($clean)) -join ";")
    if ($joined.Length -gt 32767) { return $null }
    return @{ Path = $joined; Changed = $true }
}

function Test-GitRemoteMatches {
    <#
    .SYNOPSIS
        True when a `git remote -v`-style origin URL belongs to braydos-h/BreachPilot.
    #>
    param([string]$RemoteUrl)
    if ([string]::IsNullOrWhiteSpace($RemoteUrl)) { return $false }
    $u = $RemoteUrl.Trim()
    return ($u -match "(?i)github\.com[:/]braydos-h/BreachPilot(\.git)?\s*(\(fetch\))?\s*$")
}

# ---------------------------------------------------------------------------
# Platform / environment detection (read-only)
# ---------------------------------------------------------------------------

function Get-PlatformInfo {
    $info = [ordered]@{
        OSVersion        = ""
        OSBuild          = ""
        Architecture     = ""
        PSEdition        = ""
        PSVersion        = ""
        User             = ""
        IsAdmin          = $false
        IsRemote         = $false
        TempWritable     = $false
        FreeDiskGB       = -1
        GitHubReachable  = $false
        WingetPresent    = $false
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $info.OSVersion = [string]$os.Caption
        $info.OSBuild = [string]$os.BuildNumber
    } catch {
        try {
            $info.OSVersion = [string](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop).ProductName
            $info.OSBuild = [string](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop).CurrentBuildNumber
        } catch {
            $info.OSVersion = [string][Environment]::OSVersion
        }
    }
    try {
        if ([Environment]::Is64BitOperatingSystem) {
            $arch = (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1).Architecture
            # 9 = x64, 12 = ARM64 per Win32_Processor.Architecture.
            if ($arch -eq 12 -or $env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $info.Architecture = "ARM64" }
            else { $info.Architecture = "x64" }
        } else {
            $info.Architecture = "x86"
        }
    } catch {
        $info.Architecture = $env:PROCESSOR_ARCHITECTURE
    }
    try { $info.PSEdition = $PSVersionTable.PSEdition } catch { $info.PSEdition = "Desktop" }
    try { $info.PSVersion = [string]$PSVersionTable.PSVersion } catch { $info.PSVersion = "unknown" }
    try { $info.User = [string][Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $info.User = $env:USERNAME }
    $info.IsAdmin = Test-IsAdministrator
    if (-not [string]::IsNullOrWhiteSpace($env:SSH_CONNECTION) -or -not [string]::IsNullOrWhiteSpace($env:SSH_CLIENT)) {
        $info.IsRemote = $true
    }
    try {
        if ($null -ne $PSSenderInfo) { $info.IsRemote = $true }
    } catch { }
    try {
        $probe = Join-Path ([System.IO.Path]::GetTempPath()) ("bp-write-test-" + [guid]::NewGuid().ToString("N") + ".tmp")
        [System.IO.File]::WriteAllText($probe, "ok")
        Remove-Item -LiteralPath $probe -Force
        $info.TempWritable = $true
    } catch {
        $info.TempWritable = $false
    }
    $info.WingetPresent = ($null -ne (Get-Command winget -ErrorAction SilentlyContinue))
    return [pscustomobject]$info
}

function Test-PlatformSupported {
    param([pscustomobject]$Platform)
    # Windows 10+ == build >= 10240. Anything older cannot be supported.
    $build = 0
    if (-not [int]::TryParse([string]$Platform.OSBuild, [ref]$build)) { $build = 0 }
    if ($build -ne 0 -and $build -lt 10240) {
        Write-Fail "Unsupported Windows build $($Platform.OSBuild): BreachPilot requires Windows 10 or later."
        return $false
    }
    if ($Platform.Architecture -eq "x86") {
        Write-Fail "32-bit Windows (x86) is not supported: Python/Node/Docker vendors no longer ship x86 builds."
        return $false
    }
    if (-not $Platform.TempWritable) {
        Write-Fail "TEMP directory is not writable ($([System.IO.Path]::GetTempPath())). Downloads and staging cannot proceed."
        return $false
    }
    return $true
}

function Get-InstallDriveFreeGB {
    param([string]$Path)
    try {
        $root = [System.IO.Path]::GetPathRoot((Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path)
        if ([string]::IsNullOrWhiteSpace($root)) { $root = [System.IO.Path]::GetPathRoot($Path) }
        $drive = New-Object System.IO.DriveInfo($root)
        if ($drive.IsReady) {
            return [math]::Round($drive.AvailableFreeSpace / 1GB, 1)
        }
    } catch { }
    return -1
}

function Test-NetworkConnectivity {
    # Lightweight HTTPS probe (no version logic): api.github.com over TLS.
    # Never disables certificate validation; honors -Offline by skipping.
    if ($Offline) { return $false }
    try {
        $prev = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        try {
            $r = Invoke-WebRequest -Uri "https://api.github.com/rate_limit" -UseBasicParsing -TimeoutSec 15 `
                -Headers @{ "User-Agent" = $script:UserAgent } -ErrorAction Stop
            return ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500)
        } finally {
            $ProgressPreference = $prev
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -like "*401*" -or $msg -like "*403*" -or $msg -like "*429*") { return $true }
        Write-Log "Connectivity probe failed: $msg" -Level "WARN"
        return $false
    }
}

function Resolve-InstallDir {
    param([string]$Requested, [string]$ScriptRoot)
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        $full = $Requested.Trim()
        try { $full = [System.IO.Path]::GetFullPath($full) } catch {
            Write-Fail "Invalid -InstallDir '$Requested': not a valid Windows path."
            exit $script:ExitInvalidArgs
        }
        try {
            $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd("\") + "\"
            if (($full.TrimEnd("\") + "\").StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
                Write-Fail "-InstallDir must not point inside TEMP ($tempRoot): staged archives extract there during install."
                exit $script:ExitInvalidArgs
            }
        } catch { }
        return $full
    }
    # Running from inside an existing BreachPilot checkout? Install there —
    # the operator already chose that location (never move their repo).
    if (-not [string]::IsNullOrWhiteSpace($ScriptRoot)) {
        $probe = Join-Path $ScriptRoot "main.py"
        $cfg = Join-Path $ScriptRoot "config.yaml"
        if ((Test-Path -LiteralPath $probe) -and (Test-Path -LiteralPath $cfg)) {
            Write-Log "Script is running from an existing checkout; using it as InstallDir: $ScriptRoot" -Level "INFO"
            return ([System.IO.Path]::GetFullPath($ScriptRoot))
        }
    }
    $base = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($base)) {
        Write-Fail "LOCALAPPDATA is not set and no -InstallDir was given; cannot choose a per-user install path."
        exit $script:ExitUnsupported
    }
    return (Join-Path $base "BreachPilot")
}

function Get-CheckoutStatus {
    <#
    .SYNOPSIS
        Inspect a directory for a Git checkout and report remote/branch/commit/dirt.
    .DESCRIPTION
        Read-only. Never runs reset/clean/checkout. Returns $null when $Dir is
        not a git working tree or git is unavailable.
    #>
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir)) { return $null }
    if (-not (Test-Path -LiteralPath (Join-Path $Dir ".git"))) { return $null }
    if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ IsGit = $true; GitAvailable = $false }
    }
    try {
        $origin = (Invoke-ExternalCommand -Command "git" -Arguments @("-C", $Dir, "remote", "get-url", "origin") -TimeoutSeconds 15 -AllowFailure).StdOut.Trim()
        $branch = (Invoke-ExternalCommand -Command "git" -Arguments @("-C", $Dir, "rev-parse", "--abbrev-ref", "HEAD") -TimeoutSeconds 15 -AllowFailure).StdOut.Trim()
        $sha = (Invoke-ExternalCommand -Command "git" -Arguments @("-C", $Dir, "rev-parse", "HEAD") -TimeoutSeconds 15 -AllowFailure).StdOut.Trim()
        $status = (Invoke-ExternalCommand -Command "git" -Arguments @("-C", $Dir, "status", "--porcelain") -TimeoutSeconds 30 -AllowFailure).StdOut.Trim()
        return [pscustomobject]@{
            IsGit          = $true
            GitAvailable   = $true
            Origin         = $origin
            OriginMatches  = (Test-GitRemoteMatches -RemoteUrl $origin)
            Branch         = $branch
            Sha            = $sha
            IsDirty        = (-not [string]::IsNullOrWhiteSpace($status))
            UntrackedHint  = $status
        }
    } catch {
        Write-Log "Get-CheckoutStatus failed for $Dir`: $($_.Exception.Message)" -Level "WARN"
        return [pscustomobject]@{ IsGit = $true; GitAvailable = $true }
    }
}

function Test-CheckoutSafe {
    <#
    .SYNOPSIS
        Decide whether an update may touch a git checkout (never destructive).
    #>
    param([pscustomobject]$Checkout)
    if ($null -eq $Checkout) { return @{ Safe = $true; Reason = "not a git checkout" } }
    if (-not [bool](Get-PropValue -Object $Checkout -Name "IsGit" -Default $false)) { return @{ Safe = $true; Reason = "not a git checkout" } }
    if (-not [bool](Get-PropValue -Object $Checkout -Name "GitAvailable" -Default $false)) { return @{ Safe = $true; Reason = "git unavailable; treating as plain directory" } }
    $__coOriginM = [string](Get-PropValue -Object $Checkout -Name "Origin" -Default "")
    $__coMatch = [bool](Get-PropValue -Object $Checkout -Name "OriginMatches" -Default $false)
    if (-not $__coMatch) {
        return @{ Safe = $false; Reason = "directory is a git checkout whose origin ('$__coOriginM') is NOT $script:SourceFull. Refusing to touch a foreign repository — choose a different -InstallDir." }
    }
    $__coBr = [string](Get-PropValue -Object $Checkout -Name "Branch" -Default "?")
    $__coSh = [string](Get-PropValue -Object $Checkout -Name "Sha" -Default "?")
    if ([bool](Get-PropValue -Object $Checkout -Name "IsDirty" -Default $false)) {
        return @{ Safe = $false; Reason = "git checkout has uncommitted changes (branch $__coBr, $__coSh). Commit or stash them first, or re-run with -Force to update anyway (a backup is still taken; `git reset --hard` / `git clean -fdx` are NEVER run automatically)." }
    }
    return @{ Safe = $true; Reason = "clean checkout of $script:SourceFull ($__coBr@$__coSh)" }
}

# ---------------------------------------------------------------------------
# Install metadata + installer state machine
# ---------------------------------------------------------------------------

function Read-InstallMetadata {
    param([string]$InstallDir)
    $path = Join-Path $InstallDir $script:MetadataFileName
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
        $obj = $raw | ConvertFrom-Json
        return $obj
    } catch {
        Write-Log "Install metadata at $path is corrupt: $($_.Exception.Message)" -Level "WARN"
        return [pscustomobject]@{ Corrupt = $true; Path = $path }
    }
}

function Write-InstallMetadata {
    param(
        [string]$InstallDir,
        [pscustomobject]$Resolved,
        [string]$ArchiveSha256,
        [string]$LauncherKind
    )
    $path = Join-Path $InstallDir $script:MetadataFileName
    # Never store secrets here (tokens live in env / secr.json / .webui_secret_key).
    $obj = [ordered]@{
        repository        = $script:SourceFull
        channel           = $Resolved.Channel
        tag               = $Resolved.Tag
        commit            = $Resolved.Sha
        installed_at      = (Get-Date).ToUniversalTime().ToString("o")
        installer_version = $script:InstallerVersion
        archive_sha256    = $ArchiveSha256
        launcher          = $LauncherKind
        install_dir       = $InstallDir
    }
    $json = ($obj | ConvertTo-Json -Depth 4)
    $tmp = "$path.tmp"
    try {
        Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -NoNewline:$false
        Move-Item -LiteralPath $tmp -Destination $path -Force
        Write-Log "Wrote install metadata: channel=$($Resolved.Channel) tag=$($Resolved.Tag) commit=$($Resolved.Sha)" -Level "INFO"
    } catch {
        if (Test-Path -LiteralPath $tmp) { try { Remove-Item -LiteralPath $tmp -Force } catch { } }
        throw "Failed to write install metadata to $path`: $($_.Exception.Message)"
    }
}

function Read-InstallState {
    param([string]$InstallDir)
    $path = Join-Path $InstallDir $script:StateFileName
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        Write-Log "Install state file corrupt; ignoring: $path" -Level "WARN"
        return $null
    }
}

function Write-InstallState {
    param([string]$InstallDir, [string]$State)
    $path = Join-Path $InstallDir $script:StateFileName
    try {
        $obj = [ordered]@{ state = $State; updated_at = (Get-Date).ToUniversalTime().ToString("o") }
        Set-Content -LiteralPath $path -Value ($obj | ConvertTo-Json) -Encoding UTF8
        Write-Log "Install state -> $State" -Level "INFO"
    } catch {
        Write-Log "Could not persist install state ($State): $($_.Exception.Message)" -Level "WARN"
    }
}

function Clear-InstallState {
    param([string]$InstallDir)
    $path = Join-Path $InstallDir $script:StateFileName
    if (Test-Path -LiteralPath $path) { try { Remove-Item -LiteralPath $path -Force } catch { } }
}

function Test-InterruptedInstall {
    <#
    .SYNOPSIS
        Detect an unfinished previous run and decide how to recover.
    .OUTPUTS
        @{ Interrupted = <bool>; State = <string>; BackupDir = <string> }.
    #>
    param([string]$InstallDir)
    $st = Read-InstallState -InstallDir $InstallDir
    $__stState = [string](Get-PropValue -Object $st -Name "state" -Default "")
    if ($null -eq $st -or [string]::IsNullOrWhiteSpace($__stState)) {
        return @{ Interrupted = $false; State = "none"; BackupDir = "" }
    }
    $state = [string](Get-PropValue -Object $st -Name "state" -Default "")
    if ($state -eq "completed") {
        return @{ Interrupted = $false; State = $state; BackupDir = "" }
    }
    # Any non-completed persisted state means the last run did not finish.
    $backupDir = ""
    $__stBackup = [string](Get-PropValue -Object $st -Name "backup_dir" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($__stBackup)) {
        $backupDir = $__stBackup
    }
    return @{ Interrupted = $true; State = $state; BackupDir = $backupDir }
}

# ---------------------------------------------------------------------------
# Backup / restore / atomic deploy
# ---------------------------------------------------------------------------

function Backup-BreachPilotInstall {
    <#
    .SYNOPSIS
        Copy the live install (minus venv/caches/build output) to a timestamped backup.
    .OUTPUTS
        Backup directory path, or "" when there is nothing to back up.
    #>
    param([string]$InstallDir)
    if (-not (Test-Path -LiteralPath $InstallDir)) { return "" }
    $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $parent = Split-Path -Parent $InstallDir
    $leaf = Split-Path -Leaf $InstallDir
    $backup = Join-Path $parent "$leaf.backup-$stamp"
    Write-Prog "Backing up existing installation to $backup ..."
    $exclude = @(".venv", "venv", "__pycache__", ".git", "node_modules", "webui\node_modules", "webui\dist", ".mypy_cache", ".ruff_cache", ".pytest_cache")
    try {
        New-Item -ItemType Directory -Path $backup -Force | Out-Null
        $items = Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction Stop
        foreach ($item in $items) {
            if ($exclude -contains $item.Name) { continue }
            $rel = $item.Name
            if (($InstallDir + "\webui") -eq $item.FullName) {
                # webui: copy everything except node_modules/dist.
                $destWeb = Join-Path $backup "webui"
                New-Item -ItemType Directory -Path $destWeb -Force | Out-Null
                foreach ($w in (Get-ChildItem -LiteralPath $item.FullName -Force)) {
                    if ($exclude -contains $w.Name) { continue }
                    Copy-Item -LiteralPath $w.FullName -Destination (Join-Path $destWeb $w.Name) -Recurse -Force
                }
                continue
            }
            Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $backup $rel) -Recurse -Force
        }
        Write-Ok "Backup created: $backup"
        Write-Log "Backup created at $backup" -Level "INFO"
        return $backup
    } catch {
        throw "Failed to back up $InstallDir to $backup`: $($_.Exception.Message)"
    }
}

function Restore-BreachPilotInstall {
    param([string]$InstallDir, [string]$BackupDir)
    if ([string]::IsNullOrWhiteSpace($BackupDir) -or -not (Test-Path -LiteralPath $BackupDir)) {
        throw "NONRETRY: Cannot roll back: backup directory '$BackupDir' is missing."
    }
    Write-Prog "Rolling back: restoring $BackupDir -> $InstallDir ..."
    # Remove the failed new tree (but keep the backup itself, which lives beside it).
    $failedStaging = Join-Path ([System.IO.Path]::GetTempPath()) ("bp-failed-" + [guid]::NewGuid().ToString("N"))
    try {
        if (Test-Path -LiteralPath $InstallDir) {
            New-Item -ItemType Directory -Path $failedStaging -Force | Out-Null
            $failedCopy = Join-Path $failedStaging (Split-Path -Leaf $InstallDir)
            Move-Item -LiteralPath $InstallDir -Destination $failedCopy -Force
            Write-Log "Moved failed tree to $failedCopy for forensics." -Level "WARN"
        }
        Move-Item -LiteralPath $BackupDir -Destination $InstallDir -Force
        Write-Ok "Rollback complete: previous installation restored."
        Write-Log "Rollback complete from $BackupDir" -Level "INFO"
    } catch {
        throw "Rollback FAILED: $($_.Exception.Message). Previous files are at '$BackupDir'; failed tree (if moved) is under '$failedStaging'."
    }
}

function Copy-PreservedData {
    <#
    .SYNOPSIS
        Restore user data/config/secrets from the backup into the fresh tree.
    .DESCRIPTION
        Explicit per-item migration (never a blanket copy): secrets and configs
        (secr.json, .env, .webui_secret_key) and runtime data dirs are copied
        back; the fresh config.yaml is kept but any operator-modified keys are
        NOT clobbered — operator config wins: if the backup had config.yaml, it
        is restored over the fresh default (operator edits preserved).
    #>
    param([string]$BackupDir, [string]$InstallDir)
    if ([string]::IsNullOrWhiteSpace($BackupDir) -or -not (Test-Path -LiteralPath $BackupDir)) { return }
    foreach ($name in $script:PreserveNames) {
        $src = Join-Path $BackupDir $name
        if (-not (Test-Path -LiteralPath $src)) { continue }
        $dst = Join-Path $InstallDir $name
        try {
            if ((Get-Item -LiteralPath $src) -is [System.IO.DirectoryInfo]) {
                if (-not (Test-Path -LiteralPath $dst)) {
                    New-Item -ItemType Directory -Path $dst -Force | Out-Null
                }
                # Merge: copy backup content into the fresh dir without deleting
                # anything the fresh tree legitimately added.
                Copy-Item -LiteralPath (Join-Path $src "*") -Destination $dst -Recurse -Force
            } else {
                Copy-Item -LiteralPath $src -Destination $dst -Force
            }
            Write-Log "Preserved user data: $name" -Level "INFO"
        } catch {
            Write-Warn "Could not restore preserved item '$name': $($_.Exception.Message)"
        }
    }
}

function Deploy-StagedTree {
    <#
    .SYNOPSIS
        Atomically replace the live install with the validated staged tree.
    .DESCRIPTION
        Steps: backup live -> move live aside -> move staged in -> restore
        preserved data. The old live tree is kept as the backup until the caller
        deletes it after critical validation (unless -KeepBackup).
    #>
    param(
        [string]$InstallDir,
        [string]$StagedRoot,
        [ref]$BackupDirOut
    )
    $backup = ""
    if (Test-Path -LiteralPath $InstallDir) {
        $backup = Backup-BreachPilotInstall -InstallDir $InstallDir
        $BackupDirOut.Value = $backup
        # Move the live tree aside so the staged tree takes its exact path.
        $aside = "$InstallDir.deploy-aside"
        if (Test-Path -LiteralPath $aside) {
            try { Remove-Item -LiteralPath $aside -Recurse -Force } catch { }
        }
        Move-Item -LiteralPath $InstallDir -Destination $aside -Force
        try {
            Move-Item -LiteralPath $StagedRoot -Destination $InstallDir -Force
            try { Remove-Item -LiteralPath $aside -Recurse -Force } catch {
                Write-Log "Could not remove deploy-aside dir $aside`: $($_.Exception.Message)" -Level "WARN"
            }
        } catch {
            # Deploy failed mid-move: put the live tree back immediately.
            try {
                if (Test-Path -LiteralPath $InstallDir) {
                    try { Remove-Item -LiteralPath $InstallDir -Recurse -Force } catch { }
                }
                Move-Item -LiteralPath $aside -Destination $InstallDir -Force
            } catch {
                throw "Deploy failed AND live-tree restore failed: $($_.Exception.Message). Backup is at '$backup'."
            }
            throw "Deploy failed; live tree restored from aside copy: $($_.Exception.Message)"
        }
    } else {
        $parent = Split-Path -Parent $InstallDir
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        Move-Item -LiteralPath $StagedRoot -Destination $InstallDir -Force
        $BackupDirOut.Value = ""
    }
    if (-not [string]::IsNullOrWhiteSpace($backup)) {
        Copy-PreservedData -BackupDir $backup -InstallDir $InstallDir
    }
    return $backup
}

# ---------------------------------------------------------------------------
# Package managers + dependency installation
# ---------------------------------------------------------------------------

function Get-PackageManagers {
    $managers = @()
    if ($null -ne (Get-Command winget -ErrorAction SilentlyContinue)) {
        $managers += "winget"
    }
    if ($null -ne (Get-Command choco -ErrorAction SilentlyContinue)) {
        $managers += "choco"
    }
    if ($null -ne (Get-Command scoop -ErrorAction SilentlyContinue)) {
        $managers += "scoop"
    }
    return $managers
}

function Install-Dependency {
    <#
    .SYNOPSIS
        Install one dependency via the best available package manager.
    .DESCRIPTION
        Never trusts the manager exit code alone: re-detects the command and
        verifies it executes afterward. Requires interactive approval unless
        -Yes/-Force. Honors -Offline (refuses) and -Check (reports only).
        Winget IDs are explicit per tool; choco/scoop are fallbacks where the
        package name is well-known, otherwise the user is told the winget ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$DetectCommand,
        [Parameter(Mandatory = $true)][string]$WingetId,
        [string]$ChocoPackage = "",
        [string]$ManualUrl = "",
        [string]$WhyNeeded = ""
    )
    $found = Get-Command $DetectCommand -ErrorAction SilentlyContinue
    if ($null -ne $found) {
        return @{ Installed = $true; Path = $found.Source; Changed = $false }
    }
    if ($Check) {
        $msg = "Would install $DisplayName (winget $WingetId)"
        if ($ManualUrl) { $msg += "; manual: $ManualUrl" }
        Write-Skip $msg
        return @{ Installed = $false; Path = ""; Changed = $false }
    }
    if ($Offline) {
        throw "NONRETRY: $DisplayName is missing and -Offline forbids installing it. Install manually ($ManualUrl) and re-run."
    }
    if (-not [string]::IsNullOrWhiteSpace($WhyNeeded)) {
        Write-Info "$DisplayName is needed: $WhyNeeded"
    }
    $managers = Get-PackageManagers
    if ($managers.Count -eq 0) {
        Write-Warn "$DisplayName is missing and no package manager (winget/choco/scoop) is available. Manual install: $ManualUrl"
        Add-ActionRequired "Install ${DisplayName}: $ManualUrl, then re-run install.ps1"
        return @{ Installed = $false; Path = ""; Changed = $false }
    }
    $approved = $false
    if ($Yes -or $Force) {
        $approved = $true
        Write-Prog "Installing $DisplayName via $($managers[0]) (non-interactive)..."
    } else {
        $answer = Read-Host "   Install $DisplayName via $($managers[0])? [y/N]"
        if ($answer -match "^(?i:y|yes)$") { $approved = $true }
    }
    if (-not $approved) {
        Write-Skip "$DisplayName install declined. Manual install: $ManualUrl"
        Add-ActionRequired "Install ${DisplayName}: $ManualUrl, then re-run install.ps1"
        return @{ Installed = $false; Path = ""; Changed = $false }
    }
    $installed = $false
    if ($managers -contains "winget") {
        try {
            Invoke-ExternalCommand -Command "winget" -Arguments @("install", "--id", $WingetId, "-e", "--silent",
                "--accept-package-agreements", "--accept-source-agreements") -TimeoutSeconds 900 -AllowFailure | Out-Null
        } catch {
            Write-Log "winget install $WingetId threw: $($_.Exception.Message)" -Level "WARN"
        }
        Refresh-ProcessEnvironment
        Start-Sleep -Seconds 2
        Refresh-ProcessEnvironment
    } elseif (($managers -contains "choco") -and (-not [string]::IsNullOrWhiteSpace($ChocoPackage))) {
        try {
            Invoke-ExternalCommand -Command "choco" -Arguments @("install", $ChocoPackage, "-y") -TimeoutSeconds 900 -AllowFailure | Out-Null
        } catch {
            Write-Log "choco install $ChocoPackage threw: $($_.Exception.Message)" -Level "WARN"
        }
        Refresh-ProcessEnvironment
    } else {
        Write-Warn "No supported automatic install path for $DisplayName on this machine (have: $($managers -join ', ')). Manual install: $ManualUrl"
        Add-ActionRequired "Install ${DisplayName}: $ManualUrl, then re-run install.ps1"
        return @{ Installed = $false; Path = ""; Changed = $false }
    }
    # Verify: re-detect AND execute (never trust the manager exit code alone).
    $again = Get-Command $DetectCommand -ErrorAction SilentlyContinue
    if ($null -eq $again) {
        Refresh-ProcessEnvironment
        Start-Sleep -Seconds 2
        $again = Get-Command $DetectCommand -ErrorAction SilentlyContinue
    }
    if ($null -ne $again) {
        $ver = Get-CommandVersion -Command $DetectCommand
        if ($null -ne $ver) {
            Write-Ok "$DisplayName now available: $($again.Source)"
            return @{ Installed = $true; Path = $again.Source; Changed = $true }
        }
    }
    Write-Warn "$DisplayName install ran but '$DetectCommand' is still not usable on PATH. Open a NEW terminal (package managers often need one) and re-run install.ps1. Manual: $ManualUrl"
    Add-ActionRequired "$DisplayName installed but not on PATH yet: open a new terminal and re-run install.ps1 (exit code 9 signals this)."
    return @{ Installed = $false; Path = ""; Changed = $true }
}

# ---------------------------------------------------------------------------
# Python discovery, install, venv, dependencies
# ---------------------------------------------------------------------------

function Find-BestPython {
    <#
    .SYNOPSIS
        Discover the best compatible Python interpreter (>= 3.11).
    .DESCRIPTION
        Probes `py`, `python`, `python3`, then known Windows install locations.
        Skips the Windows Store stub (WindowsApps\python.exe) which opens the
        Store instead of running Python. Parses the real version and picks the
        highest compatible interpreter. Returns $null when none qualifies.
    #>
    $candidates = New-Object System.Collections.ArrayList
    foreach ($name in @("py", "python", "python3")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -eq $cmd) { continue }
        if ($cmd.Source -match "(?i)WindowsApps") {
            Write-Log "Skipping Windows Store alias: $($cmd.Source)" -Level "INFO"
            continue
        }
        $null = $candidates.Add(@{ Name = $name; Path = $cmd.Source; Args = @() })
        if ($name -eq "py") {
            # The launcher can hide a newer Python behind `-3`; probe both.
            $null = $candidates.Add(@{ Name = "py -3"; Path = $cmd.Source; Args = @("-3") })
        }
    }
    # Known install locations (per-user + machine, 3.11-3.13+, x64/ARM64).
    $roots = @()
    foreach ($base in @($env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)}, "C:\Python311", "C:\Python312", "C:\Python313")) {
        if (-not [string]::IsNullOrWhiteSpace($base)) { $roots += $base }
    }
    foreach ($root in $roots) {
        foreach ($leaf in @("Programs\Python\Python311\python.exe", "Programs\Python\Python312\python.exe",
                "Programs\Python\Python313\python.exe", "Programs\Python\Python314\python.exe",
                "Python311\python.exe", "Python312\python.exe", "Python313\python.exe", "python.exe")) {
            try {
                $p = Join-Path $root $leaf
                if ((Test-Path -LiteralPath $p) -and ($p -notmatch "(?i)WindowsApps")) {
                    $null = $candidates.Add(@{ Name = $p; Path = $p; Args = @() })
                }
            } catch { }
        }
    }
    $best = $null
    $bestVer = $null
    foreach ($c in $candidates) {
        try {
            $args = @() + $c.Args + @("--version")
            $r = Invoke-ExternalCommand -Command $c.Path -Arguments $args -TimeoutSeconds 15 -AllowFailure
            $raw = ($r.StdOut + " " + $r.StdErr).Trim()
            if ($r.ExitCode -ne 0) { continue }
            $m = [regex]::Match($raw, "(\d+)\.(\d+)\.(\d+)")
            if (-not $m.Success) { continue }
            $v = New-Object Version([int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value)
            if ($v -lt $script:MinPython) {
                Write-Log "Python too old ($v): $($c.Path)" -Level "INFO"
                continue
            }
            # Sanity: must be able to run code (Store stub passes --version rarely, but be sure).
            $probe = Invoke-ExternalCommand -Command $c.Path -Arguments (@() + $c.Args + @("-c", "import sys;print(sys.version_info[0])")) -TimeoutSeconds 15 -AllowFailure
            if ($probe.ExitCode -ne 0) { continue }
            if ($null -eq $bestVer -or $v -gt $bestVer) {
                $bestVer = $v
                $best = @{ Command = $c.Name; Path = $c.Path; ExtraArgs = $c.Args; Version = "$v"; Raw = $raw }
            }
        } catch {
            Write-Log "Python probe failed for $($c.Path): $($_.Exception.Message)" -Level "DEBUG"
        }
    }
    return $best
}

function Install-PythonEnvironment {
    <#
    .SYNOPSIS
        Ensure a compatible Python exists (installing via winget if approved).
    .OUTPUTS
        Python info hashtable from Find-BestPython, or throws ExitDependency.
    #>
    $py = Find-BestPython
    if ($null -ne $py) {
        Write-Ok "Python $((Get-PropValue -Object $py -Name "Version" -Default "?")) ($((Get-PropValue -Object $py -Name "Command" -Default "?")))"
        return $py
    }
    if ($Check) {
        Write-Skip "Would install Python 3.12 via winget (Python.Python.3.12)"
        return $null
    }
    if ($Offline) {
        throw "NONRETRY: No compatible Python (>= 3.11) found and -Offline forbids installing one."
    }
    Write-Warn "No compatible Python (>= 3.11) found."
    $res = Install-Dependency -DisplayName "Python 3.12" -DetectCommand "python" `
        -WingetId "Python.Python.3.12" -ChocoPackage "python" `
        -ManualUrl "https://www.python.org/downloads/ (tick 'Add Python to PATH')" `
        -WhyNeeded "BreachPilot requires Python 3.11+ (pyproject.toml requires-python)."
    $py = Find-BestPython
    if ($null -eq $py) {
        throw "Python 3.11+ is required but none is usable. Install from https://www.python.org/downloads/ (tick 'Add Python to PATH'), open a NEW terminal, and re-run install.ps1."
    }
    Write-Ok "Python $((Get-PropValue -Object $py -Name "Version" -Default "?")) ($((Get-PropValue -Object $py -Name "Command" -Default "?")))"
    return $py
}

function Test-VenvHealthy {
    param([string]$VenvPython, [string]$InstallDir)
    if ([string]::IsNullOrWhiteSpace($VenvPython)) { return @{ Healthy = $false; Reason = "no venv python path" } }
    if (-not (Test-Path -LiteralPath $VenvPython)) { return @{ Healthy = $false; Reason = "venv interpreter missing: $VenvPython" } }
    try {
        $r = Invoke-ExternalCommand -Command $VenvPython -Arguments @("--version") -TimeoutSeconds 15 -AllowFailure
        if ($r.ExitCode -ne 0) { return @{ Healthy = $false; Reason = "venv python --version failed" } }
        if (-not (Test-PythonVersionSupported -VersionText ($r.StdOut + " " + $r.StdErr))) {
            return @{ Healthy = $false; Reason = "venv python version unsupported: $($r.StdOut.Trim())" }
        }
        # Must belong to this install (prefix/pyvenv.cfg check), not a stray venv.
        $cfg = Join-Path (Split-Path -Parent (Split-Path -Parent $VenvPython)) "pyvenv.cfg"
        if (-not (Test-Path -LiteralPath $cfg)) {
            return @{ Healthy = $false; Reason = "pyvenv.cfg missing — not a real venv" }
        }
        $pip = Invoke-ExternalCommand -Command $VenvPython -Arguments @("-m", "pip", "--version") -TimeoutSeconds 20 -AllowFailure
        if ($pip.ExitCode -ne 0) { return @{ Healthy = $false; Reason = "pip broken inside venv" } }
        $yaml = Invoke-ExternalCommand -Command $VenvPython -Arguments @("-c", "import yaml, fastapi, mcp; print('deps-ok')") -TimeoutSeconds 30 -AllowFailure
        if ($yaml.ExitCode -ne 0) {
            return @{ Healthy = $true; Reason = "venv works but project deps missing (pip install needed)"; NeedsDeps = $true }
        }
        return @{ Healthy = $true; Reason = "ok" }
    } catch {
        return @{ Healthy = $false; Reason = $_.Exception.Message }
    }
}

function Install-VenvAndDeps {
    <#
    .SYNOPSIS
        Create/repair .venv and install the canonical dependency set.
    .DESCRIPTION
        Canonical source is requirements.txt (header: == pip install -e
        ".[ollama,dev]"). Never installs both requirements.txt and pyproject
        extras (that would duplicate/conflict). Calls the venv interpreter
        explicitly; never depends on activation.
    #>
    param(
        [hashtable]$Python,
        [string]$InstallDir
    )
    $venvDir = Join-Path $InstallDir ".venv"
    $venvPy = Join-Path $venvDir "Scripts\python.exe"
    $health = Test-VenvHealthy -VenvPython $venvPy -InstallDir $InstallDir
    if ([bool](Get-PropValue -Object $health -Name "Healthy" -Default $false) -and -not [bool](Get-PropValue -Object $health -Name "NeedsDeps" -Default $false) -and -not $Force) {
        $r = Invoke-ExternalCommand -Command $venvPy -Arguments @("--version") -TimeoutSeconds 15 -AllowFailure
        Write-Ok "venv healthy ($($r.StdOut.Trim())), deps present — skipping recreate."
        return $venvPy
    }
    if ([bool](Get-PropValue -Object $health -Name "Healthy" -Default $false) -and [bool](Get-PropValue -Object $health -Name "NeedsDeps" -Default $false) -and -not $Force) {
        Write-Prog "venv works but project deps are missing — installing deps only."
    } elseif (-not [bool](Get-PropValue -Object $health -Name "Healthy" -Default $false)) {
        Write-Prog "venv $([string](Get-PropValue -Object $health -Name "Reason" -Default "unusable")) — (re)creating..."
        if ((Test-Path -LiteralPath $venvDir) -and $Force) {
            try { Remove-Item -LiteralPath $venvDir -Recurse -Force } catch {
                Write-Warn "Could not remove broken venv at $venvDir`: $($_.Exception.Message). Trying to reuse it."
            }
        } elseif (Test-Path -LiteralPath $venvDir) {
            # Broken venv without -Force: still recreate (a broken venv can never
            # be "already correct"), but say so loudly.
            Write-Warn "Removing broken venv at $venvDir (recreate required)."
            try { Remove-Item -LiteralPath $venvDir -Recurse -Force } catch {
                throw "Cannot remove broken venv at $venvDir`: $($_.Exception.Message). Delete it manually and re-run."
            }
        }
        if (-not (Test-Path -LiteralPath $venvPy)) {
            $pyArgs = @() + $Python.ExtraArgs + @("-m", "venv", $venvDir)
            try {
                Invoke-ExternalCommand -Command $Python.Path -Arguments $pyArgs -TimeoutSeconds 300
            } catch {
                throw "venv creation failed: $($_.Exception.Message). On Windows this usually means the Python install lacks venv support — reinstall Python from python.org (not the Store) and re-run."
            }
        }
        $health = Test-VenvHealthy -VenvPython $venvPy -InstallDir $InstallDir
        if (-not [bool](Get-PropValue -Object $health -Name "Healthy" -Default $false) -and -not [bool](Get-PropValue -Object $health -Name "NeedsDeps" -Default $false)) {
            throw "venv created but unusable: $([string](Get-PropValue -Object $health -Name "Reason" -Default "unknown"))"
        }
        Write-Ok "venv created at $venvDir"
    }
    # Upgrade packaging tooling (safe: pip/setuptools/wheel inside our own venv).
    try {
        Invoke-ExternalCommand -Command $venvPy -Arguments @("-m", "pip", "install", "--upgrade", "pip") -TimeoutSeconds 300 | Out-Null
        Write-Log "pip upgraded." -Level "INFO"
    } catch {
        Write-Warn "pip upgrade had warnings — continuing. ($($_.Exception.Message))"
    }
    # Canonical install: requirements.txt only (== .[ollama,dev]; see its header).
    $req = Join-Path $InstallDir "requirements.txt"
    if (-not (Test-Path -LiteralPath $req)) {
        throw "NONRETRY: requirements.txt missing under $InstallDir — source tree incomplete."
    }
    $pipLog = ""
    try {
        $res = Invoke-ExternalCommand -Command $venvPy -Arguments @("-m", "pip", "install", "-r", $req) -TimeoutSeconds 1800
        Write-Ok "Python dependencies installed (requirements.txt)."
    } catch {
        Write-Warn "pip install failed once; retrying after 5s... ($($_.Exception.Message))"
        Start-Sleep -Seconds 5
        try {
            Invoke-ExternalCommand -Command $venvPy -Arguments @("-m", "pip", "install", "-r", $req) -TimeoutSeconds 1800 | Out-Null
            Write-Ok "Python dependencies installed on retry."
        } catch {
            $pipLog = $_.Exception.Message
            Write-Log "pip install full error: $pipLog" -Level "ERROR"
            throw "pip install -r requirements.txt failed twice. Check network access to pypi.org and re-run install.ps1 (idempotent). Last error: $pipLog"
        }
    }
    # Verify the venv can now import the core stack.
    $verify = Invoke-ExternalCommand -Command $venvPy -Arguments @("-c", "import yaml, fastapi, mcp; print('deps-ok')") -TimeoutSeconds 60 -AllowFailure
    if ($verify.ExitCode -ne 0) {
        throw "Dependencies installed but core imports still fail: $($verify.StdErr). Re-run with -Repair."
    }
    try {
        $pv = (Invoke-ExternalCommand -Command $venvPy -Arguments @("--version") -TimeoutSeconds 15 -AllowFailure).StdOut.Trim()
        $pp = (Invoke-ExternalCommand -Command $venvPy -Arguments @("-m", "pip", "--version") -TimeoutSeconds 20 -AllowFailure).StdOut.Trim()
        Write-Log "venv python: $pv | $pp" -Level "INFO"
    } catch { }
    return $venvPy
}

# ---------------------------------------------------------------------------
# Lightweight config probing (no PyYAML needed — regex over config.yaml text)
# ---------------------------------------------------------------------------

function Get-YamlScalar {
    param([string]$ConfigPath, [string]$Section, [string]$Key, [string]$Default = "")
    try {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { return $Default }
        $lines = Get-Content -LiteralPath $ConfigPath -Encoding UTF8
        $inSection = ($Section -eq "")
        foreach ($line in $lines) {
            if ($line -match "^\s*#") { continue }
            if ($line -match "^(\S[^:]*):\s*$") {
                $inSection = ($Matches[1].Trim() -eq $Section)
                continue
            }
            if ($inSection -and ($line -match ("^\s+" + [regex]::Escape($Key) + "\s*:\s*(.+?)\s*$"))) {
                $val = $Matches[1].Trim().Trim("'", '"')
                if ($val -eq "~" -or $val -eq "null" -or $val.StartsWith("#")) { return $Default }
                $val = ($val -split "\s+#")[0].Trim().Trim("'", '"')
                return $val
            }
            # Top-level scalar (Section == "") e.g. nothing today, but keep general.
            if (($Section -eq "") -and ($line -match ("^" + [regex]::Escape($Key) + "\s*:\s*(.+?)\s*$"))) {
                $val = $Matches[1].Trim().Trim("'", '"')
                return $val
            }
        }
    } catch { }
    return $Default
}

function Get-ActiveProvider {
    param([string]$InstallDir)
    $cfg = Join-Path $InstallDir "config.yaml"
    $provider = Get-YamlScalar -ConfigPath $cfg -Section "models" -Key "provider" -Default "ollama"
    if ([string]::IsNullOrWhiteSpace($provider)) { $provider = "ollama" }
    $embed = Get-YamlScalar -ConfigPath $cfg -Section "embeddings" -Key "provider" -Default "ollama"
    return @{ Provider = $provider.Trim().ToLowerInvariant(); Embeddings = $embed.Trim().ToLowerInvariant(); ConfigPath = $cfg }
}

function Get-ConfiguredSandboxImage {
    param([string]$InstallDir)
    $cfg = Join-Path $InstallDir "config.yaml"
    $img = Get-YamlScalar -ConfigPath $cfg -Section "sandbox" -Key "image" -Default $script:SandboxImage
    if ([string]::IsNullOrWhiteSpace($img)) { $img = $script:SandboxImage }
    return $img.Trim()
}

function Get-ConfiguredNmapPath {
    param([string]$InstallDir)
    $cfg = Join-Path $InstallDir "config.yaml"
    $p = Get-YamlScalar -ConfigPath $cfg -Section "nmap" -Key "path" -Default "nmap"
    if ([string]::IsNullOrWhiteSpace($p)) { $p = "nmap" }
    return $p.Trim()
}

# ---------------------------------------------------------------------------
# Node.js + WebUI
# ---------------------------------------------------------------------------

function Test-NodeInstall {
    $node = Get-Command node -ErrorAction SilentlyContinue
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if ($null -eq $node -or $null -eq $npm) {
        return @{ Present = $false; NodeVersion = ""; NpmVersion = ""; Supported = $false }
    }
    $nr = Invoke-ExternalCommand -Command "node" -Arguments @("--version") -TimeoutSeconds 15 -AllowFailure
    $mr = Invoke-ExternalCommand -Command "npm" -Arguments @("--version") -TimeoutSeconds 15 -AllowFailure
    $nv = ($nr.StdOut + " " + $nr.StdErr).Trim()
    $mv = ($mr.StdOut + " " + $mr.StdErr).Trim()
    $supported = (Test-NodeVersionSupported -VersionText $nv) -and ($mr.ExitCode -eq 0)
    return @{ Present = $true; NodeVersion = $nv; NpmVersion = $mv; Supported = $supported; NodePath = $node.Source }
}

function Install-WebUI {
    param([string]$InstallDir, [string]$VenvPython)
    if ($SkipWebUI) {
        Write-Skip "WebUI build skipped (-SkipWebUI). The app lazy-builds on first 'python main.py --web' if Node is added later."
        return @{ Built = $false; Skipped = $true }
    }
    $webDir = Join-Path $InstallDir "webui"
    $pkgJson = Join-Path $webDir "package.json"
    $distIndex = Join-Path $webDir "dist\index.html"
    if (-not (Test-Path -LiteralPath $pkgJson)) {
        Write-Skip "webui\package.json not found — skipping WebUI build (source tree without WebUI)."
        return @{ Built = $false; Skipped = $true }
    }
    if ((Test-Path -LiteralPath $distIndex) -and -not $Force) {
        # Freshness: skip rebuild when dist is newer than package.json + lockfile.
        try {
            $distTime = (Get-Item -LiteralPath $distIndex).LastWriteTimeUtc
            $pkgTime = (Get-Item -LiteralPath $pkgJson).LastWriteTimeUtc
            $lock = Join-Path $webDir "package-lock.json"
            $lockTime = $pkgTime
            if (Test-Path -LiteralPath $lock) { $lockTime = (Get-Item -LiteralPath $lock).LastWriteTimeUtc }
            $newest = $pkgTime
            if ($lockTime -gt $newest) { $newest = $lockTime }
            if ($distTime -ge $newest) {
                Write-Ok "WebUI already built and current (dist newer than package.json/lockfile) — skipping rebuild."
                return @{ Built = $true; Skipped = $false }
            }
            Write-Prog "WebUI sources newer than dist — rebuilding..."
        } catch {
            Write-Prog "WebUI dist present but freshness check failed — rebuilding to be safe."
        }
    } elseif ((Test-Path -LiteralPath $distIndex) -and $Force) {
        Write-Prog "WebUI dist present but -Force given — rebuilding..."
    }
    if ($Check) {
        Write-Skip "Would build WebUI (npm install + npm run build) in $webDir"
        return @{ Built = $false; Skipped = $true }
    }
    $node = Test-NodeInstall
    if (-not $node.Present -or -not $node.Supported) {
        if (-not $node.Present) {
            Write-Warn "Node.js not on PATH — WebUI build needs Node 18+ and npm."
        } else {
            Write-Warn "Node.js version '$($node.NodeVersion)' is below the minimum (18+). WebUI build needs Node 18+."
        }
        if ($Offline) {
            Write-Skip "Offline: cannot install Node.js. WebUI will build on first 'python main.py --web' once Node is present."
            return @{ Built = $false; Skipped = $true }
        }
        $res = Install-Dependency -DisplayName "Node.js LTS" -DetectCommand "node" `
            -WingetId "OpenJS.NodeJS.LTS" -ChocoPackage "nodejs-lts" `
            -ManualUrl "https://nodejs.org/ (LTS)" `
            -WhyNeeded "WebUI production build (npm ci + npm run build -> webui/dist)."
        $node = Test-NodeInstall
        if (-not $node.Present -or -not $node.Supported) {
            Write-Skip "Node.js still unavailable — WebUI will build on first 'python main.py --web' once Node is present."
            Add-ActionRequired "Install Node.js 18+ (https://nodejs.org/) then re-run install.ps1 or 'cd webui && npm ci && npm run build'."
            return @{ Built = $false; Skipped = $true }
        }
    }
    Write-Prog "Building WebUI (node $($node.NodeVersion), npm $($node.NpmVersion))..."
    $lockFile = Join-Path $webDir "package-lock.json"
    $useCi = (Test-Path -LiteralPath $lockFile)
    try {
        if ($useCi) {
            Write-Log "npm ci (deterministic, lockfile present)" -Level "INFO"
            Invoke-ExternalCommand -Command "npm" -Arguments @("ci", "--no-audit", "--no-fund") -TimeoutSeconds 1200 -WorkingDirectory $webDir | Out-Null
        } else {
            Write-Log "npm install (no lockfile)" -Level "INFO"
            Invoke-ExternalCommand -Command "npm" -Arguments @("install", "--no-audit", "--no-fund") -TimeoutSeconds 1200 -WorkingDirectory $webDir | Out-Null
        }
    } catch {
        Write-Warn "WebUI dependency install failed: $($_.Exception.Message). The app will retry the build on first 'python main.py --web'."
        Add-ActionRequired "WebUI npm install failed: check network access to registry.npmjs.org, then 'cd webui && npm ci && npm run build'."
        return @{ Built = $false; Skipped = $true }
    }
    try {
        # `npm run build` = `tsc -b && vite build` (webui/package.json) -> webui/dist/.
        Invoke-ExternalCommand -Command "npm" -Arguments @("run", "build") -TimeoutSeconds 1200 -WorkingDirectory $webDir | Out-Null
    } catch {
        Write-Warn "WebUI build failed: $($_.Exception.Message). The app will retry on first 'python main.py --web'."
        Add-ActionRequired "WebUI build failed: ensure Node 18+ ('node --version'), then 'cd webui && npm run build'."
        return @{ Built = $false; Skipped = $true }
    }
    if (Test-Path -LiteralPath $distIndex) {
        Write-Ok "WebUI built to webui\dist\"
        return @{ Built = $true; Skipped = $false }
    }
    Write-Warn "Build finished but webui\dist\index.html is missing — will retry on next run."
    Add-ActionRequired "WebUI dist missing after build: 'cd webui && npm run build' and inspect the error."
    return @{ Built = $false; Skipped = $true }
}

# ---------------------------------------------------------------------------
# Nmap / Git
# ---------------------------------------------------------------------------

function Find-Nmap {
    param([string]$InstallDir)
    # 1. Configured path wins (config.yaml nmap.path), 2. PATH, 3. known locations.
    $configured = Get-ConfiguredNmapPath -InstallDir $InstallDir
    $probes = New-Object System.Collections.ArrayList
    if ($configured -match "[\\/]") {
        $null = $probes.Add($configured)
    } elseif ($configured -ne "nmap") {
        $null = $probes.Add($configured)
    }
    $null = $probes.Add("nmap")
    foreach ($p in @("C:\Program Files (x86)\Nmap\nmap.exe", "C:\Program Files\Nmap\nmap.exe")) {
        $null = $probes.Add($p)
    }
    foreach ($probe in $probes) {
        try {
            $r = Invoke-ExternalCommand -Command $probe -Arguments @("--version") -TimeoutSeconds 15 -AllowFailure
            if ($r.ExitCode -eq 0 -and ($r.StdOut -match "(?i)nmap")) {
                $first = (($r.StdOut -split "`r?`n") | Select-Object -First 1).Trim()
                $src = $probe
                try {
                    $cmd = Get-Command $probe -ErrorAction SilentlyContinue
                    if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) { $src = $cmd.Source }
                } catch { }
                return @{ Present = $true; Path = $src; VersionLine = $first }
            }
        } catch { }
    }
    return @{ Present = $false; Path = ""; VersionLine = "" }
}

function Install-NmapIfNeeded {
    param([string]$InstallDir)
    $found = Find-Nmap -InstallDir $InstallDir
    if ([bool](Get-PropValue -Object $found -Name "Present" -Default $false)) {
        Write-Ok "Nmap: $((Get-PropValue -Object $found -Name "VersionLine" -Default "?")) [$((Get-PropValue -Object $found -Name "Path" -Default "?"))]"
        # If it came from a known location but is not on PATH, say how to fix
        # without reinstalling: add its directory for this process + user PATH hint.
        try {
            $onPath = ($null -ne (Get-Command nmap -ErrorAction SilentlyContinue))
            $__foundPath = [string](Get-PropValue -Object $found -Name "Path" -Default "")
            if ((-not $onPath) -and ($__foundPath -match "[\\/]")) {
                $dir = Split-Path -Parent $__foundPath
                if (($env:Path -split ";" | Where-Object { $_.Trim().Equals($dir.Trim(), [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) {
                    $env:Path = "$env:Path;$dir"
                    Write-Log "Added Nmap dir to process PATH: $dir" -Level "INFO"
                }
                Write-Info "Nmap was found outside PATH; its directory was added to this session. Persist via -Repair (PATH registration) or add '$dir' to user PATH."
            }
        } catch { }
        return $found
    }
    Write-Warn "Nmap not found — needed for recon scans."
    if ($Check) {
        Write-Skip "Would install Nmap via winget (Insecure.Nmap)"
        return $found
    }
    if ($Offline) {
        Add-ActionRequired "Install Nmap manually (https://nmap.org/download.html), then re-run install.ps1."
        return $found
    }
    $res = Install-Dependency -DisplayName "Nmap" -DetectCommand "nmap" `
        -WingetId "Insecure.Nmap" -ChocoPackage "nmap" `
        -ManualUrl "https://nmap.org/download.html" `
        -WhyNeeded "Recon scans (doctor honors nmap.path else PATH)."
    $found = Find-Nmap -InstallDir $InstallDir
    if ([bool](Get-PropValue -Object $found -Name "Present" -Default $false)) {
        Write-Ok "Nmap: $((Get-PropValue -Object $found -Name "VersionLine" -Default "?")) [$((Get-PropValue -Object $found -Name "Path" -Default "?"))]"
    } else {
        Add-ActionRequired "Install Nmap (https://nmap.org/download.html or 'winget install Insecure.Nmap'), then re-run install.ps1."
    }
    return $found
}

function Test-GitInstall {
    $cmd = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return @{ Present = $false; Version = "" } }
    $r = Invoke-ExternalCommand -Command "git" -Arguments @("--version") -TimeoutSeconds 15 -AllowFailure
    $raw = ($r.StdOut + " " + $r.StdErr).Trim()
    if ($r.ExitCode -ne 0) { return @{ Present = $false; Version = $raw } }
    return @{ Present = $true; Version = $raw; Path = $cmd.Source }
}

# ---------------------------------------------------------------------------
# Ollama / AI providers (provider-aware: Ollama is OPTIONAL)
# ---------------------------------------------------------------------------

function Test-OllamaInstall {
    $cmd = Get-Command ollama -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return @{ CliPresent = $false; Version = ""; DaemonUp = $false } }
    $r = Invoke-ExternalCommand -Command "ollama" -Arguments @("--version") -TimeoutSeconds 15 -AllowFailure
    $raw = ($r.StdOut + " " + $r.StdErr).Trim()
    $up = $false
    try {
        $prev = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        try {
            $resp = Invoke-WebRequest -Uri "http://localhost:11434/api/version" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            $up = ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300)
        } finally { $ProgressPreference = $prev }
    } catch { $up = $false }
    return @{ CliPresent = ($r.ExitCode -eq 0); Version = $raw; DaemonUp = $up; Path = $cmd.Source }
}

function Install-OllamaIfNeeded {
    param([string]$InstallDir)
    $active = Get-ActiveProvider -InstallDir $InstallDir
    $__actProv = [string](Get-PropValue -Object $active -Name "Provider" -Default "ollama")
    $__actEmb = [string](Get-PropValue -Object $active -Name "Embeddings" -Default "ollama")
    $needsOllama = ($__actProv -eq "ollama") -or ($__actEmb -eq "ollama")
    if ($SkipOllama) {
        if ($needsOllama) {
            Write-Warn "-SkipOllama given but config uses Ollama (provider=$($active.Provider), embeddings=$($active.Embeddings)). Doctor will report the Ollama check as failing until you configure another provider or remove -SkipOllama."
            Add-ActionRequired "Ollama skipped but configured: switch providers (WebUI System -> Models, or models.provider: opencode_go + embeddings.provider: none) or re-run without -SkipOllama."
        } else {
            Write-Skip "Ollama skipped (-SkipOllama); active provider is '$($active.Provider)' — no Ollama needed."
        }
        return @{ Skipped = $true; CliPresent = $false; DaemonUp = $false }
    }
    if (-not $needsOllama) {
        Write-Skip "Ollama not required (models.provider=$($active.Provider), embeddings=$($active.Embeddings)) — detection only, no install offered."
        $st = Test-OllamaInstall
        if ($st.CliPresent) {
            $daemon = "daemon stopped"
            if ($st.DaemonUp) { $daemon = "daemon running" }
            Write-Info "Ollama CLI present ($($st.Version), $daemon) but not required by the active provider."
        }
        return @{ Skipped = $true; CliPresent = $st.CliPresent; DaemonUp = $st.DaemonUp }
    }
    $st = Test-OllamaInstall
    if ($st.CliPresent) {
        $daemon = "daemon stopped"
        if ($st.DaemonUp) { $daemon = "daemon running" }
        Write-Ok "Ollama CLI: $($st.Version) ($daemon)"
    } else {
        Write-Warn "Ollama CLI not on PATH — AI features on the ollama provider need it."
        if ($Check) {
            Write-Skip "Would install Ollama via winget (Ollama.Ollama)"
        } elseif (-not $Offline) {
            $res = Install-Dependency -DisplayName "Ollama" -DetectCommand "ollama" `
                -WingetId "Ollama.Ollama" -ChocoPackage "" `
                -ManualUrl "https://ollama.com/download (OllamaSetup.exe)" `
                -WhyNeeded "Active provider is 'ollama' (models.provider in config.yaml)."
            $st = Test-OllamaInstall
        } else {
            Add-ActionRequired "Install Ollama (https://ollama.com/download), then re-run install.ps1."
        }
    }
    # Daemon: probe only, start best-effort when interactive; never hang.
    if ($st.CliPresent -and -not $st.DaemonUp -and -not $Check) {
        Write-Prog "Ollama daemon not responding on http://localhost:11434 — attempting to start (max 15s)..."
        try {
            Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Minimized -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Log "ollama serve start failed: $($_.Exception.Message)" -Level "WARN"
        }
        $deadline = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 1
            $st = Test-OllamaInstall
            if ($st.DaemonUp) { break }
        }
        if ($st.DaemonUp) { Write-Ok "Ollama daemon now responding." }
        else {
            Write-Warn "Ollama daemon still not responding — start it via the Ollama tray app or 'ollama serve'."
            Add-ActionRequired "Start Ollama ('ollama serve' or the Ollama app) so the ollama provider is reachable."
        }
    } elseif ($st.CliPresent -and $st.DaemonUp) {
        Write-Ok "Ollama daemon responding on http://localhost:11434"
    }
    # Model pull: NEVER forced silently. Interactive: ask. -Yes: skip (documented).
    $pullWanted = $false
    if ($st.DaemonUp -and -not $Check) {
        if ($Yes -or $Force) {
            Write-Skip "Model pull skipped in non-interactive mode (documented -Yes behavior): run 'ollama pull $script:DefaultModelCloud' and 'ollama pull $script:DefaultModelEmbed' once a provider key is configured."
        } elseif (-not $Offline) {
            $ans = Read-Host "   Pull default models (glm-5.2:cloud + nomic-embed-text, large download)? [y/N]"
            if ($ans -match "^(?i:y|yes)$") { $pullWanted = $true }
        }
    }
    if ($pullWanted) {
        try {
            Write-Prog "Pulling $script:DefaultModelCloud (best-effort; cloud model needs OLLAMA_API_KEY)..."
            $pr = Invoke-ExternalCommand -Command "ollama" -Arguments @("pull", $script:DefaultModelCloud) -TimeoutSeconds 1800 -AllowFailure
            if ($pr.ExitCode -ne 0) { Write-Warn "$script:DefaultModelCloud pull failed — is OLLAMA_API_KEY set? Is the daemon running?" }
            else { Write-Ok "$script:DefaultModelCloud ready." }
        } catch { Write-Warn "Model pull failed: $($_.Exception.Message)" }
        try {
            Write-Prog "Pulling $script:DefaultModelEmbed (best-effort; needed for semantic memory)..."
            $pr = Invoke-ExternalCommand -Command "ollama" -Arguments @("pull", $script:DefaultModelEmbed) -TimeoutSeconds 1800 -AllowFailure
            if ($pr.ExitCode -ne 0) { Write-Warn "$script:DefaultModelEmbed pull failed — will retry on next run." }
            else { Write-Ok "$script:DefaultModelEmbed ready." }
        } catch { Write-Warn "Embedding model pull failed: $($_.Exception.Message)" }
    }
    return $st
}

# ---------------------------------------------------------------------------
# Docker / sandbox / WSL
# ---------------------------------------------------------------------------

function Test-DockerInstall {
    $cmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        return @{ CliPresent = $false; Version = ""; DaemonUp = $false; Detail = "Docker CLI missing" }
    }
    $vr = Invoke-ExternalCommand -Command "docker" -Arguments @("--version") -TimeoutSeconds 15 -AllowFailure
    $raw = ($vr.StdOut + " " + $vr.StdErr).Trim()
    if ($vr.ExitCode -ne 0) {
        return @{ CliPresent = $false; Version = $raw; DaemonUp = $false; Detail = "Docker CLI broken" }
    }
    $info = Invoke-ExternalCommand -Command "docker" -Arguments @("info") -TimeoutSeconds 30 -AllowFailure
    if ($info.ExitCode -eq 0) {
        return @{ CliPresent = $true; Version = $raw; DaemonUp = $true; Detail = "daemon working"; Path = $cmd.Source }
    }
    $combined = ($info.StdOut + " " + $info.StdErr)
    if ($combined -match "(?i)desktop|pipe|connect|not running|starting") {
        return @{ CliPresent = $true; Version = $raw; DaemonUp = $false; Detail = "Docker Desktop installed but daemon unreachable (stopped or starting)"; Path = $cmd.Source }
    }
    return @{ CliPresent = $true; Version = $raw; DaemonUp = $false; Detail = "daemon unavailable: $($combined.Trim())"; Path = $cmd.Source }
}

function Test-WslPresent {
    $cmd = Get-Command wsl -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return @{ Present = $false; Detail = "wsl.exe not found" } }
    $r = Invoke-ExternalCommand -Command "wsl" -Arguments @("--status") -TimeoutSeconds 20 -AllowFailure
    $raw = ($r.StdOut + " " + $r.StdErr).Trim()
    if ($r.ExitCode -eq 0) { return @{ Present = $true; Detail = $raw } }
    $l = Invoke-ExternalCommand -Command "wsl" -Arguments @("--list", "--verbose") -TimeoutSeconds 20 -AllowFailure
    $raw2 = ($l.StdOut + " " + $l.StdErr).Trim()
    return @{ Present = $true; Detail = $raw2 }
}

function Install-SandboxImage {
    param([string]$InstallDir)
    # Sandbox is default-ON and fail-closed (fallback_native: false in code).
    # -SkipDocker degrades loudly to native mode; the config is NEVER auto-edited
    # to hide that.
    $cfgPath = Join-Path $InstallDir "config.yaml"
    $enabledTxt = Get-YamlScalar -ConfigPath $cfgPath -Section "sandbox" -Key "enabled" -Default "true"
    $enabled = ($enabledTxt.Trim().ToLowerInvariant() -ne "false")
    if ($SkipDocker) {
        $fallback = Get-YamlScalar -ConfigPath $cfgPath -Section "sandbox" -Key "fallback_native" -Default "false"
        $mode = "STRICT fail-closed (executions denied until Docker works)"
        if ($fallback.Trim().ToLowerInvariant() -eq "true") { $mode = "NATIVE fallback (uncontained host execution)" }
        Write-Warn "Docker/sandbox skipped (-SkipDocker). Execution mode: $mode. Sandbox containment is OFF — only run against targets you own."
        Add-ActionRequired "Docker skipped: sandbox containment OFF ($mode). Install Docker Desktop to restore containment."
        return @{ Status = "skipped"; DaemonUp = $false; ImagePresent = $false }
    }
    if (-not $enabled) {
        Write-Skip "Sandbox disabled in config (sandbox.enabled: false) — explicit operator opt-out; Docker checks skipped."
        return @{ Status = "disabled"; DaemonUp = $false; ImagePresent = $false }
    }
    if ($Check) {
        $d = Test-DockerInstall
        Write-Skip "Would verify Docker daemon + image $(Get-ConfiguredSandboxImage -InstallDir $InstallDir) (now: $($d.Detail))"
        return @{ Status = "check"; DaemonUp = $d.DaemonUp; ImagePresent = $false }
    }
    $d = Test-DockerInstall
    if (-not $d.CliPresent) {
        Write-Warn "Docker CLI missing — BreachPilot's sandbox (default-ON containment) needs Docker Desktop on Windows."
        if (-not $Offline) {
            $res = Install-Dependency -DisplayName "Docker Desktop" -DetectCommand "docker" `
                -WingetId "Docker.DockerDesktop" -ChocoPackage "docker-desktop" `
                -ManualUrl "https://docs.docker.com/desktop/install/windows-install/" `
                -WhyNeeded "Sandboxed exploit execution (disposable Docker worker, fail-closed)."
            $d = Test-DockerInstall
        } else {
            Add-ActionRequired "Install Docker Desktop (https://docs.docker.com/desktop/install/windows-install/), then re-run install.ps1."
        }
    }
    if ($d.CliPresent -and -not $d.DaemonUp) {
        Write-Warn "Docker CLI present but daemon unreachable: $($d.Detail)."
        Write-Info "Docker Desktop may need starting (or a logout/reboot after first install, or WSL2 setup)."
        $wsl = Test-WslPresent
        if (-not $wsl.Present) {
            Write-Warn "WSL not detected — Docker Desktop requires WSL2 (or Hyper-V). Install via 'wsl --install' in an ELEVATED terminal, reboot, then re-run install.ps1."
            Add-ActionRequired "Install WSL2 ('wsl --install' elevated + reboot) for Docker Desktop, then re-run install.ps1."
        } else {
            Write-Info "WSL status: $($wsl.Detail)"
            Write-Prog "Waiting up to 60s for the Docker daemon (start Docker Desktop if it is stopped)..."
            $deadline = (Get-Date).AddSeconds(60)
            while ((Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 5
                $d = Test-DockerInstall
                if ($d.DaemonUp) { break }
            }
        }
        if (-not $d.DaemonUp) {
            $d = Test-DockerInstall
            if (-not $d.DaemonUp) {
                Write-Warn "Docker daemon still unavailable. Sandbox builds are blocked; continuing without the sandbox image (doctor will flag it)."
                Add-ActionRequired "Start Docker Desktop (may need logout/reboot after first install), then re-run install.ps1 -Repair to build the sandbox image."
                return @{ Status = "daemon-down"; DaemonUp = $false; ImagePresent = $false }
            }
        }
    }
    if ($d.DaemonUp) {
        Write-Ok "Docker: $($d.Version) (daemon working)"
    }
    # Build/check the worker image using the repo Dockerfile (name from config).
    $image = Get-ConfiguredSandboxImage -InstallDir $InstallDir
    $dockerfile = Join-Path $InstallDir $script:SandboxDockerfile
    if (-not (Test-Path -LiteralPath $dockerfile)) {
        Write-Warn "Sandbox Dockerfile missing at $dockerfile — cannot build '$image'."
        Add-ActionRequired "Restore $script:SandboxDockerfile from the repository, then re-run install.ps1 -Repair."
        return @{ Status = "no-dockerfile"; DaemonUp = $d.DaemonUp; ImagePresent = $false }
    }
    $imgCheck = Invoke-ExternalCommand -Command "docker" -Arguments @("image", "inspect", $image) -TimeoutSeconds 30 -AllowFailure
    if ($imgCheck.ExitCode -eq 0 -and -not $Force) {
        Write-Ok "Sandbox image present: $image"
        return @{ Status = "ready"; DaemonUp = $true; ImagePresent = $true }
    }
    Write-Prog "Building sandbox image '$image' (docker build, several minutes first time)..."
    try {
        Invoke-ExternalCommand -Command "docker" -Arguments @("build", "-t", $image, "docker/sandbox") -TimeoutSeconds 3600 -WorkingDirectory $InstallDir | Out-Null
        $verify = Invoke-ExternalCommand -Command "docker" -Arguments @("image", "inspect", $image) -TimeoutSeconds 30 -AllowFailure
        if ($verify.ExitCode -eq 0) {
            Write-Ok "Sandbox image built: $image"
            return @{ Status = "ready"; DaemonUp = $true; ImagePresent = $true }
        }
        Write-Warn "docker build finished but image '$image' not found afterward."
        Add-ActionRequired "Sandbox image build did not produce '$image': run 'docker build -t $image docker/sandbox' manually and inspect the error."
        return @{ Status = "build-failed"; DaemonUp = $true; ImagePresent = $false }
    } catch {
        Write-Warn "Sandbox image build failed: $($_.Exception.Message)"
        Add-ActionRequired "Build the sandbox image manually ('docker build -t $image docker/sandbox'), then re-run install.ps1 -Repair."
        return @{ Status = "build-failed"; DaemonUp = $true; ImagePresent = $false }
    }
}

# ---------------------------------------------------------------------------
# API keys (project-owned secure mechanism only)
# ---------------------------------------------------------------------------

function Test-ApiKeySetup {
    param([string]$InstallDir, [string]$VenvPython)
    $active = Get-ActiveProvider -InstallDir $InstallDir
    # Map active provider -> required env (optional keys are never demanded).
    $required = @()
    $__keyProv = [string](Get-PropValue -Object $active -Name "Provider" -Default "")
    switch ($__keyProv) {
        "ollama" { $required = @("OLLAMA_API_KEY") }
        "opencode_go" { $required = @("OPENCODE_GO_API_KEY") }
        "chatgpt" { $required = @() }  # OAuth via ~/.codex/auth.json, never a pasted key.
        default { $required = @() }
    }
    $missing = @()
    foreach ($name in $required) {
        $v = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrWhiteSpace($v)) {
            # Also honored from secr.json (project store) — check without logging values.
            try {
                $secr = Join-Path $InstallDir "secr.json"
                if (Test-Path -LiteralPath $secr) {
                    # load_api_key_file shape: {"api_keys": {...}} OR flat {ENV: secret}.
                    $rawKeys = Get-Content -LiteralPath $secr -Raw -Encoding UTF8 | ConvertFrom-Json
                    $keyMap = Get-PropValue -Object $rawKeys -Name "api_keys" -Default $null
                    if ($null -eq $keyMap) { $keyMap = $rawKeys }
                    $val = [string](Get-PropValue -Object $keyMap -Name $name -Default "")
                    if ([string]::IsNullOrWhiteSpace($val)) { $missing += $name }
                } else {
                    $missing += $name
                }
            } catch {
                $missing += $name
            }
        }
    }
    if ([string](Get-PropValue -Object $active -Name "Provider" -Default "") -eq "chatgpt") {
        $codex = Join-Path $env:USERPROFILE ".codex\auth.json"
        if ($env:CODEX_HOME) { $codex = Join-Path $env:CODEX_HOME "auth.json" }
        if (-not (Test-Path -LiteralPath $codex)) {
            return @{ Missing = @(); Note = "ChatGPT provider: sign in via the interactive menu ('Sign in with ChatGPT'); tokens stay in $codex and are never copied." }
        }
        return @{ Missing = @(); Note = "" }
    }
    return @{ Missing = $missing; Note = "" }
}

function Request-ApiKeySetup {
    param([string]$InstallDir, [string]$VenvPython)
    $st = Test-ApiKeySetup -InstallDir $InstallDir -VenvPython $VenvPython
    $__stMissing = @(Get-PropValue -Object $st -Name "Missing" -Default @())
    if ($__stMissing.Count -eq 0) {
        $__stNote = [string](Get-PropValue -Object $st -Name "Note" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($__stNote)) { Write-Info $__stNote }
        else { Write-Ok "Provider API key present (or not required by the active provider)." }
        return
    }
    $names = ($__stMissing -join ", ")
    Write-Warn "Required provider key missing: $names. BreachPilot runs, but AI-backed flows will fail until it is set."
    Add-ActionRequired "Set $names via: python main.py --setup-api-keys (saves to secr.json, gitignored) or the environment."
    if ($Check -or $Yes -or $Offline) {
        Write-Skip "Skipping key prompt (non-interactive/check/offline). Run: python main.py --setup-api-keys"
        return
    }
    $ans = Read-Host "   Launch the secure key setup now (python main.py --setup-api-keys)? [y/N]"
    if ($ans -match "^(?i:y|yes)$") {
        try {
            Invoke-ExternalCommand -Command $VenvPython -Arguments @("main.py", "--setup-api-keys") -TimeoutSeconds 300 -StreamOutput | Out-Null
            $again = Test-ApiKeySetup -InstallDir $InstallDir -VenvPython $VenvPython
            $__againMissing = @(Get-PropValue -Object $again -Name "Missing" -Default @("?"))
            if ($__againMissing.Count -eq 0) { Write-Ok "Provider key configured." }
        } catch {
            Write-Warn "Key setup exited: $($_.Exception.Message). Re-run 'python main.py --setup-api-keys' any time."
        }
    } else {
        Write-Info "Skipped. Run any time: python main.py --setup-api-keys"
    }
}

# ---------------------------------------------------------------------------
# Launcher + PATH + shortcuts
# ---------------------------------------------------------------------------

function Get-LauncherDir {
    $bin = Join-Path $env:USERPROFILE ".local\bin"
    return $bin
}

function Install-Launcher {
    <#
    .SYNOPSIS
        Write lightweight bp/breachpilot launchers that resolve the install dir.
    .DESCRIPTION
        The .cmd shims resolve their own location (no baked TEMP paths): the
        install dir is recorded once at generation; -Repair rewrites them if the
        install moved. Per-user PATH only; machine PATH is never touched.
    #>
    param([string]$InstallDir, [string]$VenvPython)
    $binDir = Get-LauncherDir
    if ($NoPath) {
        Write-Skip "Launcher PATH install skipped (-NoPath). In-install launchers still written under $InstallDir."
        # Still drop a local convenience shim inside the install dir.
        try {
            $local = Join-Path $InstallDir "bp.cmd"
            $content = "@echo off`r`nREM BreachPilot local launcher (generated by install.ps1)`r`n" +
                "pushd `"%~dp0`" 2>nul || exit /b 1`r`n" +
                "`"%~dp0.venv\Scripts\python.exe`" `"%~dp0main.py`" %*`r`n" +
                "set `"RC=%ERRORLEVEL%`"`r`n" +
                "popd`r`n" +
                "exit /b %RC%`r`n"
            Set-Content -LiteralPath $local -Value $content -Encoding ASCII
            Write-Log "Wrote in-install launcher: $local" -Level "INFO"
        } catch {
            Write-Log "Could not write in-install launcher: $($_.Exception.Message)" -Level "WARN"
        }
        return @{ BinDir = ""; Changed = $false }
    }
    if ($Check) {
        Write-Skip "Would install bp/breachpilot launchers to $binDir + user PATH"
        return @{ BinDir = $binDir; Changed = $false }
    }
    try {
        if (-not (Test-Path -LiteralPath $binDir)) {
            New-Item -ItemType Directory -Path $binDir -Force | Out-Null
        }
    } catch {
        throw "Cannot create launcher dir $binDir`: $($_.Exception.Message)"
    }
    # .cmd shim: resolves install dir via the generated path line; falls back to
    # system python when the venv is absent (mirrors START.bat behavior).
    $venvRel = ".venv\Scripts\python.exe"
    $shim = "@echo off`r`n" +
        "REM BreachPilot launcher (generated by install.ps1 v$script:InstallerVersion)`r`n" +
        "REM Resolves the install location recorded below; re-run -Repair if moved.`r`n" +
        "set `"BP_HOME=$InstallDir`"`r`n" +
        "pushd `"%BP_HOME%`" 2>nul || ( echo breachpilot: install not found at %BP_HOME% 1>&2 & exit /b 1 )`r`n" +
        "set `"BP_PY=%BP_HOME%\$venvRel`"`r`n" +
        "if not exist `"%BP_PY%`" set `"BP_PY=python`"`r`n" +
        "`"%BP_PY%`" `"%BP_HOME%\main.py`" %*`r`n" +
        "set `"BP_RC=%ERRORLEVEL%`"`r`n" +
        "set `"BP_PY=`"`r`n" +
        "set `"BP_HOME=`"`r`n" +
        "popd`r`n" +
        "exit /b %BP_RC%`r`n"
    $changed = $false
    foreach ($name in @("breachpilot.cmd", "bp.cmd")) {
        $dest = Join-Path $binDir $name
        $write = $true
        if ((Test-Path -LiteralPath $dest) -and -not $Force) {
            try {
                $existing = Get-Content -LiteralPath $dest -Raw -Encoding ASCII
                if ($existing -eq $shim) {
                    Write-Log "Launcher $name already correct; skipping." -Level "DEBUG"
                    $write = $false
                }
            } catch { }
        }
        if ($write) {
            Set-Content -LiteralPath $dest -Value $shim -Encoding ASCII
            $changed = $true
            Write-Log "Wrote launcher: $dest" -Level "INFO"
        }
    }
    if ($changed) { Write-Ok "Launchers installed: $binDir\bp.cmd, breachpilot.cmd" }
    else { Write-Ok "Launchers already correct — skipping." }
    return @{ BinDir = $binDir; Changed = $changed }
}

function Add-UserPath {
    <#
    .SYNOPSIS
        Idempotent per-user PATH registration (case-insensitive dedup).
    .DESCRIPTION
        Normalizes entries, never duplicates (case-insensitive), preserves the
        existing PATH byte-for-byte otherwise, enforces the 32767-char Windows
        limit, updates the current process, and broadcasts WM_SETTINGCHANGE.
        Never touches Machine PATH (per-user install scope).
    #>
    param([string]$Entry)
    if ($NoPath) {
        Write-Skip "PATH modification skipped (-NoPath)."
        return @{ Changed = $false; NeedsRelogin = $false }
    }
    if ($Check) {
        Write-Skip "Would ensure '$Entry' is on user PATH"
        return @{ Changed = $false; NeedsRelogin = $false }
    }
    $current = ""
    try { $current = [Environment]::GetEnvironmentVariable("Path", "User") } catch { $current = "" }
    if ($null -eq $current) { $current = "" }
    $merged = Join-NormalizedPath -CurrentPath $current -Entry $Entry
    if ($null -eq $merged) {
        Write-Warn "User PATH is near the 32767-char Windows limit; refusing to append '$Entry'. Add it manually or prune stale entries."
        Add-ActionRequired "User PATH too long to append '$Entry': prune stale entries, then re-run install.ps1 -Repair."
        return @{ Changed = $false; NeedsRelogin = $false }
    }
    $changed = [bool]$merged.Changed
    if ($changed) {
        try {
            [Environment]::SetEnvironmentVariable("Path", $merged.Path, "User")
            Write-Ok "Added '$Entry' to user PATH (open a NEW terminal to use it)."
        } catch {
            Write-Warn "Could not update user PATH: $($_.Exception.Message). Add '$Entry' manually."
            Add-ActionRequired "Add '$Entry' to user PATH manually, then open a new terminal."
            return @{ Changed = $false; NeedsRelogin = $false }
        }
    } else {
        Write-Ok "User PATH already contains '$Entry'."
    }
    # Current process: reflect the registry value without a restart.
    try {
        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ([string]::IsNullOrWhiteSpace($machinePath)) { $machinePath = "" }
        $env:Path = "$machinePath;$($merged.Path)"
    } catch { }
    # Broadcast so open Explorer/terminal instances pick it up where possible.
    try {
        $sig = @"
using System;
using System.Runtime.InteropServices;
public static class EnvBroadcast {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}
"@
        Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue
        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $SMTO_ABORTIFHUNG = 0x0002
        $res = [UIntPtr]::Zero
        [void][EnvBroadcast]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Environment", $SMTO_ABORTIFHUNG, 5000, [ref]$res)
        Write-Log "Broadcast WM_SETTINGCHANGE." -Level "DEBUG"
    } catch {
        Write-Log "Environment broadcast failed (non-fatal): $($_.Exception.Message)" -Level "DEBUG"
    }
    return @{ Changed = $changed; NeedsRelogin = $changed }
}

function Remove-UserPathEntry {
    param([string]$Entry)
    try {
        $current = [Environment]::GetEnvironmentVariable("Path", "User")
        if ([string]::IsNullOrWhiteSpace($current)) { return $false }
        $clean = $Entry.Trim().TrimEnd("\")
        $kept = @($current -split ";" | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().TrimEnd("\").Equals($clean, [StringComparison]::OrdinalIgnoreCase)
        })
        $newPath = ($kept -join ";")
        if ($newPath -eq $current) { return $false }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Log "Removed '$Entry' from user PATH." -Level "INFO"
        return $true
    } catch {
        Write-Warn "Could not remove '$Entry' from user PATH: $($_.Exception.Message)"
        return $false
    }
}

function Install-Shortcuts {
    <#
    .SYNOPSIS
        Optional Start Menu shortcuts (prompted unless -Yes, which skips).
    #>
    param([string]$InstallDir)
    if ($Check -or $NoPath) { return }
    if ($Yes) {
        Write-Skip "Start Menu shortcuts skipped in non-interactive mode (re-run interactively to add them)."
        return
    }
    $ans = Read-Host "   Create Start Menu shortcuts (BreachPilot, WebUI, Doctor, Uninstall)? [y/N]"
    if ($ans -notmatch "^(?i:y|yes)$") {
        Write-Skip "Start Menu shortcuts declined."
        return
    }
    try {
        $startDir = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\BreachPilot"
        if (-not (Test-Path -LiteralPath $startDir)) {
            New-Item -ItemType Directory -Path $startDir -Force | Out-Null
        }
        $shell = New-Object -ComObject WScript.Shell
        $binDir = Get-LauncherDir
        $entries = @(
            @{ Name = "BreachPilot"; Args = "--menu"; Desc = "BreachPilot terminal menu" },
            @{ Name = "BreachPilot WebUI"; Args = "--web"; Desc = "BreachPilot WebUI (http://127.0.0.1:8765)" },
            @{ Name = "BreachPilot Doctor"; Args = "--doctor"; Desc = "BreachPilot environment self-check" }
        )
        foreach ($e in $entries) {
            $lnk = $shell.CreateShortcut((Join-Path $startDir "$($e.Name).lnk"))
            $lnk.TargetPath = (Join-Path $binDir "bp.cmd")
            $lnk.Arguments = $e.Args
            $lnk.WorkingDirectory = $InstallDir
            $lnk.Description = $e.Desc
            $lnk.Save()
        }
        # Uninstall shortcut re-invokes this installer from its installed copy.
        $installedPs1 = Join-Path $InstallDir "install.ps1"
        if (Test-Path -LiteralPath $installedPs1) {
            $u = $shell.CreateShortcut((Join-Path $startDir "Uninstall BreachPilot.lnk"))
            $u.TargetPath = "powershell.exe"
            $u.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$installedPs1`" -Uninstall"
            $u.WorkingDirectory = $InstallDir
            $u.Description = "Uninstall BreachPilot"
            $u.Save()
        }
        Write-Ok "Start Menu shortcuts created (Programs\BreachPilot)."
    } catch {
        Write-Warn "Could not create Start Menu shortcuts: $($_.Exception.Message)"
    }
}

function Remove-Shortcuts {
    try {
        $startDir = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\BreachPilot"
        if (Test-Path -LiteralPath $startDir) {
            Remove-Item -LiteralPath $startDir -Recurse -Force
            Write-Ok "Removed Start Menu shortcuts."
        }
        $desktop = [Environment]::GetFolderPath("Desktop")
        foreach ($n in @("BreachPilot.lnk", "BreachPilot WebUI.lnk", "BreachPilot Doctor.lnk")) {
            $p = Join-Path $desktop $n
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
        }
    } catch {
        Write-Log "Shortcut removal issue: $($_.Exception.Message)" -Level "WARN"
    }
}

# ---------------------------------------------------------------------------
# Doctor / self-test (real project health checks — success is never faked)
# ---------------------------------------------------------------------------

function Invoke-BreachPilotDoctor {
    param([string]$VenvPython, [string]$InstallDir)
    Write-Prog "Running real health check: main.py --doctor ..."
    $r = Invoke-ExternalCommand -Command $VenvPython -Arguments @("main.py", "--doctor") -TimeoutSeconds 600 -AllowFailure
    $combined = ($r.StdOut + "`n" + $r.StdErr)
    if (-not [string]::IsNullOrWhiteSpace($combined)) {
        Write-Host $combined
    }
    Write-Log "doctor exit=$($r.ExitCode)" -Level "INFO"
    return $r
}

function Get-DoctorJson {
    param([string]$VenvPython)
    try {
        $r = Invoke-ExternalCommand -Command $VenvPython -Arguments @("main.py", "--doctor", "--json") -TimeoutSeconds 300 -AllowFailure
        if ($r.ExitCode -ne 0 -and [string]::IsNullOrWhiteSpace($r.StdOut)) { return $null }
        # Stdout may carry log lines before the JSON; take the last {...} block.
        $text = $r.StdOut
        $start = $text.LastIndexOf("{")
        if ($start -lt 0) { return $null }
        $candidate = $text.Substring($start)
        return ($candidate | ConvertFrom-Json)
    } catch {
        Write-Log "doctor --json parse failed: $($_.Exception.Message)" -Level "WARN"
        return $null
    }
}

function Test-DoctorResult {
    <#
    .SYNOPSIS
        Classify doctor output: hard failure vs warnings vs provider-setup gaps.
    .OUTPUTS
        @{ Status = 'pass'|'warnings'|'action-required'|'fail'; Detail = <string> }.
    #>
    param($DoctorJson, [int]$ExitCode)
    if ($ExitCode -eq 0) {
        if ($script:ActionItems.Count -gt 0) {
            return @{ Status = "warnings"; Detail = "doctor passed with $($script:ActionItems.Count) action item(s)" }
        }
        return @{ Status = "pass"; Detail = "doctor passed" }
    }
    # Non-zero: separate "provider key missing / optional tool absent" (action
    # required, install is sound) from hard failures using the JSON report.
    $hardFails = @()
    $__checksRaw = Get-PropValue -Object $DoctorJson -Name "checks" -Default $null
    if (($null -ne $DoctorJson) -and ($null -ne $__checksRaw)) {
        foreach ($c in @($__checksRaw)) {
            if ($null -eq $c) { continue }
            if (-not [bool](Get-PropValue -Object $c -Name "ok" -Default $false)) {
                $name = [string](Get-PropValue -Object $c -Name "name" -Default "unknown")
                # Per tools/doctor.py build_doctor_report: optional_tools and
                # linux_privilege never fail the count (informational-only).
                # Provider subchecks (ollama_reachable/chatgpt_provider/
                # opencode_go_provider/model_registry + *_provider/config/api-key
                # misses) and sandbox/browser/port gaps are operator actions,
                # not install breakage.
                if ($name -match "(?i)^(optional_tools|linux_privilege)$") {
                    continue
                }
                if ($name -match "(?i)(provider|api[_-]?key|ollama|opencode|chatgpt|docker|sandbox|browser|model|port_.*_free|config_valid)") {
                    # NOTE: extracted to locals — nested "" inside an
                    # interpolated string is an escape sequence, not "".
                    $__herr = [string](Get-PropValue -Object $c -Name "error" -Default "")
                    $__hint = [string](Get-PropValue -Object $c -Name "hint" -Default $__herr)
                    Add-ActionRequired "doctor: ${name}: ${__hint}"
                } else {
                    $hardFails += $name
                }
            }
        }
    }
    if ($hardFails.Count -gt 0) {
        return @{ Status = "fail"; Detail = "doctor hard failures: $($hardFails -join ', ')" }
    }
    return @{ Status = "action-required"; Detail = "doctor reports setup gaps (provider key / Docker / optional tools) — install is sound" }
}

# ---------------------------------------------------------------------------
# Modes: Check / Uninstall / Repair / Update / Install
# ---------------------------------------------------------------------------

function Show-Header {
    param([pscustomobject]$Platform, [string]$InstallDir)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " BreachPilot Windows Installer  v$script:InstallerVersion" -ForegroundColor Cyan
    Write-Host " Autonomous Security Assessment Platform" -ForegroundColor DarkGray
    Write-Host "============================================================" -ForegroundColor Cyan
    $mode = "Install"
    if ($Check) { $mode = "Check (read-only — no changes)" }
    elseif ($Update) { $mode = "Update" }
    elseif ($Repair) { $mode = "Repair" }
    elseif ($Uninstall) { $mode = "Uninstall" }
    Write-Host " Mode:          $mode"
    Write-Host " Install dir:   $InstallDir"
    Write-Host " Channel:       $(if ($Version) { "explicit $Version" } else { $Channel })"
    Write-Host " OS:            $($Platform.OSVersion) (build $($Platform.OSBuild), $($Platform.Architecture))"
    Write-Host " PowerShell:    $($Platform.PSEdition) $($Platform.PSVersion)"
    $elev = "no"
    if ($Platform.IsAdmin) { $elev = "yes" }
    Write-Host " Elevated:      $elev   User: $($Platform.User)"
    if ($Platform.IsRemote) { Write-Host " Session:       remote (no interactive prompts assumed safe)" -ForegroundColor Yellow }
    Write-Host ""
    Write-Log "Header: mode=$mode dir=$InstallDir channel=$Channel version=$Version os=$($Platform.OSVersion) arch=$($Platform.Architecture) ps=$($Platform.PSEdition)/$($Platform.PSVersion) admin=$($Platform.IsAdmin) remote=$($Platform.IsRemote)" -Level "INFO"
}

function Invoke-CheckMode {
    param([string]$InstallDir)
    Write-Step "System checks (read-only)"
    $platform = Get-PlatformInfo
    Show-Header -Platform $platform -InstallDir $InstallDir
    Write-Info "OS: $($platform.OSVersion) (build $($platform.OSBuild), $($platform.Architecture))"
    Write-Info "PowerShell: $($platform.PSEdition) $($platform.PSVersion); user $($platform.User); admin: $($platform.IsAdmin)"
    if (-not (Test-PlatformSupported -Platform $platform)) { exit $script:ExitUnsupported }
    $free = Get-InstallDriveFreeGB -Path (Split-Path -Parent $InstallDir)
    if ($free -ge 0) { Write-Info "Free disk on install drive: ${free} GB" }
    if ($platform.WingetPresent) { Write-Ok "winget present" } else { Write-Warn "winget not found — missing tools need manual install (https://aka.ms/getwinget)" }
    Write-Info "Package managers: $((Get-PackageManagers) -join ', ')"
    if ([string]::IsNullOrWhiteSpace($platform.OSVersion)) { Write-Warn "Could not determine Windows version precisely." }
    Write-StepDone

    Write-Step "Installation state (read-only)"
    $meta = Read-InstallMetadata -InstallDir $InstallDir
    $interrupted = Test-InterruptedInstall -InstallDir $InstallDir
    if ($interrupted.Interrupted) {
        Write-Warn "Interrupted previous run detected (state '$($interrupted.State)'). Re-run install/update/repair to recover cleanly."
    }
    $checkout = Get-CheckoutStatus -Dir $InstallDir
    $__coIsGit = [bool](Get-PropValue -Object $checkout -Name "IsGit" -Default $false)
    if (($null -ne $checkout) -and $__coIsGit) {
        if ([bool](Get-PropValue -Object $checkout -Name "GitAvailable" -Default $false)) {
            $__coOrigin = [string](Get-PropValue -Object $checkout -Name "Origin" -Default "")
            $__coBranch = [string](Get-PropValue -Object $checkout -Name "Branch" -Default "")
            $__coSha = [string](Get-PropValue -Object $checkout -Name "Sha" -Default "")
            $__coDirty = [string](Get-PropValue -Object $checkout -Name "IsDirty" -Default "")
            Write-Info "Git checkout: origin='$__coOrigin' branch=$__coBranch sha=$__coSha dirty=$__coDirty"
        } else {
            Write-Info ".git present but git CLI unavailable."
        }
    }
    $__metaCorrupt = [bool](Get-PropValue -Object $meta -Name "Corrupt" -Default $false)
    if (($null -ne $meta) -and (-not $__metaCorrupt)) {
        $__metaTag = [string](Get-PropValue -Object $meta -Name "tag" -Default "")
        $__metaCommit = [string](Get-PropValue -Object $meta -Name "commit" -Default "")
        $__metaShow = $__metaTag
        if ([string]::IsNullOrWhiteSpace($__metaShow)) { $__metaShow = $__metaCommit }
        Write-Info "Installed: $__metaShow (channel $((Get-PropValue -Object $meta -Name "channel" -Default "?")), $((Get-PropValue -Object $meta -Name "installed_at" -Default "?")))"
    } elseif (($null -ne $meta) -and $__metaCorrupt) {
        Write-Warn "Install metadata is corrupt — treated as unknown/corrupted install."
    } else {
        Write-Info "No install metadata — no managed BreachPilot install at $InstallDir."
    }
    Write-StepDone

    Write-Step "Version resolution (read-only)"
    $net = Test-NetworkConnectivity
    if (-not $net) {
        Write-Warn "GitHub not reachable (or -Offline): latest-version comparison unavailable."
        Write-Host " Status: Unknown (offline)" -ForegroundColor Yellow
    } else {
        try {
            $resolved = Resolve-BreachPilotVersion
            $have = ""
            $__metaCorrupt2 = [bool](Get-PropValue -Object $meta -Name "Corrupt" -Default $false)
            if (($null -ne $meta) -and (-not $__metaCorrupt2)) {
                $have = [string](Get-PropValue -Object $meta -Name "commit" -Default "")
                $__haveTag = [string](Get-PropValue -Object $meta -Name "tag" -Default "")
                if (-not [string]::IsNullOrWhiteSpace($__haveTag)) { $have = $__haveTag }
            }
            $want = $resolved.Tag
            if ([string]::IsNullOrWhiteSpace($want)) { $want = $resolved.Sha }
            Write-Host " Installed: $(if ($have) { $have } else { '(none)' })"
            Write-Host " Latest ($($resolved.Channel)): $want"
            $__metaCommit2 = [string](Get-PropValue -Object $meta -Name "commit" -Default "")
            if ($have -eq $want -or ($have -ne "" -and $resolved.Sha -eq $__metaCommit2)) {
                Write-Host " Status: Up to date" -ForegroundColor Green
            } elseif ([string]::IsNullOrWhiteSpace($have)) {
                Write-Host " Status: Not installed" -ForegroundColor Yellow
            } else {
                Write-Host " Status: Update available" -ForegroundColor Yellow
            }
        } catch {
            Write-Warn "Version resolution failed: $($_.Exception.Message)"
            Write-Host " Status: Unknown" -ForegroundColor Yellow
        }
    }
    Write-StepDone

    Write-Step "Dependencies (read-only)"
    $py = Find-BestPython
    if ($null -ne $py) { Write-Ok "Python $((Get-PropValue -Object $py -Name "Version" -Default "?")) ($((Get-PropValue -Object $py -Name "Command" -Default "?")))" } else { Write-Warn "No compatible Python (>= 3.11) found" }
    $venvPy = Join-Path $InstallDir ".venv\Scripts\python.exe"
    $vh = Test-VenvHealthy -VenvPython $venvPy -InstallDir $InstallDir
    if ($vh.Healthy -and -not $vh.NeedsDeps) { Write-Ok "venv healthy" }
    elseif ($vh.Healthy) { Write-Warn "venv works but project deps missing" }
    else { Write-Info "venv: $($vh.Reason)" }
    $node = Test-NodeInstall
    if ([bool](Get-PropValue -Object $node -Name "Present" -Default $false)) {
        $okFlag = "OK"
        if (-not [bool](Get-PropValue -Object $node -Name "Supported" -Default $false)) { $okFlag = "OLD" }
        Write-Info "Node $((Get-PropValue -Object $node -Name "NodeVersion" -Default "?")) / npm $((Get-PropValue -Object $node -Name "NpmVersion" -Default "?")) [$okFlag, need 18+]"
    } else { Write-Info "Node.js not installed (WebUI-build only)" }
    $nmap = Find-Nmap -InstallDir $InstallDir
    if ($nmap.Present) { Write-Ok "Nmap: $($nmap.VersionLine) [$($nmap.Path)]" } else { Write-Warn "Nmap not found" }
    $git = Test-GitInstall
    if ($git.Present) { Write-Ok "Git: $($git.Version)" } else { Write-Info "Git not installed (optional — ZIP download path works without it)" }
    $active = Get-ActiveProvider -InstallDir $InstallDir
    Write-Info "Active provider: $((Get-PropValue -Object $active -Name "Provider" -Default "?")) (embeddings: $((Get-PropValue -Object $active -Name "Embeddings" -Default "?")))"
    $ol = Test-OllamaInstall
    if ([bool](Get-PropValue -Object $ol -Name "CliPresent" -Default $false)) {
        $dstat = "stopped"
        if ([bool](Get-PropValue -Object $ol -Name "DaemonUp" -Default $false)) { $dstat = "running" }
        Write-Info "Ollama CLI: $((Get-PropValue -Object $ol -Name "Version" -Default "?")) (daemon $dstat)"
    } else { Write-Info "Ollama CLI not installed (needed only when provider/embeddings use ollama)" }
    $dk = Test-DockerInstall
    $__dkVer = [string](Get-PropValue -Object $dk -Name "Version" -Default "")
    $__dkDetail = [string](Get-PropValue -Object $dk -Name "Detail" -Default "?")
    Write-Info "Docker: $__dkDetail $(if ($__dkVer) { "[$__dkVer]" })"
    $img = Get-ConfiguredSandboxImage -InstallDir $InstallDir
    if ([bool](Get-PropValue -Object $dk -Name "DaemonUp" -Default $false)) {
        $chk = Invoke-ExternalCommand -Command "docker" -Arguments @("image", "inspect", $img) -TimeoutSeconds 30 -AllowFailure
        $__chkCode = 1
        try { $__chkCode = [int](Get-PropValue -Object $chk -Name "ExitCode" -Default 1) } catch { $__chkCode = 1 }
        if ($__chkCode -eq 0) { Write-Ok "Sandbox image present: $img" } else { Write-Warn "Sandbox image missing: $img" }
    }
    $dist = Join-Path $InstallDir "webui\dist\index.html"
    if (Test-Path -LiteralPath $dist) { Write-Ok "WebUI built (webui\dist\index.html)" } else { Write-Info "WebUI not built" }
    $binDir = Get-LauncherDir
    foreach ($n in @("bp.cmd", "breachpilot.cmd")) {
        if (Test-Path -LiteralPath (Join-Path $binDir $n)) { Write-Ok "Launcher present: $binDir\$n" }
        else { Write-Info "Launcher missing: $binDir\$n" }
    }
    try {
        $up = [Environment]::GetEnvironmentVariable("Path", "User")
        if (($up -split ";" | Where-Object { $_.Trim().TrimEnd("\").Equals($binDir.Trim().TrimEnd("\"), [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) {
            Write-Ok "User PATH contains $binDir"
        } else { Write-Info "User PATH lacks $binDir" }
    } catch { }
    Write-StepDone

    Write-Step "BreachPilot doctor (read-only)"
    if ((Test-Path -LiteralPath $venvPy) -and (Test-Path -LiteralPath (Join-Path $InstallDir "main.py"))) {
        $dr = Invoke-BreachPilotDoctor -VenvPython $venvPy -InstallDir $InstallDir
        $dj = Get-DoctorJson -VenvPython $venvPy
        $cls = Test-DoctorResult -DoctorJson $dj -ExitCode $dr.ExitCode
        Write-Info "Doctor classification: $($cls.Status) — $($cls.Detail)"
    } else {
        Write-Skip "Doctor unavailable (no venv or main.py at $InstallDir)."
    }
    Write-StepDone

    Write-Host ""
    Write-Host "Check complete — no changes made (-Check mode)." -ForegroundColor Cyan
    Write-Host "Installer log: $script:LogFile"
    return $script:ExitSuccess
}

function Remove-BreachPilot {
    param([string]$InstallDir)
    Write-Host ""
    Write-Host "Uninstalling BreachPilot-owned components..." -ForegroundColor Cyan
    # Launchers (owned).
    $binDir = Get-LauncherDir
    foreach ($n in @("breachpilot.cmd", "bp.cmd", "breachpilot.bat", "natai.bat")) {
        $p = Join-Path $binDir $n
        if (Test-Path -LiteralPath $p) {
            try { Remove-Item -LiteralPath $p -Force; Write-Ok "Removed $p" }
            catch { Write-Warn "Could not remove $p`: $($_.Exception.Message)" }
        }
    }
    # PATH entry (owned; shared dir left alone, other tools unaffected).
    if (Remove-UserPathEntry -Entry $binDir) {
        Write-Ok "Removed '$binDir' from user PATH."
    } else {
        Write-Skip "'$binDir' was not on user PATH (or already removed)."
    }
    # Shortcuts (owned).
    Remove-Shortcuts
    # Install dir: prompt unless -Yes. User data choice is separate from code.
    $deleteData = $false
    if (Test-Path -LiteralPath $InstallDir) {
        $hasData = $false
        foreach ($n in @("reports", "exploit_workspace", "research_workspace", "swarm_workspace", "secr.json", ".env", ".webui_secret_key")) {
            if (Test-Path -LiteralPath (Join-Path $InstallDir $n)) { $hasData = $true; break }
        }
        $removeDir = $false
        if ($Yes) {
            # -Yes: remove the application but KEEP user data by default is
            # ambiguous — choose the safe side: remove code, keep data dirs.
            $removeDir = $true
            Write-Info "-Yes: removing application files but preserving user data (reports/workspaces/secrets)."
        } else {
            $ans = Read-Host "   Remove the installation directory $InstallDir ? [y/N]"
            if ($ans -match "^(?i:y|yes)$") { $removeDir = $true }
            if ($hasData) {
                $ans2 = Read-Host "   Also delete user data (reports, workspaces, secr.json, .env)? [y/N]"
                if ($ans2 -match "^(?i:y|yes)$") { $deleteData = $true }
            }
        }
        if ($removeDir) {
            if (-not $deleteData -and $hasData) {
                # Move user data aside instead of deleting: code gone, data safe.
                $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
                $aside = "$InstallDir.userdata-$stamp"
                try {
                    New-Item -ItemType Directory -Path $aside -Force | Out-Null
                    foreach ($n in ($script:PreserveNames + @("*.db", "*.log"))) {
                        foreach ($match in (Get-ChildItem -LiteralPath $InstallDir -Filter $n -Force -ErrorAction SilentlyContinue)) {
                            Move-Item -LiteralPath $match.FullName -Destination (Join-Path $aside $match.Name) -Force
                        }
                    }
                    Write-Ok "User data preserved at $aside"
                } catch {
                    Write-Warn "Could not stage user data aside: $($_.Exception.Message). Aborting dir removal to protect data."
                    $removeDir = $false
                }
            }
            if ($removeDir) {
                try {
                    Remove-Item -LiteralPath $InstallDir -Recurse -Force
                    Write-Ok "Removed $InstallDir"
                } catch {
                    Write-Warn "Could not fully remove $InstallDir`: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Skip "Installation directory kept: $InstallDir"
        }
    } else {
        Write-Skip "Install dir not present: $InstallDir"
    }
    Write-Host ""
    Write-Host "Shared dependencies were NOT uninstalled (Python, Node, Docker, Nmap, Ollama, Git) — they may belong to other tools." -ForegroundColor DarkGray
    Write-Host "Uninstall complete." -ForegroundColor Green
    Write-Host "Installer log: $script:LogFile"
    # Refresh process PATH to drop the removed entry for this session.
    try { Refresh-ProcessEnvironment } catch { }
    return $script:ExitSuccess
}

function Invoke-RepairMode {
    param([string]$InstallDir)
    Write-Prog "Repair mode: verifying required files (user data is never deleted)..."
    $missing = @()
    foreach ($req in $script:RequiredSourceFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $InstallDir $req))) { $missing += $req }
    }
    if ($missing.Count -gt 0) {
        Write-Fail "Install at $InstallDir is missing: $($missing -join ', '). Repair needs a source tree — run 'install.ps1 -Update' to re-stage, or fresh-install."
        return @{ Code = $script:ExitFailure; VenvPython = ""; Proceeded = $false }
    }
    Write-Ok "Required source files present."
    Write-InstallState -InstallDir $InstallDir -State "dependencies"
    $py = Install-PythonEnvironment
    $venvPy = Install-VenvAndDeps -Python $py -InstallDir $InstallDir
    Install-NmapIfNeeded -InstallDir $InstallDir | Out-Null
    Install-OllamaIfNeeded -InstallDir $InstallDir | Out-Null
    $webui = Install-WebUI -InstallDir $InstallDir -VenvPython $venvPy
    Install-SandboxImage -InstallDir $InstallDir | Out-Null
    Install-Launcher -InstallDir $InstallDir -VenvPython $venvPy | Out-Null
    $binDir = Get-LauncherDir
    Add-UserPath -Entry $binDir | Out-Null
    Request-ApiKeySetup -InstallDir $InstallDir -VenvPython $venvPy
    Write-InstallState -InstallDir $InstallDir -State "validating"
    $dr = Invoke-BreachPilotDoctor -VenvPython $venvPy -InstallDir $InstallDir
    $dj = Get-DoctorJson -VenvPython $venvPy
    $cls = Test-DoctorResult -DoctorJson $dj -ExitCode $dr.ExitCode
    if ($cls.Status -eq "fail") {
        Write-Fail "Doctor still reports hard failures after repair: $($cls.Detail)"
        Write-InstallState -InstallDir $InstallDir -State "completed"
        return @{ Code = $script:ExitDoctor; VenvPython = $venvPy; Proceeded = $true }
    }
    Write-InstallState -InstallDir $InstallDir -State "completed"
    Write-Ok "Repair finished: $($cls.Status) — $($cls.Detail)"
    return @{ Code = $script:ExitSuccess; VenvPython = $venvPy; Proceeded = $true }
}

# ---------------------------------------------------------------------------
# Final summary screen
# ---------------------------------------------------------------------------

function Show-FinalSummary {
    param(
        [string]$InstallDir,
        [string]$VenvPython,
        [pscustomobject]$Resolved,
        [string]$ArchiveSha256,
        [hashtable]$Sandbox,
        [hashtable]$WebUI,
        [string]$DoctorStatus,
        [int]$ExitCode
    )
    $py = Find-BestPython
    $node = Test-NodeInstall
    $nmap = Find-Nmap -InstallDir $InstallDir
    $git = Test-GitInstall
    $ol = Test-OllamaInstall
    $dk = Test-DockerInstall
    $bpVer = ""
    if ($null -ne $Resolved) {
        $bpVer = [string](Get-PropValue -Object $Resolved -Name "Tag" -Default "")
        if ([string]::IsNullOrWhiteSpace($bpVer)) {
            $__rSha = [string](Get-PropValue -Object $Resolved -Name "Sha" -Default "")
            if (-not [string]::IsNullOrWhiteSpace($__rSha)) { $bpVer = $__rSha.Substring(0, [Math]::Min(12, $__rSha.Length)) }
        }
    }
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " BreachPilot is ready" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host (" BreachPilot       {0} / {1}" -f $bpVer, $Resolved.Channel)
    Write-Host (" Python            {0}" -f $(if ($py) { (Get-PropValue -Object $py -Name "Version" -Default "?") } else { "missing" }))
    $__sumNodePresent = [bool](Get-PropValue -Object $node -Name "Present" -Default $false)
    Write-Host (" Node              {0}" -f $(if ($__sumNodePresent) { "$((Get-PropValue -Object $node -Name "NodeVersion" -Default "?")) / npm $((Get-PropValue -Object $node -Name "NpmVersion" -Default "?"))" } else { "not installed (WebUI-build only)" }))
    Write-Host (" Nmap              {0}" -f $(if ($nmap.Present) { "$($nmap.VersionLine) [$($nmap.Path)]" } else { "missing" }))
    Write-Host (" Git               {0}" -f $(if ($git.Present) { $git.Version } else { "not installed (optional)" }))
    $__sumDkCli = [bool](Get-PropValue -Object $dk -Name "CliPresent" -Default $false)
    Write-Host (" Docker            {0}" -f $(if ($__sumDkCli) { "$((Get-PropValue -Object $dk -Name "Version" -Default "?")) / $((Get-PropValue -Object $dk -Name "Detail" -Default "?"))" } else { "not installed" }))
    $__sumOlCli = [bool](Get-PropValue -Object $ol -Name "CliPresent" -Default $false)
    $__sumOlUp = [bool](Get-PropValue -Object $ol -Name "DaemonUp" -Default $false)
    Write-Host (" Ollama            {0}" -f $(if ($__sumOlCli) { "$((Get-PropValue -Object $ol -Name "Version" -Default "?")) / $(if ($__sumOlUp) { 'daemon running' } else { 'daemon stopped' })" } else { "skipped / not required" }))
    $__sumWebBuilt = [bool](Get-PropValue -Object $WebUI -Name "Built" -Default $false)
    $__sumWebSkip = [bool](Get-PropValue -Object $WebUI -Name "Skipped" -Default $false)
    Write-Host (" WebUI             {0}" -f $(if ($__sumWebBuilt) { "built" } elseif ($__sumWebSkip) { "skipped" } else { "not built" }))
    $__sumSbStatus = [string](Get-PropValue -Object $Sandbox -Name "Status" -Default "?")
    Write-Host (" Sandbox           {0}" -f $(if ($__sumSbStatus -eq "ready") { "ready ($((Get-ConfiguredSandboxImage -InstallDir $InstallDir)))" } else { $__sumSbStatus }))
    Write-Host (" Doctor            {0}" -f $DoctorStatus)
    Write-Host (" Install location  {0}" -f $InstallDir)
    $binDir = Get-LauncherDir
    Write-Host (" Launcher          {0}" -f $(if ($NoPath) { "(in-install only, -NoPath)" } else { "$binDir\bp.cmd" }))
    Write-Host ""
    if ($script:ActionItems.Count -gt 0) {
        Write-Host " Action items:" -ForegroundColor Yellow
        $seen = @{}
        foreach ($a in $script:ActionItems) {
            if ($seen.ContainsKey($a)) { continue }
            $seen[$a] = $true
            Write-Host "  - $a" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    if ($ExitCode -eq $script:ExitReboot) {
        Write-Host " REBOOT/RE-LOGIN REQUIRED: Docker Desktop, WSL, or PATH changes need a new session. Re-run install.ps1 afterward — it resumes cleanly." -ForegroundColor Yellow
    }
    Write-Host " Quick start (open a NEW terminal if PATH was just updated):" -ForegroundColor Cyan
    Write-Host "   bp --doctor                 re-check environment"
    Write-Host "   bp --menu                   terminal menu"
    Write-Host "   bp                          WebUI daemon + browser (default)"
    Write-Host ""
    Write-Host " Only run against systems you own or are explicitly authorized to test." -ForegroundColor DarkGray
    Write-Host " Installer log: $script:LogFile"
}

# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

function Invoke-Main {
    Initialize-Logging -ExplicitPath $LogPath
    try { $script:SupportsColor = ($Host.UI.SupportsVirtualTerminal -ne $false) } catch { $script:SupportsColor = $true }

    $scriptRoot = ""
    try { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path } catch { $scriptRoot = (Get-Location).Path }
    $installDir = Resolve-InstallDir -Requested $InstallDir -ScriptRoot $scriptRoot
    Write-Log "InstallDir resolved: $installDir (script root: $scriptRoot)" -Level "INFO"

    if ($Uninstall) {
        $platform = Get-PlatformInfo
        Show-Header -Platform $platform -InstallDir $installDir
        return (Remove-BreachPilot -InstallDir $installDir)
    }

    if ($Check) {
        return (Invoke-CheckMode -InstallDir $installDir)
    }

    if ($Repair) {
        $platform = Get-PlatformInfo
        Show-Header -Platform $platform -InstallDir $installDir
        if (-not (Test-PlatformSupported -Platform $platform)) { return $script:ExitUnsupported }
        $script:PhaseTotal = 8
        Write-Step "Verifying install + repairing"
        $res = Invoke-RepairMode -InstallDir $installDir
        Write-StepDone
        Show-FinalSummary -InstallDir $installDir -VenvPython $res.VenvPython -Resolved (
            [pscustomobject]@{ Tag = ""; Sha = "unknown"; Channel = "Repair" }
        ) -ArchiveSha256 "" -Sandbox @{ Status = "see-above" } -WebUI @{ Built = $false; Skipped = $true } `
            -DoctorStatus $(if ($res.Code -eq 0) { "PASS" } else { "FAIL" }) -ExitCode $res.Code
        return $res.Code
    }

    # ---- Install / Update shared flow ----
    $platform = Get-PlatformInfo
    Show-Header -Platform $platform -InstallDir $installDir
    if (-not (Test-PlatformSupported -Platform $platform)) { return $script:ExitUnsupported }
    if (-not $platform.WingetPresent -and -not $Offline) {
        Write-Warn "winget not found — missing tools will need manual install (https://aka.ms/getwinget)."
    }

    $existingMeta = Read-InstallMetadata -InstallDir $installDir
    $hasExisting = (Test-Path -LiteralPath (Join-Path $installDir "main.py"))
    if ($Update -and -not $hasExisting -and ($null -eq $existingMeta)) {
        Write-Fail "No existing install at $installDir to update. Run plain 'install.ps1' for a fresh install (or point -InstallDir at the existing one)."
        return $script:ExitInvalidArgs
    }
    $__existCorrupt = [bool](Get-PropValue -Object $existingMeta -Name "Corrupt" -Default $false)
    if ((-not $Update) -and $hasExisting -and ($null -ne $existingMeta) -and (-not $__existCorrupt) -and -not $Force) {
        $__exTag = [string](Get-PropValue -Object $existingMeta -Name "tag" -Default "")
        $__exCommit = [string](Get-PropValue -Object $existingMeta -Name "commit" -Default "")
        Write-Info "Existing managed install detected at $installDir ($__exTag $__exCommit). Re-running as repair/update of that install — user data preserved."
    }
    $interrupted = Test-InterruptedInstall -InstallDir $installDir
    $__intInterrupted = [bool](Get-PropValue -Object $interrupted -Name "Interrupted" -Default $false)
    if ($__intInterrupted) {
        $__intState = [string](Get-PropValue -Object $interrupted -Name "State" -Default "?")
        $__intBackup = [string](Get-PropValue -Object $interrupted -Name "BackupDir" -Default "")
        Write-Warn "Interrupted previous run detected (state '$__intState') — recovering: verifying what completed before continuing."
        Write-Log "Interrupted state: $__intState; backup: $__intBackup" -Level "WARN"
    }

    # ---- Phase: resolve version ----
    $script:PhaseTotal = 12
    Write-Step "Resolving BreachPilot version"
    $__existCorruptOff = [bool](Get-PropValue -Object $existingMeta -Name "Corrupt" -Default $false)
    if ($Offline -and (($null -eq $existingMeta) -or $__existCorruptOff)) {
        Write-Fail "-Offline given but no usable local metadata to resolve from. Connect once (or supply a staged tree) and re-run."
        return $script:ExitDownload
    }
    try {
        $resolved = Resolve-BreachPilotVersion
    } catch {
        Write-Fail "Version resolution failed: $($_.Exception.Message)"
        Write-Log "Version resolution error: $($_.Exception.Message)" -Level "ERROR"
        return $script:ExitDownload
    }
    $__existCorruptUpd = [bool](Get-PropValue -Object $existingMeta -Name "Corrupt" -Default $false)
    if ($Update -and ($null -ne $existingMeta) -and (-not $__existCorruptUpd)) {
        $sameTag = ((-not [string]::IsNullOrWhiteSpace($resolved.Tag)) -and ($resolved.Tag -eq [string](Get-PropValue -Object $existingMeta -Name "tag" -Default "")))
        $sameSha = ((-not [string]::IsNullOrWhiteSpace($resolved.Sha)) -and ($resolved.Sha -eq [string](Get-PropValue -Object $existingMeta -Name "commit" -Default "")))
        if (($sameTag -or $sameSha) -and -not $Force) {
            Write-Host ""
            Write-Host "Already up to date ($($resolved.Tag) $($resolved.Sha.Substring(0, 12))). Nothing to do." -ForegroundColor Green
            Write-Host "Installer log: $script:LogFile"
            return $script:ExitSuccess
        }
    }
    if ($hasExisting) {
        $checkout = Get-CheckoutStatus -Dir $installDir
        $safety = Test-CheckoutSafe -Checkout $checkout
        $__safeOk = [bool](Get-PropValue -Object $safety -Name "Safe" -Default $false)
        $__safeReason = [string](Get-PropValue -Object $safety -Name "Reason" -Default "?")
        if ((-not $__safeOk) -and -not $Force) {
            Write-Fail $__safeReason
            return $script:ExitInvalidArgs
        } elseif (-not $__safeOk) {
            Write-Warn "Proceeding despite checkout concern (-Force): $__safeReason"
        } else {
            Write-Log "Checkout safety: $__safeReason" -Level "INFO"
        }
    }
    Write-InstallState -InstallDir $installDir -State "resolving"
    Write-StepDone

    # ---- Phase: acquire source (staging) ----
    $stagingParent = Join-Path ([System.IO.Path]::GetTempPath()) ("BreachPilot-Install-" + [guid]::NewGuid().ToString("N"))
    $archiveSha = ""
    $stagedRoot = ""
    # Function scope: the backup made during deploy must survive to the doctor
    # gate (rollback) and finalizing (KeepBackup/delete). Never re-declared.
    $deployBackupDir = ""
    try {
        New-Item -ItemType Directory -Path $stagingParent -Force | Out-Null
    } catch {
        Write-Fail "Cannot create staging dir $stagingParent`: $($_.Exception.Message)"
        return $script:ExitFailure
    }
    try {
        $runningFromCheckout = $false
        try {
            $fullScript = [System.IO.Path]::GetFullPath($scriptRoot)
            $fullInstall = [System.IO.Path]::GetFullPath($installDir)
            $runningFromCheckout = $fullScript.TrimEnd("\").Equals($fullInstall.TrimEnd("\"), [StringComparison]::OrdinalIgnoreCase)
        } catch { }
        if ($runningFromCheckout -and -not $Update -and -not $Force) {
            # Already inside the desired tree: skip download, validate in place,
            # still run the full dependency/doctor pipeline below.
            Write-Step "Validating package"
            Write-Info "Running from inside the install tree — validating in place (no download, no file replacement)."
            foreach ($req in $script:RequiredSourceFiles) {
                if (-not (Test-Path -LiteralPath (Join-Path $installDir $req))) {
                    Write-Fail "Current tree is not a valid BreachPilot source tree: missing '$req'."
                    return $script:ExitValidation
                }
            }
            Write-Ok "Package validated (in-place checkout)."
            $stagedRoot = $installDir
            Write-InstallState -InstallDir $installDir -State "staged"
            Write-StepDone
        } else {
            Write-Step "Downloading source"
            Write-InstallState -InstallDir $installDir -State "downloading"
            $zipPath = Join-Path $stagingParent "breachpilot-source.zip"
            try {
                $archiveSha = Get-BreachPilotArchive -Resolved $resolved -DestinationZip $zipPath
            } catch {
                Write-Fail "Download failed: $($_.Exception.Message)"
                return $script:ExitDownload
            }
            Write-StepDone

            Write-Step "Validating package"
            try {
                $extractDir = Join-Path $stagingParent "extract"
                New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
                $stagedRoot = Expand-ValidatedArchive -ZipPath $zipPath -StagingDir $extractDir
                try { Remove-Item -LiteralPath $zipPath -Force } catch { }
            } catch {
                Write-Fail "Package validation failed: $($_.Exception.Message)"
                return $script:ExitValidation
            }
            Write-InstallState -InstallDir $installDir -State "staged"
            Write-StepDone

            # ---- Phase: atomic deploy ----
            Write-Step "Deploying (backup + atomic replace)"
            Write-InstallState -InstallDir $installDir -State "backup_created"
            $backupRef = ""
            $backupHolder = @{ Value = "" }
            try {
                if ($runningFromCheckout) {
                    # Updating the very checkout we run from: never move the live
                    # dir (we execute from it). Copy staged files over the top,
                    # excluding runtime/user data + ourselves.
                    $deployBackupDir = Backup-BreachPilotInstall -InstallDir $installDir
                    $backupHolder.Value = $deployBackupDir
                    try {
                        Set-Content -LiteralPath (Join-Path $installDir $script:StateFileName + ".backup") -Value $deployBackupDir -Encoding UTF8
                    } catch { }
                    $excl = @(".venv", "venv", "__pycache__", ".git", "node_modules", "webui\node_modules", "webui\dist",
                        "reports", "exploit_workspace", "research_workspace", "swarm_workspace",
                        "secr.json", ".env", ".webui_secret_key", "*.db", "*.log",
                        $script:MetadataFileName, $script:StateFileName) + $script:PreserveNames
                    foreach ($item in (Get-ChildItem -LiteralPath $stagedRoot -Force)) {
                        if ($excl -contains $item.Name) { continue }
                        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $installDir $item.Name) -Recurse -Force
                    }
                    $__depLabel = [string](Get-PropValue -Object $resolved -Name "Tag" -Default "")
                    if ([string]::IsNullOrWhiteSpace($__depLabel)) { $__depLabel = [string](Get-PropValue -Object $resolved -Name "Sha" -Default "?") }
                    Write-Ok "In-place checkout refreshed from $__depLabel (user data + venv + .git untouched)."
                } else {
                    $backupHolder.Value = Deploy-StagedTree -InstallDir $installDir -StagedRoot $stagedRoot -BackupDirOut ([ref]$backupRef)
                    $deployBackupDir = $backupHolder.Value
                    try {
                        Set-Content -LiteralPath (Join-Path $installDir $script:StateFileName + ".backup") -Value $deployBackupDir -Encoding UTF8
                    } catch { }
                }
            } catch {
                Write-Fail "Deploy failed: $($_.Exception.Message)"
                $bd = $backupHolder.Value
                if (-not [string]::IsNullOrWhiteSpace($bd)) {
                    try {
                        Restore-BreachPilotInstall -InstallDir $installDir -BackupDir $bd
                        Write-InstallState -InstallDir $installDir -State "rollback"
                        return $script:ExitRolledBack
                    } catch {
                        Write-Fail "ROLLBACK FAILED: $($_.Exception.Message)"
                        return $script:ExitFailure
                    }
                }
                return $script:ExitFailure
            }
            $backupRef = $backupHolder.Value
            Write-InstallState -InstallDir $installDir -State "deploying"
            Write-StepDone
        }
    } finally {
        if ((Test-Path -LiteralPath $stagingParent) -and ($stagedRoot -ne $installDir)) {
            try { Remove-Item -LiteralPath $stagingParent -Recurse -Force } catch {
                Write-Log "Staging cleanup incomplete: $($_.Exception.Message)" -Level "WARN"
            }
        }
    }
    # ---- Dependency phases ----
    Write-Step "Python"
    try {
        $python = Install-PythonEnvironment
    } catch {
        Write-Fail "Python setup failed: $($_.Exception.Message)"
        return $script:ExitDependency
    }
    try {
        $pv = Invoke-ExternalCommand -Command $python.Path -Arguments (@() + $python.ExtraArgs + @("--version")) -TimeoutSeconds 15 -AllowFailure
        $pp = Invoke-ExternalCommand -Command $python.Path -Arguments (@() + $python.ExtraArgs + @("-m", "pip", "--version")) -TimeoutSeconds 20 -AllowFailure
        if ($pv.ExitCode -ne 0 -or $pp.ExitCode -ne 0) {
            Write-Fail "Python verification failed: 'python --version' / 'python -m pip --version' must both succeed."
            return $script:ExitDependency
        }
        Write-Ok "Verified: $($pv.StdOut.Trim()) / $($pp.StdOut.Trim().Split("`n")[0])"
    } catch {
        Write-Fail "Python verification failed: $($_.Exception.Message)"
        return $script:ExitDependency
    }
    Write-StepDone

    Write-Step "Python environment"
    Write-InstallState -InstallDir $installDir -State "dependencies"
    try {
        $venvPython = Install-VenvAndDeps -Python $python -InstallDir $installDir
    } catch {
        Write-Fail "Python environment setup failed: $($_.Exception.Message)"
        return $script:ExitDependency
    }
    Write-StepDone

    Write-Step "System tools"
    Install-NmapIfNeeded -InstallDir $installDir | Out-Null
    $gitInfo = Test-GitInstall
    if ([bool](Get-PropValue -Object $gitInfo -Name "Present" -Default $false)) { Write-Ok "Git: $((Get-PropValue -Object $gitInfo -Name "Version" -Default "?"))" }
    else { Write-Skip "Git not installed — optional (source ZIP path works without it). Manual: https://git-scm.com/downloads" }
    Install-OllamaIfNeeded -InstallDir $installDir | Out-Null
    Write-StepDone

    Write-Step "WebUI"
    $webuiResult = Install-WebUI -InstallDir $installDir -VenvPython $venvPython
    Write-StepDone

    Write-Step "Docker sandbox"
    $sandboxResult = Install-SandboxImage -InstallDir $installDir
    Write-StepDone

    Write-Step "Launcher"
    Install-Launcher -InstallDir $installDir -VenvPython $venvPython | Out-Null
    $binDir = Get-LauncherDir
    $pathRes = Add-UserPath -Entry $binDir
    Install-Shortcuts -InstallDir $installDir
    Request-ApiKeySetup -InstallDir $installDir -VenvPython $venvPython
    Write-StepDone

    Write-Step "Doctor"
    Write-InstallState -InstallDir $installDir -State "validating"
    $dr = Invoke-BreachPilotDoctor -VenvPython $venvPython -InstallDir $installDir
    $dj = Get-DoctorJson -VenvPython $venvPython
    $cls = Test-DoctorResult -DoctorJson $dj -ExitCode $dr.ExitCode
    $doctorStatus = ""
    $finalCode = $script:ExitSuccess
    switch ($cls.Status) {
        "pass" { $doctorStatus = "PASS"; Write-Ok "Doctor passed — you're ready to run!" }
        "warnings" { $doctorStatus = "PASS (warnings)"; Write-Warn "Doctor passed with warnings — see action items." }
        "action-required" { $doctorStatus = "ACTION REQUIRED"; Write-Warn "Doctor: $($cls.Detail)"; $finalCode = $script:ExitActionRequired }
        "fail" { $doctorStatus = "FAIL"; Write-Fail "Doctor hard failures: $($cls.Detail)" }
    }
    if ($cls.Status -eq "fail") {
        # Critical validation failed AFTER replacing files: roll back (update) or
        # fail loudly (fresh install has no backup to restore).
        if ((-not [string]::IsNullOrWhiteSpace($backupDir)) -and (Test-Path -LiteralPath $backupDir)) {
            try {
                Restore-BreachPilotInstall -InstallDir $installDir -BackupDir $backupDir
                Write-InstallState -InstallDir $installDir -State "rollback"
                Show-FinalSummary -InstallDir $installDir -VenvPython $venvPython -Resolved $resolved `
                    -ArchiveSha256 $archiveSha -Sandbox $sandboxResult -WebUI $webuiResult `
                    -DoctorStatus "ROLLED BACK" -ExitCode $script:ExitRolledBack
                return $script:ExitRolledBack
            } catch {
                Write-Fail "ROLLBACK FAILED: $($_.Exception.Message). Backup at '$deployBackupDir'."
                return $script:ExitFailure
            }
        }
        Write-InstallState -InstallDir $installDir -State "completed"
        Show-FinalSummary -InstallDir $installDir -VenvPython $venvPython -Resolved $resolved `
            -ArchiveSha256 $archiveSha -Sandbox $sandboxResult -WebUI $webuiResult `
            -DoctorStatus $doctorStatus -ExitCode $script:ExitDoctor
        return $script:ExitDoctor
    }
    Write-StepDone

    Write-Step "Finalizing"
    if ($null -eq $Resolved) { }
    try {
        $launcherKind = "bp.cmd+breachpilot.cmd"
        if ($NoPath) { $launcherKind = "in-install-only" }
        Write-InstallMetadata -InstallDir $installDir -Resolved $resolved -ArchiveSha256 $archiveSha -LauncherKind $launcherKind
    } catch {
        Write-Warn "Install succeeded but metadata could not be written: $($_.Exception.Message)"
    }
    # Drop an installed copy of this installer for the Uninstall shortcut + reruns.
    try {
        Copy-Item -LiteralPath $MyInvocation.MyCommand.Path -Destination (Join-Path $installDir "install.ps1") -Force
        Write-Log "Installed copy of install.ps1 refreshed." -Level "INFO"
    } catch {
        Write-Log "Could not refresh installed install.ps1 copy: $($_.Exception.Message)" -Level "WARN"
    }
    # Delete the pre-update backup after critical validation — unless -KeepBackup.
    if ((-not [string]::IsNullOrWhiteSpace($deployBackupDir)) -and (Test-Path -LiteralPath $deployBackupDir)) {
        if ($KeepBackup) {
            Write-Info "Keeping pre-update backup: $deployBackupDir (-KeepBackup)."
        } else {
            try {
                Remove-Item -LiteralPath $deployBackupDir -Recurse -Force
                Write-Log "Deleted pre-update backup after validation: $deployBackupDir" -Level "INFO"
            } catch {
                Write-Warn "Could not delete pre-update backup $deployBackupDir`: $($_.Exception.Message). Remove it manually when satisfied."
            }
        }
    }
    # Free space sanity after install.
    try {
        $freeAfter = Get-InstallDriveFreeGB -Path $installDir
        if ($freeAfter -ge 0 -and $freeAfter -lt 2) {
            Write-Warn "Only ${freeAfter} GB free on the install drive — Docker image builds and reports need headroom."
        }
    } catch { }
    Write-InstallState -InstallDir $installDir -State "completed"
    Clear-InstallState -InstallDir $installDir
    Write-StepDone

    $statusLabel = "SUCCESS"
    if ($script:HadWarning -or $finalCode -eq $script:ExitActionRequired) {
        $statusLabel = "SUCCESS WITH WARNINGS"
        if ($finalCode -eq $script:ExitSuccess) { $finalCode = $script:ExitActionRequired }
    }
    Write-Host ""
    Write-Host "Status: $statusLabel" -ForegroundColor $(if ($finalCode -eq 0) { "Green" } else { "Yellow" })
    Show-FinalSummary -InstallDir $installDir -VenvPython $venvPython -Resolved $resolved `
        -ArchiveSha256 $archiveSha -Sandbox $sandboxResult -WebUI $webuiResult `
        -DoctorStatus $doctorStatus -ExitCode $finalCode

    # Launch offer (interactive installs only; never in -Yes/-NoLaunch/remote).
    $isRemote = $platform.IsRemote
    if ((-not $NoLaunch) -and (-not $Yes) -and (-not $isRemote) -and ($finalCode -in @($script:ExitSuccess, $script:ExitActionRequired))) {
        Write-Host ""
        Write-Host " Launch BreachPilot now?"
        Write-Host "   [1] Yes — terminal menu (bp --menu)"
        Write-Host "   [2] Yes — WebUI in browser (bp --web)"
        Write-Host "   [3] No — exit installer"
        $choice = Read-Host " Choice [1/2/3, default 3]"
        if ($choice -eq "1") {
            try { Invoke-ExternalCommand -Command $venvPython -Arguments @("main.py", "--menu") -TimeoutSeconds 86400 -StreamOutput | Out-Null } catch { }
        } elseif ($choice -eq "2") {
            try { Invoke-ExternalCommand -Command $venvPython -Arguments @("main.py", "--web") -TimeoutSeconds 86400 -StreamOutput | Out-Null } catch { }
        } else {
            Write-Host " Exit. Run bp (or START.bat) when ready."
        }
    } elseif ($isRemote -and (-not $NoLaunch)) {
        Write-Info "Remote session: skipping launch offer (run 'bp --web' in a local terminal)."
    }

    return $finalCode
}

# ---------------------------------------------------------------------------
# Bootstrap: help, arg validation, logging, UX helpers
# ---------------------------------------------------------------------------

if ($Help) {
    Get-Help -Detailed ($MyInvocation.MyCommand.Path)
    exit $script:ExitSuccess
}

function Test-MutuallyExclusiveModes {
    $modes = @()
    if ($Check) { $modes += "-Check" }
    if ($Update) { $modes += "-Update" }
    if ($Repair) { $modes += "-Repair" }
    if ($Uninstall) { $modes += "-Uninstall" }
    if ($modes.Count -gt 1) {
        Write-Host "[FAIL] Modes $($modes -join ', ') are mutually exclusive. Pick at most one." -ForegroundColor Red
        exit $script:ExitInvalidArgs
    }
    if ($Offline -and $Uninstall) {
        # Uninstall is local-only; -Offline is accepted but meaningless — warn, don't fail.
        Write-Host "[WARN] -Offline has no effect combined with -Uninstall (uninstall is already offline)." -ForegroundColor Yellow
    }
}

Test-MutuallyExclusiveModes

# TLS 1.2+ without weakening validation (old WinPS 5.1 defaults to TLS 1.0).
try {
    $tls12 = [Net.SecurityProtocolType]::Tls12
    $tls13 = $null
    try { $tls13 = [Net.SecurityProtocolType]::Tls13 } catch { $tls13 = $null }
    $wanted = $tls12
    if ($tls13 -ne $null) { $wanted = $tls12 -bor $tls13 }
    [Net.ServicePointManager]::SecurityProtocol = $wanted
} catch {
    # Non-fatal: modern .NET already negotiates TLS 1.2+.
}

function Get-DefaultLogPath {
    $base = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($base)) { $base = $env:TEMP }
    if ([string]::IsNullOrWhiteSpace($base)) { $base = (Get-Location).Path }
    $dir = Join-Path $base "BreachPilot\logs"
    $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    return (Join-Path $dir "installer-$stamp.log")
}

function Initialize-Logging {
    param([string]$ExplicitPath)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $script:LogFile = $ExplicitPath
    } else {
        $script:LogFile = Get-DefaultLogPath
    }
    try {
        $dir = Split-Path -Parent $script:LogFile
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        Add-Content -LiteralPath $script:LogFile -Value "=== BreachPilot installer v$script:InstallerVersion started $(Get-Date -Format o) ===" -Encoding UTF8
    } catch {
        # Logging must never break the install; fall back to console-only.
        $script:LogFile = ""
    }
}

function Protect-SecretText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    foreach ($name in $script:SecretEnvNames) {
        $val = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrEmpty($val) -and $val.Length -ge 4) {
            $out = $out.Replace($val, "<redacted:$name>")
        }
    }
    if (-not [string]::IsNullOrEmpty($script:GitHubTokenPlain) -and $script:GitHubTokenPlain.Length -ge 4) {
        $out = $out.Replace($script:GitHubTokenPlain, "<redacted:GITHUB_TOKEN>")
    }
    if (-not [string]::IsNullOrEmpty($GitHubToken) -and $GitHubToken.Length -ge 4 -and $GitHubToken -ne $script:GitHubTokenPlain) {
        $out = $out.Replace($GitHubToken, "<redacted:GITHUB_TOKEN>")
    }
    # Generic bearer-token shapes (conservative: long alphanumerics after key= or Bearer).
    $out = [regex]::Replace($out, "(?i)(bearer\s+)[A-Za-z0-9\-._~+/=]{12,}", '$1<redacted>')
    $out = [regex]::Replace($out, "(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*['\""]?)[^'\""\s;]{8,}", '$1<redacted>')
    return $out
}

function Get-PropValue {
    <#
    .SYNOPSIS
        StrictMode-safe property read: returns $Default when the property or
        object is missing instead of throwing. THE canonical accessor for
        GitHub API JSON, doctor JSON, install metadata, and any external data.
    .NOTES
        Quoting trap: never use -Default "") INSIDE an interpolated string
        ("... $(Get-PropValue ... -Default "") ...") — the "" reads as an
        escape sequence and breaks parsing. Extract to a local first, or use
        a non-empty default ("?") when interpolating.
    #>
    param(
        $Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    # Hashtables/ordered dicts: PSObject.Properties does NOT expose keys —
    # check Contains first (works for Hashtable + OrderedDictionary).
    try {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($Name)) { return $Object[$Name] }
            return $Default
        }
    } catch { return $Default }
    try {
        $prop = $Object.PSObject.Properties[$Name]
        if ($null -eq $prop) { return $Default }
        return $prop.Value
    } catch {
        return $Default
    }
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Level] $(Protect-SecretText $Message)"
    if (-not [string]::IsNullOrWhiteSpace($script:LogFile)) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
    # Always logged to the file (console output is decided by the caller).
}

function Write-Status {
    param(
        [string]$Prefix,
        [string]$Message,
        [string]$Color = ""
    )
    $text = " $Prefix $Message"
    if ($script:SupportsColor -and -not [string]::IsNullOrEmpty($Color)) {
        Write-Host $text -ForegroundColor $Color
    } else {
        Write-Host $text
    }
    $level = "INFO"
    switch ($Prefix.Trim()) {
        "FAIL" { $level = "ERROR" }
        "WARN" { $level = "WARN"; $script:HadWarning = $true }
        "SKIP" { $level = "INFO" }
    }
    Write-Log "$Prefix $Message" -Level $level
}

function Write-Info { param([string]$Message) Write-Status -Prefix "[INFO]" -Message $Message }
function Write-Ok { param([string]$Message) Write-Status -Prefix "[ OK ]" -Message $Message -Color "Green" }
function Write-Warn {
    param([string]$Message)
    $null = $script:ActionItems.Add($Message)
    Write-Status -Prefix "[WARN]" -Message $Message -Color "Yellow"
}
function Write-Fail { param([string]$Message) Write-Status -Prefix "[FAIL]" -Message $Message -Color "Red" }
function Write-Skip { param([string]$Message) Write-Status -Prefix "[SKIP]" -Message $Message -Color "DarkGray" }
function Write-Prog { param([string]$Message) Write-Status -Prefix "[....]" -Message $Message }

function Write-Step {
    param([string]$Name)
    $script:PhaseIndex++
    $script:PhaseStart = [DateTime]::UtcNow
    $label = "[$script:PhaseIndex/$script:PhaseTotal] $Name"
    Write-Host ""
    Write-Host $label -ForegroundColor Cyan
    Write-Log "PHASE START: $label" -Level "INFO"
}

function Write-StepDone {
    $elapsed = ([DateTime]::UtcNow - $script:PhaseStart).TotalSeconds
    $msg = "done in $([math]::Round($elapsed, 1))s"
    Write-Host "       ($msg)" -ForegroundColor DarkGray
    Write-Log "PHASE END: $msg" -Level "INFO"
}

function Add-ActionRequired {
    param([string]$Message)
    $null = $script:ActionItems.Add($Message)
    Write-Log "ACTION REQUIRED: $Message" -Level "WARN"
}

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Refresh-ProcessEnvironment {
    # Re-read User + Machine env into the current process without a restart.
    # Never fails the install: PATH refresh is best-effort.
    try {
        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    } catch { $machinePath = "" }
    try {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    } catch { $userPath = "" }
    $parts = @()
    if (-not [string]::IsNullOrWhiteSpace($machinePath)) { $parts += $machinePath }
    if (-not [string]::IsNullOrWhiteSpace($userPath)) { $parts += $userPath }
    if ($parts.Count -gt 0) {
        $env:Path = ($parts -join ";")
        Write-Log "Refreshed process PATH from registry." -Level "DEBUG"
    }
    # Common tool homes that installers update only in the registry.
    foreach ($probe in @(
        @{ Name = "ProgramFiles"; Sub = "nodejs" },
        @{ Name = "ProgramFiles"; Sub = "Nmap" },
        @{ Name = "ProgramFiles"; Sub = "Git\cmd" },
        @{ Name = "ProgramW6432"; Sub = "nodejs" }
    )) {
        try {
            $root = [Environment]::GetEnvironmentVariable($probe.Name)
            if ([string]::IsNullOrWhiteSpace($root)) { continue }
            $candidate = Join-Path $root $probe.Sub
            if ((Test-Path -LiteralPath $candidate) -and ($env:Path -split ";" | Where-Object { $_.Trim() -eq $candidate.Trim() } | Measure-Object).Count -eq 0) {
                $env:Path = "$env:Path;$candidate"
                Write-Log "Appended probe dir to process PATH: $candidate" -Level "DEBUG"
            }
        } catch { }
    }
}

function Get-CommandVersion {
    param(
        [string]$Command,
        [string[]]$VersionArgs = @("--version")
    )
    try {
        $cmd = Get-Command $Command -ErrorAction SilentlyContinue
        if ($null -eq $cmd) { return $null }
        $r = Invoke-ExternalCommand -Command $Command -Arguments $VersionArgs -TimeoutSeconds 15 -AllowFailure
        if ($r.ExitCode -ne 0) { return @{ Path = $cmd.Source; Version = ""; Raw = $r.StdOut } }
        $raw = ($r.StdOut + " " + $r.StdErr).Trim()
        return @{ Path = $cmd.Source; Version = $raw; Raw = $raw }
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Entry (LAST in file: every function above must be defined before this runs)
# ---------------------------------------------------------------------------
# Dot-source guard: Pester tests dot-source this file to test its pure
# functions. Only execute the installer when run as a script, never when
# dot-sourced (in that case $MyInvocation.InvocationName is "." and the
# caller's command path differs from ours).
$__isDotSourced = $false
try {
    $__invocation = $MyInvocation.InvocationName
    if ($__invocation -eq ".") {
        $__isDotSourced = $true
    } elseif (-not [string]::IsNullOrWhiteSpace($__invocation)) {
        try {
            $__resolvedCmd = (Get-Command $__invocation -ErrorAction SilentlyContinue).Source
            if (-not [string]::IsNullOrWhiteSpace($__resolvedCmd)) {
                $__isDotSourced = -not $script:ScriptPath.TrimEnd("\").Equals(
                    ([System.IO.Path]::GetFullPath($__resolvedCmd)).TrimEnd("\"),
                    [StringComparison]::OrdinalIgnoreCase)
            }
        } catch { $__isDotSourced = $false }
    }
} catch { $__isDotSourced = $false }

if (-not $__isDotSourced) {
    $code = $script:ExitFailure
    try {
        $code = Invoke-Main
    } catch {
        $msg = Protect-SecretText $_.Exception.Message
        # Write-Log/Write-Fail are defined above by the time we get here.
        Write-Fail "Fatal: $msg"
        Write-Log "FATAL: $($_.ScriptStackTrace)" -Level "ERROR"
        $code = $script:ExitFailure
    }
    if (-not [string]::IsNullOrWhiteSpace($script:LogFile)) {
        Write-Host "Installer log: $script:LogFile"
    }
    exit $code
}
