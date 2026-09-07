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
# Auth token resolution (env fallback). Never printed or logged (Redact-Secrets).
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
        [switch]$StreamOutput
    )
    $argString = Join-CommandArguments -Arguments $Arguments
    $display = (Redact-Secrets "$Command $argString").Trim()
    Write-Log "RUN: $display (timeout ${TimeoutSeconds}s)" -Level "DEBUG"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Command
    $psi.Arguments = $argString
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
            $clean = Redact-Secrets $msg
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
                $sha = [string]$commit.sha
                if ([string]::IsNullOrWhiteSpace($sha)) { throw "NONRETRY: GitHub returned an empty commit SHA for tag $tag." }
                Write-Ok "Resolved version $tag (commit $($sha.Substring(0, 12)))"
                return [pscustomobject]@{
                    Channel      = "Explicit"
                    Tag          = $tag
                    Sha          = $sha
                    PublishedAt  = [string]$rel.published_at
                    IsPrerelease = [bool]$rel.prerelease
                    Name         = [string]$rel.name
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
        $branch = [string]$repo.default_branch
        if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "main" }
        $commit = Invoke-WithRetry -Operation "fetch HEAD of $branch" -Script {
            Invoke-GitHubApi -Path "/repos/$script:SourceFull/commits/$branch"
        }
        $sha = [string]$commit.sha
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
    $usable = @($releases | Where-Object { (-not [bool]$_.draft) } )
    if ($Channel -eq "Stable") {
        $usable = @($usable | Where-Object { (-not [bool]$_.prerelease) })
    }
    if ($usable.Count -eq 0) {
        if ($Channel -eq "Stable") {
            throw "NONRETRY: No stable (non-draft, non-prerelease) release exists in $script:SourceFull. This is NOT silently substituted: re-run with -Channel Prerelease (newest prerelease/release) or -Channel Main (default-branch HEAD), or pin -Version to an existing tag. See https://github.com/$script:SourceFull/releases."
        }
        throw "NONRETRY: No releases at all (not even prereleases) exist in $script:SourceFull. Re-run with -Channel Main or pin -Version to an existing tag."
    }
    $best = $usable | Sort-Object -Property published_at -Descending | Select-Object -First 1
    $tag = [string]$best.tag_name
    $commit = Invoke-WithRetry -Operation "resolve commit for tag $tag" -Script {
        Invoke-GitHubApi -Path "/repos/$script:SourceFull/commits/$tag"
    }
    $sha = [string]$commit.sha
    if ([string]::IsNullOrWhiteSpace($sha)) { throw "NONRETRY: GitHub returned an empty commit SHA for tag $tag." }
    $pre = ""
    if ([bool]$best.prerelease) { $pre = " (prerelease)" }
    Write-Ok "Resolved $label release $tag$pre (commit $($sha.Substring(0, 12)))"
    return [pscustomobject]@{
        Channel      = $label
        Tag          = $tag
        Sha          = $sha
        PublishedAt  = [string]$best.published_at
        IsPrerelease = [bool]$best.prerelease
        Name         = [string]$best.name
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
    Confirm-ReleaseChecksum -Resolved $Resolved -ArchivePath $DestinationZip -ArchiveSha256 $hash
    return $hash
}

function Confirm-ReleaseChecksum {
    param(
        [pscustomobject]$Resolved,
        [string]$ArchivePath,
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
    if ($null -ne $rel.assets) { $assets = @($rel.assets) }
    $sumAsset = $assets | Where-Object { [string]$_.name -match "(?i)(sha256|sha-256|checksum)" } | Select-Object -First 1
    if ($null -eq $sumAsset) {
        Write-Skip "Release $($Resolved.Tag) publishes no checksum asset; trusting HTTPS + resolved tag identity (SHA-256 recorded in metadata for diagnostics)."
        Write-Log "No checksum asset on release $($Resolved.Tag); calculated SHA-256 recorded." -Level "INFO"
        return
    }
    Write-Prog "Verifying against official checksum asset '$($sumAsset.name)'..."
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("bp-checksum-" + [guid]::NewGuid().ToString("N") + ".txt")
    try {
        Invoke-WithRetry -Operation "download checksum asset" -Script {
            Invoke-WebRequest -Uri ([string]$sumAsset.browser_download_url) -OutFile $tmp -UseBasicParsing `
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
            Write-Skip "Checksum asset '$($sumAsset.name)' had no parseable SHA-256; trusting HTTPS + tag identity (hash recorded)."
            return
        }
        if ($wanted -ne $ArchiveSha256) {
            throw "NONRETRY: Official checksum mismatch for $($Resolved.Tag): archive SHA-256 $ArchiveSha256 != published $wanted. Deleted partial state; refusing to install."
        }
        if ($matched) { Write-Ok "Official checksum verified ($($sumAsset.name))." }
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
    $usable = @($Releases | Where-Object { $_ -ne $null -and (-not [bool]$_.draft) })
    if ($WantedChannel -eq "Stable") {
        $usable = @($usable | Where-Object { (-not [bool]$_.prerelease) })
    }
    if ($usable.Count -eq 0) { return $null }
    return ($usable | Sort-Object -Property published_at -Descending | Select-Object -First 1)
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
    param([pscustomobject]$Checkout, [string]$Dir)
    if ($null -eq $Checkout -or -not $Checkout.IsGit) { return @{ Safe = $true; Reason = "not a git checkout" } }
    if (-not $Checkout.GitAvailable) { return @{ Safe = $true; Reason = "git unavailable; treating as plain directory" } }
    if (-not $Checkout.OriginMatches) {
        return @{ Safe = $false; Reason = "directory is a git checkout whose origin ('$($Checkout.Origin)') is NOT $script:SourceFull. Refusing to touch a foreign repository — choose a different -InstallDir." }
    }
    if ($Checkout.IsDirty) {
        return @{ Safe = $false; Reason = "git checkout has uncommitted changes (branch $($Checkout.Branch), $($Checkout.Sha)). Commit or stash them first, or re-run with -Force to update anyway (a backup is still taken; `git reset --hard` / `git clean -fdx` are NEVER run automatically)." }
    }
    return @{ Safe = $true; Reason = "clean checkout of $script:SourceFull ($($Checkout.Branch)@$($Checkout.Sha))" }
}

# __PART4__

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

function Redact-Secrets {
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

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Level] $(Redact-Secrets $Message)"
    if (-not [string]::IsNullOrWhiteSpace($script:LogFile)) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
    if ($Level -eq "DEBUG" -and -not $PSBoundParameters.ContainsKey("Verbose") -and $VerbosePreference -eq "SilentlyContinue") {
        return
    }
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
