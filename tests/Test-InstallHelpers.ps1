<#
.SYNOPSIS
    Pester tests for install.ps1 pure helpers (no network, no installs).

.DESCRIPTION
    Dot-sources install.ps1 (its dot-source guard prevents execution) and
    exercises: semver comparison, release/channel selection, ZIP traversal
    rejection, metadata round-trip, PATH dedup, Python/Node version parsing,
    admin detection shape, interrupted-state logic, argument validation, and
    secret redaction. All hermetic — external commands and web requests are
    never issued by the functions under test.

    Run: Invoke-Pester tests/Test-InstallHelpers.ps1
    CI:  .github/workflows/installer-windows.yml
#>

BeforeAll {
    $script:InstallerPath = Join-Path $PSScriptRoot ".." "install.ps1"
    if (-not (Test-Path -LiteralPath $script:InstallerPath)) {
        throw "install.ps1 not found at $script:InstallerPath"
    }
    . $script:InstallerPath
}

Describe "install.ps1 dot-sourcing" {
    It "loads without executing the installer" {
        # If the guard failed, Invoke-Main would have run (network/PATH writes).
        # Reaching here proves the guard held.
        (Get-Command Get-PropValue -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        (Get-Command Compare-SemVersion -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        (Get-Command Invoke-Main -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
}

Describe "Get-PropValue" {
    It "reads present hashtable keys" {
        Get-PropValue -Object @{ Healthy = $true } -Name "Healthy" -Default $false | Should -Be $true
    }
    It "returns the default for missing hashtable keys (no throw under StrictMode)" {
        Get-PropValue -Object @{ Healthy = $true } -Name "NeedsDeps" -Default $false | Should -Be $false
        Get-PropValue -Object @{ a = 1 } -Name "b" -Default "dflt" | Should -Be "dflt"
    }
    It "reads PSCustomObject properties and defaults on missing" {
        $o = [pscustomobject]@{ a = 1 }
        Get-PropValue -Object $o -Name "a" -Default 0 | Should -Be 1
        Get-PropValue -Object $o -Name "b" -Default "dflt" | Should -Be "dflt"
    }
    It "returns the default for a null object" {
        Get-PropValue -Object $null -Name "x" -Default "dflt" | Should -Be "dflt"
    }
    It "reads ConvertFrom-Json output" {
        $j = '{"tag":"v1","commit":"abc"}' | ConvertFrom-Json
        Get-PropValue -Object $j -Name "tag" -Default "" | Should -Be "v1"
        Get-PropValue -Object $j -Name "nope" -Default "dflt" | Should -Be "dflt"
    }
}

Describe "Compare-SemVersion" {
    It "treats v-prefixed and bare versions as equal" {
        Compare-SemVersion -A "v1.2.3" -B "1.2.3" | Should -Be 0
    }
    It "orders numerically, not lexically" {
        Compare-SemVersion -A "0.68.4" -B "0.69.0" | Should -Be -1
        Compare-SemVersion -A "0.9.0" -B "0.10.0" | Should -Be -1
        Compare-SemVersion -A "1.10.0" -B "1.9.9" | Should -Be 1
    }
    It "pads missing minor/patch with zero" {
        Compare-SemVersion -A "1.2" -B "1.2.0" | Should -Be 0
        Compare-SemVersion -A "2" -B "1.9.9" | Should -Be 1
    }
    It "ranks a release above its own prerelease" {
        Compare-SemVersion -A "1.2.3-beta" -B "1.2.3" | Should -Be -1
        Compare-SemVersion -A "1.2.3" -B "1.2.3-beta" | Should -Be 1
    }
    It "returns null for non-numeric garbage" {
        Compare-SemVersion -A "not-a-version" -B "1.0.0" | Should -BeNullOrEmpty
    }
}

Describe "Select-GitHubRelease" {
    BeforeAll {
        $script:Releases = @(
            [pscustomobject]@{ tag_name = "v0.1.0"; draft = $false; prerelease = $false; published_at = "2026-01-01T00:00:00Z" },
            [pscustomobject]@{ tag_name = "v0.2.0"; draft = $false; prerelease = $false; published_at = "2026-02-15T00:00:00Z" },
            [pscustomobject]@{ tag_name = "v0.3.0-beta"; draft = $false; prerelease = $true; published_at = "2026-03-01T00:00:00Z" },
            [pscustomobject]@{ tag_name = "v0.4.0-draft"; draft = $true; prerelease = $false; published_at = "2026-04-01T00:00:00Z" }
        )
    }
    It "Stable picks the newest non-draft non-prerelease" {
        $best = Select-GitHubRelease -Releases $script:Releases -WantedChannel "Stable"
        $best.tag_name | Should -Be "v0.2.0"
    }
    It "Stable never picks drafts even when newest" {
        $only = @([pscustomobject]@{ tag_name = "v9-draft"; draft = $true; prerelease = $false; published_at = "2026-09-01T00:00:00Z" })
        Select-GitHubRelease -Releases $only -WantedChannel "Stable" | Should -BeNullOrEmpty
    }
    It "Prerelease includes prereleases but still excludes drafts" {
        $best = Select-GitHubRelease -Releases $script:Releases -WantedChannel "Prerelease"
        $best.tag_name | Should -Be "v0.3.0-beta"
    }
    It "returns null when nothing qualifies" {
        Select-GitHubRelease -Releases @() -WantedChannel "Stable" | Should -BeNullOrEmpty
        Select-GitHubRelease -Releases $null -WantedChannel "Stable" | Should -BeNullOrEmpty
    }
}

Describe "Test-PythonVersionSupported" {
    It "accepts 3.11+" {
        Test-PythonVersionSupported -VersionText "Python 3.11.0" | Should -Be $true
        Test-PythonVersionSupported -VersionText "Python 3.12.4" | Should -Be $true
        Test-PythonVersionSupported -VersionText "Python 3.13.5" | Should -Be $true
        Test-PythonVersionSupported -VersionText "Python 3.14.0" | Should -Be $true
    }
    It "rejects 3.10 and below" {
        Test-PythonVersionSupported -VersionText "Python 3.10.9" | Should -Be $false
        Test-PythonVersionSupported -VersionText "Python 2.7.18" | Should -Be $false
    }
    It "rejects empty/unparseable input" {
        Test-PythonVersionSupported -VersionText "" | Should -Be $false
        Test-PythonVersionSupported -VersionText "no python here" | Should -Be $false
    }
}

Describe "Node version helpers" {
    It "parses node --version majors" {
        Get-NodeMajorVersion -VersionText "v22.11.0" | Should -Be 22
        Get-NodeMajorVersion -VersionText "v18.0.0" | Should -Be 18
        Get-NodeMajorVersion -VersionText "" | Should -Be -1
        Get-NodeMajorVersion -VersionText "garbage" | Should -Be -1
    }
    It "gates on major >= 18" {
        Test-NodeVersionSupported -VersionText "v22.11.0" | Should -Be $true
        Test-NodeVersionSupported -VersionText "v18.0.0" | Should -Be $true
        Test-NodeVersionSupported -VersionText "v16.20.0" | Should -Be $false
    }
}

Describe "Join-NormalizedPath" {
    It "appends a missing entry" {
        $r = Join-NormalizedPath -CurrentPath "C:\\A;C:\\B" -Entry "C:\\C"
        $r.Changed | Should -Be $true
        $r.Path | Should -Be "C:\\A;C:\\B;C:\\C"
    }
    It "dedups case-insensitively without touching existing entries" {
        $r = Join-NormalizedPath -CurrentPath "C:\\A;c:\\tools\\Bp" -Entry "C:\\TOOLS\\bp\\"
        $r.Changed | Should -Be $false
        $r.Path | Should -Be "C:\\A;c:\\tools\\Bp"
    }
    It "handles an empty current PATH" {
        $r = Join-NormalizedPath -CurrentPath "" -Entry "C:\\Tools\\Bp"
        $r.Changed | Should -Be $true
        $r.Path | Should -Be "C:\\Tools\\Bp"
    }
    It "refuses PATH growth past the Windows limit" {
        $huge = ("C:\\x" * 9000) -join ";"
        Join-NormalizedPath -CurrentPath $huge -Entry "C:\\Tools\\Bp" | Should -BeNullOrEmpty
    }
}

Describe "Test-GitRemoteMatches" {
    It "accepts https/ssh/git origins of braydos-h/BreachPilot" {
        Test-GitRemoteMatches -RemoteUrl "https://github.com/braydos-h/BreachPilot.git" | Should -Be $true
        Test-GitRemoteMatches -RemoteUrl "https://github.com/braydos-h/BreachPilot" | Should -Be $true
        Test-GitRemoteMatches -RemoteUrl "git@github.com:braydos-h/BreachPilot.git" | Should -Be $true
    }
    It "rejects foreign repositories" {
        Test-GitRemoteMatches -RemoteUrl "https://github.com/evil-org/BreachPilot.git" | Should -Be $false
        Test-GitRemoteMatches -RemoteUrl "https://github.com/braydos-h/OtherRepo.git" | Should -Be $false
        Test-GitRemoteMatches -RemoteUrl "" | Should -Be $false
    }
}

Describe "Test-ZipEntrySafe" {
    BeforeAll {
        $script:StageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("bp-pester-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $script:StageRoot -Force | Out-Null
    }
    AfterAll {
        if (Test-Path -LiteralPath $script:StageRoot) {
            Remove-Item -LiteralPath $script:StageRoot -Recurse -Force
        }
    }
    It "accepts normal archive entries" {
        Test-ZipEntrySafe -EntryName "BreachPilot-main/main.py" -StagingRoot $script:StageRoot | Should -Be $true
    }
    It "rejects parent-directory traversal" {
        Test-ZipEntrySafe -EntryName "../evil.ps1" -StagingRoot $script:StageRoot | Should -Be $false
        Test-ZipEntrySafe -EntryName "a/../../evil.ps1" -StagingRoot $script:StageRoot | Should -Be $false
    }
    It "rejects absolute paths and drive-qualified entries" {
        Test-ZipEntrySafe -EntryName "/etc/cron.d/evil" -StagingRoot $script:StageRoot | Should -Be $false
        Test-ZipEntrySafe -EntryName "C:/Windows/evil.exe" -StagingRoot $script:StageRoot | Should -Be $false
    }
    It "rejects backslash traversal" {
        Test-ZipEntrySafe -EntryName "..\\evil.ps1" -StagingRoot $script:StageRoot | Should -Be $false
    }
}

Describe "Install metadata round-trip" {
    BeforeAll {
        $script:MetaDir = Join-Path ([System.IO.Path]::GetTempPath()) ("bp-meta-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $script:MetaDir -Force | Out-Null
    }
    AfterAll {
        if (Test-Path -LiteralPath $script:MetaDir) {
            Remove-Item -LiteralPath $script:MetaDir -Recurse -Force
        }
    }
    It "writes metadata without secrets and reads it back" {
        $resolved = [pscustomobject]@{
            Channel = "Stable"; Tag = "v0.68.4"; Sha = "abc123def456"
        }
        Write-InstallMetadata -InstallDir $script:MetaDir -Resolved $resolved -ArchiveSha256 "deadbeef" -LauncherKind "test"
        $back = Read-InstallMetadata -InstallDir $script:MetaDir
        $back.tag | Should -Be "v0.68.4"
        $back.commit | Should -Be "abc123def456"
        $back.channel | Should -Be "Stable"
        $raw = Get-Content -LiteralPath (Join-Path $script:MetaDir ".breachpilot-install.json") -Raw
        $raw | Should -Not -Match "(?i)token|secret|api[_-]?key"
    }
    It "reports corrupt metadata instead of throwing" {
        Set-Content -LiteralPath (Join-Path $script:MetaDir ".breachpilot-install.json") -Value "{not json" -Encoding UTF8
        $back = Read-InstallMetadata -InstallDir $script:MetaDir
        $back.Corrupt | Should -Be $true
    }
    It "returns null when no metadata exists" {
        Remove-Item -LiteralPath (Join-Path $script:MetaDir ".breachpilot-install.json") -Force
        Read-InstallMetadata -InstallDir $script:MetaDir | Should -BeNullOrEmpty
    }
}

Describe "Install state machine" {
    BeforeAll {
        $script:StateDir = Join-Path ([System.IO.Path]::GetTempPath()) ("bp-state-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null
    }
    AfterAll {
        if (Test-Path -LiteralPath $script:StateDir) {
            Remove-Item -LiteralPath $script:StateDir -Recurse -Force
        }
    }
    It "reports no interruption for a fresh directory" {
        $r = Test-InterruptedInstall -InstallDir $script:StateDir
        $r.Interrupted | Should -Be $false
    }
    It "detects an unfinished run" {
        Write-InstallState -InstallDir $script:StateDir -State "downloading"
        $r = Test-InterruptedInstall -InstallDir $script:StateDir
        $r.Interrupted | Should -Be $true
        $r.State | Should -Be "downloading"
    }
    It "treats completed as clean" {
        Write-InstallState -InstallDir $script:StateDir -State "completed"
        $r = Test-InterruptedInstall -InstallDir $script:StateDir
        $r.Interrupted | Should -Be $false
    }
    It "clears state" {
        Clear-InstallState -InstallDir $script:StateDir
        (Test-Path -LiteralPath (Join-Path $script:StateDir ".breachpilot-install.state")) | Should -Be $false
    }
}

Describe "Test-CheckoutSafe" {
    It "allows non-git directories" {
        $r = Test-CheckoutSafe -Checkout $null
        $r.Safe | Should -Be $true
    }
    It "allows clean checkouts of the expected repo" {
        $co = [pscustomobject]@{
            IsGit = $true; GitAvailable = $true; Origin = "https://github.com/braydos-h/BreachPilot.git"
            OriginMatches = $true; Branch = "main"; Sha = "abc123"; IsDirty = $false
        }
        $r = Test-CheckoutSafe -Checkout $co
        $r.Safe | Should -Be $true
    }
    It "refuses foreign origins" {
        $co = [pscustomobject]@{
            IsGit = $true; GitAvailable = $true; Origin = "https://github.com/evil/x.git"
            OriginMatches = $false; Branch = "main"; Sha = "abc123"; IsDirty = $false
        }
        $r = Test-CheckoutSafe -Checkout $co
        $r.Safe | Should -Be $false
    }
    It "refuses dirty trees" {
        $co = [pscustomobject]@{
            IsGit = $true; GitAvailable = $true; Origin = "https://github.com/braydos-h/BreachPilot.git"
            OriginMatches = $true; Branch = "main"; Sha = "abc123"; IsDirty = $true
        }
        $r = Test-CheckoutSafe -Checkout $co
        $r.Safe | Should -Be $false
    }
}

Describe "Test-IsAdministrator" {
    It "returns a boolean without throwing" {
        $r = Test-IsAdministrator
        ($r -is [bool]) | Should -Be $true
    }
}

Describe "Protect-SecretText" {
    It "redacts bearer tokens and key=value secrets" {
        $clean = Protect-SecretText -Text "Authorization: Bearer abcdefghijklmnop rest"
        $clean | Should -Not -Match "abcdefghijklmnop"
        $clean | Should -Match "<redacted>"
        $clean2 = Protect-SecretText -Text "api_key=supersecretvalue123 done"
        $clean2 | Should -Not -Match "supersecretvalue123"
    }
    It "passes plain text through" {
        Protect-SecretText -Text "hello world" | Should -Be "hello world"
    }
    It "handles null/empty safely" {
        Protect-SecretText -Text "" | Should -Be ""
    }
}

Describe "Test-TransientError" {
    It "classifies timeouts/DNS/5xx/429 as transient" {
        Test-TransientError -Message "The operation timed out" | Should -Be $true
        Test-TransientError -Message "Could not resolve host github.com" | Should -Be $true
        Test-TransientError -Message "Server returned 503 Service Unavailable" | Should -Be $true
        Test-TransientError -Message "API rate limit exceeded (429)" | Should -Be $true
    }
    It "treats auth/404 as permanent" {
        Test-TransientError -Message "NONRETRY: GitHub API authentication failed (401)" | Should -Be $false
        Test-TransientError -Message "NONRETRY: GitHub API returned 404" | Should -Be $false
    }
}

Describe "Get-ArchiveDownloadUrl" {
    It "pins tags and SHAs (never a moving target)" {
        $tag = [pscustomobject]@{ Tag = "v0.68.4"; Sha = "abc123" }
        Get-ArchiveDownloadUrl -Resolved $tag | Should -BeLike "*/zip/refs/tags/v0.68.4"
        $sha = [pscustomobject]@{ Tag = ""; Sha = "abc123def456" }
        Get-ArchiveDownloadUrl -Resolved $sha | Should -BeLike "*/zip/abc123def456"
    }
}
