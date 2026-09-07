#!/usr/bin/env bash
#
# BreachPilot installer — Linux/macOS bootstrap, update, repair, and uninstall.
#
#   Fresh install (from a checkout):   ./install.sh
#   Fresh install (one-liner):         curl -fsSL https://raw.githubusercontent.com/braydos-h/BreachPilot/main/install.sh | bash
#   Update a managed install:          ./install.sh --update
#   Health check (no changes):         ./install.sh --check
#   Repair in place:                   ./install.sh --repair
#   Uninstall:                         ./install.sh --uninstall
#
# Idempotent and safe to re-run. Never destroys user data (config.yaml, .env,
# secr.json, mission.yaml, reports/, research_workspace/, exploit_workspace/,
# swarm_workspace/, api_runtime.db, logs/). See --help for all options.
#
# Design notes:
# - Requirements come from the repo itself: requires-python >= 3.11
#   (pyproject.toml), provider-aware Ollama handling (tools/doctor.py probes
#   only the ACTIVE models.provider), npm + package-lock.json WebUI build
#   (webui/dist/index.html), and the external-binary matrix in
#   tools/mcp_tools/ (nmap core; scanners/credentials/exploit tools optional).
# - There are currently no GitHub Releases for this repo, so version
#   resolution falls back to tags, then the default branch (main).
# - No published checksums exist, so tarballs cannot be signature-verified.
#   The installer says so openly and records the exact commit SHA installed.

set -Eeuo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BP_INSTALLER_VERSION="1.0.0"
BP_REPO="braydos-h/BreachPilot"
BP_GITHUB="https://github.com/${BP_REPO}"
BP_API="https://api.github.com/repos/${BP_REPO}"
BP_TARBALL_BASE="https://codeload.github.com/${BP_REPO}/tar.gz"
BP_RAW_BASE="https://raw.githubusercontent.com/${BP_REPO}"
BP_DEFAULT_BRANCH="main"
BP_MIN_PYTHON_MAJOR=3
BP_MIN_PYTHON_MINOR=11

# Exit codes (documented in --help).
BP_EX_OK=0
BP_EX_FAIL=1
BP_EX_ARGS=2
BP_EX_PLATFORM=3
BP_EX_PREFLIGHT=4
BP_EX_DOWNLOAD=5
BP_EX_VALIDATE=6
BP_EX_UPDATE=7

# Conservative free-space floor per profile (documented estimates: source +
# venv + npm build + temp staging; models/docker image extra on top).
BP_DISK_MINIMAL_MB=2048
BP_DISK_STANDARD_MB=5120
BP_DISK_FULL_MB=12288

# Files/dirs treated as persistent user data — never overwritten by updates.
# (Kept in sync with .gitignore + the audit in tools/doctor.py.)
BP_PRESERVE_ITEMS=(
    "config.yaml"
    ".env"
    "secr.json"
    ".webui_secret_key"
    "mission.yaml"
    "reports"
    "research_workspace"
    "exploit_workspace"
    "swarm_workspace"
    "api_runtime.db"
    "logs"
)

# ---------------------------------------------------------------------------
# Global state (defaults; parse_args / env overrides below)
# ---------------------------------------------------------------------------
BP_ACTION="install"        # install | update | repair | check | doctor | uninstall
BP_PROFILE="standard"      # minimal | standard | full
BP_DESIRED_VERSION=""      # --version
BP_INSTALL_DIR=""          # --install-dir
BP_VERBOSE=0
BP_QUIET=0
BP_DRY_RUN=0
BP_ASSUME_YES=0
BP_WITH_KALI=""            # 1 | 0 | "" (unset → profile default)
BP_WITH_SCANNERS=""        # 1 | 0 | "" (unset → profile default)
BP_SKIP_MODELS=0
BP_WITH_CHATGPT=0
BP_NO_PATH=0
BP_ALLOW_DEV=0

BP_OS_KIND="unknown"       # debian | macos | unknown
BP_OS_NAME=""
BP_OS_VERSION=""
BP_ARCH=""
BP_PKG_MGR=""
BP_IS_ROOT=0
BP_HAVE_SUDO=0
BP_SUDO_CMD=""             # "sudo" when elevation is available, else ""
BP_NONINTERACTIVE=0

BP_STAGE="startup"         # current stage label (for error reports)
BP_FAILED=0                # set when a stage fails but we continue
BP_ERRORS=()               # human-readable failure lines for the summary

BP_SOURCE_DIR=""           # resolved repo root we install FROM/INTO
BP_MANAGED=0               # 1 when BP_SOURCE_DIR is installer-managed
BP_DEV_CHECKOUT=0          # 1 when BP_SOURCE_DIR is a user's git checkout
BP_VENV_DIR=".venv"
BP_RUN_PY="python3"
BP_LOG_FILE=""
BP_TMP_DIRS=()             # temp dirs removed by cleanup trap
BP_UPDATE_BACKUP=""        # backup path during --update (restored on failure)
BP_UPDATE_STAGED=0
BP_INTERRUPTED=0

# Legacy env-var compatibility (documented in --help).
# shellcheck disable=SC2034
BP_ENV_DOC="PYTHON VENV INSTALL_KALI_TOOLS INSTALL_SCANNERS SKIP_MODEL_PULL ADD_TO_PATH"

# ---------------------------------------------------------------------------
# Output helpers (colors only on TTY; NO_COLOR / dumb-term safe)
# ---------------------------------------------------------------------------
_bp_use_color() {
    [[ -t 1 ]] || return 1
    [[ -n "${NO_COLOR:-}" ]] && return 1
    [[ "${TERM:-}" == "dumb" ]] && return 1
    return 0
}

_bp_c() {
    # _bp_c <code> <text...> — colorize when allowed, else plain.
    local code="$1"
    shift
    if _bp_use_color; then
        printf '\033[%sm%s\033[0m' "$code" "$*"
    else
        printf '%s' "$*"
    fi
}

log_to_file() {
    # Always-on file logging; never fails the install if the log is unwritable.
    [[ -n "$BP_LOG_FILE" ]] || return 0
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$BP_LOG_FILE" 2>/dev/null || true
}

info() {
    log_to_file "INFO: $*"
    [[ "$BP_QUIET" == "1" ]] && return 0
    printf '%s\n' "$*"
}

step() {
    log_to_file "STEP: $*"
    [[ "$BP_QUIET" == "1" ]] && return 0
    printf '%s\n' "$(_bp_c 34 "==>" "$*")"
}

ok() {
    log_to_file "OK: $*"
    [[ "$BP_QUIET" == "1" ]] && return 0
    printf '  %s %s\n' "$(_bp_c 32 "✓")" "$*"
}

warn() {
    log_to_file "WARN: $*"
    printf '  %s %s\n' "$(_bp_c 33 "[!]")" "$*" >&2
}

error() {
    log_to_file "ERROR: $*"
    printf '  %s %s\n' "$(_bp_c 31 "✗")" "$*" >&2
}

fatal() {
    # fatal <message...> — record stage context, print remediation, exit 1.
    local msg="$*"
    log_to_file "FATAL at stage '${BP_STAGE}': ${msg}"
    printf '%s %s\n' "$(_bp_c 31 "FATAL")" "[$BP_STAGE] $msg" >&2
    if [[ -n "$BP_LOG_FILE" ]]; then
        printf '  Log: %s\n' "$BP_LOG_FILE" >&2
    fi
    exit "$BP_EX_FAIL"
}

debug() {
    [[ "$BP_VERBOSE" == "1" ]] || return 0
    log_to_file "DEBUG: $*"
    printf '  %s %s\n' "$(_bp_c 36 "...")" "$*"
}

record_error() {
    BP_FAILED=1
    BP_ERRORS+=("$1")
    error "$1"
}

note_stage() {
    BP_STAGE="$1"
    log_to_file "--- stage: $1 ---"
}

is_dry_run() { [[ "$BP_DRY_RUN" == "1" ]]; }

confirm() {
    # confirm <prompt> — true on yes; auto-yes with --yes or non-TTY default-no.
    local prompt="$1"
    if [[ "$BP_ASSUME_YES" == "1" ]]; then
        debug "auto-yes: $prompt"
        return 0
    fi
    if [[ ! -t 0 ]]; then
        return 1
    fi
    local answer=""
    printf '%s [y/N] ' "$prompt" >&2
    IFS= read -r answer </dev/tty || return 1
    [[ "$answer" == "y" || "$answer" == "Y" || "$answer" == "yes" ]]
}

# __NEXT__


print_usage() {
    cat <<'USAGE'
BreachPilot installer — bootstrap, update, repair, diagnose, uninstall.

Usage:
  ./install.sh [OPTIONS]                 (from a BreachPilot checkout)
  curl -fsSL https://raw.githubusercontent.com/braydos-h/BreachPilot/main/install.sh | bash [-s -- OPTIONS]
  ./install.sh --update                  (atomic update of a managed install)
  ./install.sh --check                   (diagnostics only, changes nothing)
  ./install.sh --repair                  (fix a managed install in place)
  ./install.sh --uninstall               (remove managed install)

Modes (mutually exclusive):
  --update            Download the newest version into staging, validate it,
                      then atomically swap it in (rollback on failure).
  --repair            Recreate venv, reinstall deps, fix launchers/PATH,
                      rebuild WebUI if stale — without redownloading source.
  --check             Non-destructive diagnostics. Makes no modifications.
  --doctor            Run `python main.py --doctor` against the install and exit.
  --uninstall         Remove managed app files, launchers, PATH block.
                      Preserves user data by default.

Version selection:
  --version VERSION   Install exactly VERSION (tag like v0.49.2, or branch/SHA).
                      Without it: latest stable GitHub Release → newest git tag
                      → default branch (main). This repo currently publishes no
                      Releases, so tags → main is the live path. The installer
                      never silently installs an older version than requested.

Location:
  --install-dir PATH  Where to place a managed install when no checkout is
                      available. Default: ~/.local/share/breachpilot.

Profiles:
  --minimal           Core only (Python venv + requirements).
  --standard          Core + WebUI build + nmap/recon prereqs. (default)
  --full              Everything: Kali arsenal + scanners + models where the
                      platform allows it.

Feature flags:
  --with-kali-tools / --without-kali-tools
  --with-scanners / --without-scanners
  --with-chatgpt      Set up the optional ChatGPT provider runtime (bun +
                      vendored openai-oauth). Opt-in only; never required.
  --skip-models       Skip model pulls (same as SKIP_MODEL_PULL=1).
  --no-path           Do not install launchers or touch shell rc files.

Behavior:
  --dry-run           Show what would happen; change nothing.
  --yes               Assume yes for confirmations (CI / non-interactive).
  --verbose           Detailed diagnostics to console + log.
  --quiet             Minimal console output (log still written).
  --allow-dev         Permit --update inside a git checkout (see SAFETY below).
  -h, --help          This help.

Exit codes:
  0 success · 1 installation/validation failure · 2 invalid arguments
  3 unsupported platform · 4 preflight failure · 5 download/version failure
  6 validation failure · 7 update/rollback failure

Environment (validated, never blindly trusted):
  PYTHON (default python3) · VENV (default .venv, checkout installs only)
  INSTALL_KALI_TOOLS=1/0 · INSTALL_SCANNERS=1/0 · SKIP_MODEL_PULL=1
  ADD_TO_PATH=1/0 (legacy alias for launchers; --no-path wins)
  GITHUB_TOKEN (optional, raises GitHub API rate limits; never logged)
  OLLAMA_API_KEY (needed at RUNTIME for Ollama Cloud, not by the installer)
  SKIP_WEBUI_BUILD=1 skips the WebUI build step · BP_NO_SANDBOX_IMAGE=1 skips
  the sandbox worker-image build.

SAFETY:
  Managed installs (created by this installer, marked with .install-info) are
  updated atomically with rollback. A directory containing .git WITHOUT
  .install-info is treated as your development checkout: --update refuses to
  touch it unless --allow-dev is given (and even then never runs
  `git reset --hard` / `git clean` / `rm -rf`). User data (config.yaml, .env,
  secr.json, mission.yaml, reports/, research_workspace/, exploit_workspace/,
  swarm_workspace/, api_runtime.db, logs/) is preserved across updates and
  uninstalls.

Log: ~/.local/state/breachpilot/install.log (XDG_STATE_HOME respected).
USAGE
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h | --help)
                print_usage
                exit "$BP_EX_OK"
                ;;
            --update | --repair | --check | --doctor | --uninstall)
                if [[ "$BP_ACTION" != "install" ]]; then
                    printf 'error: --%s conflicts with earlier mode --%s\n' "${1#--}" "$BP_ACTION" >&2
                    exit "$BP_EX_ARGS"
                fi
                BP_ACTION="${1#--}"
                shift
                ;;
            --minimal | --standard | --full)
                BP_PROFILE="${1#--}"
                shift
                ;;
            --version)
                [[ $# -ge 2 ]] || { printf 'error: --version needs a value\n' >&2; exit "$BP_EX_ARGS"; }
                BP_DESIRED_VERSION="$2"
                shift 2
                ;;
            --version=*)
                BP_DESIRED_VERSION="${1#--version=}"
                [[ -n "$BP_DESIRED_VERSION" ]] || { printf 'error: --version needs a value\n' >&2; exit "$BP_EX_ARGS"; }
                shift
                ;;
            --install-dir)
                [[ $# -ge 2 ]] || { printf 'error: --install-dir needs a value\n' >&2; exit "$BP_EX_ARGS"; }
                BP_INSTALL_DIR="$2"
                shift 2
                ;;
            --install-dir=*)
                BP_INSTALL_DIR="${1#--install-dir=}"
                [[ -n "$BP_INSTALL_DIR" ]] || { printf 'error: --install-dir needs a value\n' >&2; exit "$BP_EX_ARGS"; }
                shift
                ;;
            --with-kali-tools) BP_WITH_KALI=1; shift ;;
            --without-kali-tools) BP_WITH_KALI=0; shift ;;
            --with-scanners) BP_WITH_SCANNERS=1; shift ;;
            --without-scanners) BP_WITH_SCANNERS=0; shift ;;
            --with-chatgpt) BP_WITH_CHATGPT=1; shift ;;
            --skip-models) BP_SKIP_MODELS=1; shift ;;
            --no-path) BP_NO_PATH=1; shift ;;
            --allow-dev) BP_ALLOW_DEV=1; shift ;;
            --dry-run) BP_DRY_RUN=1; shift ;;
            --yes | -y) BP_ASSUME_YES=1; shift ;;
            --verbose) BP_VERBOSE=1; shift ;;
            --quiet) BP_QUIET=1; shift ;;
            --)
                shift
                [[ $# -gt 0 ]] && { printf 'error: unexpected arguments: %s\n' "$*" >&2; exit "$BP_EX_ARGS"; }
                break
                ;;
            -*)
                printf 'error: unknown option: %s (see --help)\n' "$1" >&2
                exit "$BP_EX_ARGS"
                ;;
            *)
                printf 'error: unexpected argument: %s (see --help)\n' "$1" >&2
                exit "$BP_EX_ARGS"
                ;;
        esac
    done

    # Env-var compatibility with the historical installer.
    [[ "$BP_SKIP_MODELS" == "1" ]] || [[ "${SKIP_MODEL_PULL:-0}" == "1" ]] && BP_SKIP_MODELS=1
    if [[ -z "$BP_WITH_KALI" && -n "${INSTALL_KALI_TOOLS:-}" ]]; then
        [[ "${INSTALL_KALI_TOOLS}" == "1" ]] && BP_WITH_KALI=1 || BP_WITH_KALI=0
    fi
    if [[ -z "$BP_WITH_SCANNERS" && -n "${INSTALL_SCANNERS:-}" ]]; then
        [[ "${INSTALL_SCANNERS}" == "1" ]] && BP_WITH_SCANNERS=1 || BP_WITH_SCANNERS=0
    fi
    if [[ "${ADD_TO_PATH:-1}" == "0" ]]; then
        BP_NO_PATH=1
    fi

    # Profile defaults for anything still unset.
    if [[ -z "$BP_WITH_KALI" ]]; then
        [[ "$BP_PROFILE" == "full" ]] && BP_WITH_KALI=1 || BP_WITH_KALI=0
    fi
    if [[ -z "$BP_WITH_SCANNERS" ]]; then
        [[ "$BP_PROFILE" == "minimal" ]] && BP_WITH_SCANNERS=0 || BP_WITH_SCANNERS=1
    fi
}

# ---------------------------------------------------------------------------
# Logging / temp / signal handling
# ---------------------------------------------------------------------------
init_logging() {
    local state_home="${XDG_STATE_HOME:-$HOME/.local/state}"
    local log_dir="$state_home/breachpilot"
    BP_LOG_FILE="$log_dir/install.log"
    if ! mkdir -p "$log_dir" 2>/dev/null; then
        BP_LOG_FILE=""
        return 0
    fi
    if ! touch "$BP_LOG_FILE" 2>/dev/null; then
        BP_LOG_FILE=""
        return 0
    fi
    log_to_file "=== BreachPilot installer v${BP_INSTALLER_VERSION} (action=${BP_ACTION} profile=${BP_PROFILE}) ==="
}

make_temp_dir() {
    # make_temp_dir <purpose> — echo path; registered for cleanup on EXIT.
    local purpose="${1:-work}"
    local dir=""
    dir="$(mktemp -d "${TMPDIR:-/tmp}/breachpilot-${purpose}-XXXXXX")" || fatal "cannot create temp directory (check TMPDIR and free space)."
    BP_TMP_DIRS+=("$dir")
    log_to_file "temp dir: $dir"
    printf '%s' "$dir"
}

cleanup() {
    local rc=$?
    local dir
    for dir in "${BP_TMP_DIRS[@]:-}"; do
        [[ -n "$dir" && -d "$dir" ]] || continue
        rm -rf "$dir" 2>/dev/null || true
    done
    BP_TMP_DIRS=()
    return "$rc"
}

on_interrupt() {
    BP_INTERRUPTED=1
    warn "interrupted — cleaning up temporary files."
    log_to_file "interrupted by signal"
    if [[ "$BP_UPDATE_STAGED" == "1" && -n "$BP_UPDATE_BACKUP" && -d "$BP_UPDATE_BACKUP" ]]; then
        warn "update was staged but not activated — restoring previous installation."
        restore_backup || warn "automatic restore failed; your backup is at: $BP_UPDATE_BACKUP"
    fi
    exit 130
}

install_traps() {
    trap cleanup EXIT
    trap on_interrupt INT TERM
}

# ---------------------------------------------------------------------------
# Network helper (bounded retries, timeouts, no secret leakage)
# ---------------------------------------------------------------------------
_redact_for_log() {
    # Strip Authorization headers / tokens from a string before logging.
    printf '%s' "$1" | sed -E 's/[Aa]uthorization:[^;]*;[ ]*/Authorization: [REDACTED]; /g; s/(Bearer )[A-Za-z0-9._~+/-]+/\1[REDACTED]/g'
}

net_fetch() {
    # net_fetch <url> <dest> — curl with timeouts + bounded backoff. No auth
    # headers are ever sent except an optional GITHUB_TOKEN for api.github.com.
    local url="$1" dest="$2"
    local attempt=0 delay=2
    local scheme="${url%%://*}"
    if [[ "$scheme" != "https" ]]; then
        error "refusing non-HTTPS download: $(_redact_for_log "$url")"
        return 1
    fi
    : >"$dest" || return 1
    local -a args=(--fail --show-error --location --silent
        --connect-timeout 15 --max-time 300 --retry 0
        --proto "=https" --proto-redir "=https")
    if [[ "$url" == https://api.github.com/* && -n "${GITHUB_TOKEN:-}" ]]; then
        # Token stays in the process env + header; never echoed or logged.
        args+=(--header "Authorization: Bearer ${GITHUB_TOKEN}")
        debug "using GITHUB_TOKEN for api.github.com (value not logged)"
    fi
    while [[ $attempt -lt 4 ]]; do
        attempt=$((attempt + 1))
        debug "fetch attempt ${attempt}/4: $url"
        if curl "${args[@]}" --output "$dest" "$url" 2>>"$BP_LOG_FILE"; then
            if [[ -s "$dest" ]]; then
                return 0
            fi
            log_to_file "fetch produced an empty file: $url"
        fi
        if [[ $attempt -lt 4 ]]; then
            sleep "$delay"
            delay=$((delay * 2))
        fi
    done
    log_to_file "fetch failed after 4 attempts: $(_redact_for_log "$url")"
    return 1
}

check_network() {
    # check_network — DNS + HTTPS probe of github.com. Returns 0 when usable.
    debug "probing network: DNS + HTTPS to github.com"
    if ! getent hosts github.com >/dev/null 2>&1; then
        if ! python3 -c 'import socket; socket.gethostbyname("github.com")' >/dev/null 2>&1; then
            error "DNS resolution failed for github.com — check DNS/network."
            return 1
        fi
    fi
    local code=""
    code="$(curl -fsSL -o /dev/null -w '%{http_code}' --connect-timeout 10 --max-time 30 https://github.com 2>>"$BP_LOG_FILE")" || code=""
    if [[ "$code" != "200" && "$code" != "301" && "$code" != "302" ]]; then
        error "HTTPS to github.com failed (check proxy/firewall). See log: ${BP_LOG_FILE:-unavailable}"
        return 1
    fi
    debug "network OK (github.com -> $code)"
    return 0
}




# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------
detect_environment() {
    note_stage "detect-environment"

    if [[ -z "${HOME:-}" || ! -d "${HOME:-/nonexistent}" ]]; then
        fatal "HOME is unset or not a directory — cannot determine install locations."
    fi

    # Non-interactive (CI) detection: no TTY on stdin.
    if [[ ! -t 0 ]]; then
        BP_NONINTERACTIVE=1
    fi

    # Root detection. Kali operators often run as root; that is supported but
    # launchers/PATH still target the invoking user's home when available.
    if [[ "$(id -u)" == "0" ]]; then
        BP_IS_ROOT=1
        local sudo_user="${SUDO_USER:-}"
        if [[ -n "$sudo_user" && "$sudo_user" != "root" ]]; then
            warn "running as root via sudo (invoked by $sudo_user). Files will be owned by root."
        else
            info "running as root — installing system-wide where that is meaningful."
        fi
    fi

    # sudo availability (passwordless preferred; interactive sudo needs a TTY).
    if [[ "$BP_IS_ROOT" == "1" ]]; then
        BP_HAVE_SUDO=1
    elif command -v sudo >/dev/null 2>&1; then
        if sudo -n true >/dev/null 2>&1; then
            BP_HAVE_SUDO=1
        elif [[ -t 0 ]]; then
            BP_HAVE_SUDO=1 # interactive sudo can prompt
        else
            BP_HAVE_SUDO=0
        fi
    fi
    if [[ "$BP_HAVE_SUDO" == "1" && "$BP_IS_ROOT" != "1" ]]; then
        BP_SUDO_CMD="sudo"
    fi
    debug "root=$BP_IS_ROOT sudo=$BP_HAVE_SUDO cmd='$BP_SUDO_CMD' interactive=$([ -t 0 ] && echo yes || echo no)"
}

detect_platform() {
    note_stage "detect-platform"

    local uname_s=""
    uname_s="$(uname -s 2>/dev/null || echo unknown)"
    local uname_m=""
    uname_m="$(uname -m 2>/dev/null || echo unknown)"
    case "$uname_m" in
        x86_64 | amd64) BP_ARCH="x86_64" ;;
        aarch64 | arm64) BP_ARCH="arm64" ;;
        *)
            fatal "unsupported CPU architecture: $uname_m (need x86_64/amd64 or arm64/aarch64)."
            ;;
    esac

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        BP_OS_NAME="${PRETTY_NAME:-${NAME:-Linux}}"
        BP_OS_VERSION="${VERSION_ID:-}"
        local id="${ID:-}" id_like="${ID_LIKE:-}"
        if [[ "$id" == "kali" ]]; then
            BP_OS_KIND="kali"
            BP_PKG_MGR="apt"
        elif [[ "$id" == "debian" || "$id" == "ubuntu" || "$id" == "linuxmint" || "$id" == "pop" ]] \
            || [[ "$id_like" == *debian* || "$id_like" == *ubuntu* ]]; then
            BP_OS_KIND="debian"
            BP_PKG_MGR="apt"
        else
            printf 'error: unsupported Linux distribution: %s\n' "$BP_OS_NAME" >&2
            printf '  BreachPilot supports Kali, Debian, Ubuntu, Mint/Pop and macOS.\n' >&2
            printf '  Install Python 3.11+, nmap, git, curl manually, then rerun.\n' >&2
            exit "$BP_EX_PLATFORM"
        fi
    elif [[ "$uname_s" == "Darwin" ]]; then
        BP_OS_KIND="macos"
        BP_OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo unknown)"
        BP_PKG_MGR="brew"
    else
        printf 'error: unsupported platform: %s\n' "$uname_s" >&2
        printf '  BreachPilot supports Linux (Kali/Debian/Ubuntu/Mint/Pop) and macOS.\n' >&2
        exit "$BP_EX_PLATFORM"
    fi

    debug "os=$BP_OS_KIND ($BP_OS_NAME) arch=$BP_ARCH pkg=$BP_PKG_MGR"
}

# ---------------------------------------------------------------------------
# Source location: checkout vs piped/standalone (bootstrap mode)
# ---------------------------------------------------------------------------
is_breachpilot_checkout() {
    # True when $1 looks like a BreachPilot source tree.
    local dir="$1"
    [[ -f "$dir/main.py" && -f "$dir/pyproject.toml" && -f "$dir/requirements.txt" && -d "$dir/tools" ]]
}

is_managed_install() {
    # True when $1 was created by this installer (marker file present).
    [[ -f "$1/.install-info" ]]
}

default_install_dir() {
    if [[ -n "$BP_INSTALL_DIR" ]]; then
        printf '%s' "$BP_INSTALL_DIR"
    else
        printf '%s/.local/share/breachpilot' "$HOME"
    fi
}

resolve_source_dir() {
    note_stage "resolve-source"
    local script_path="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
    local script_dir=""
    script_dir="$(cd "$(dirname "$script_path")" 2>/dev/null && pwd)" || script_dir=""

    # Case 1: running from inside a checkout (./install.sh or bp-managed path).
    if [[ -n "$script_dir" ]] && is_breachpilot_checkout "$script_dir"; then
        BP_SOURCE_DIR="$script_dir"
        if is_managed_install "$script_dir"; then
            BP_MANAGED=1
            debug "managed install detected at $script_dir"
        else
            BP_DEV_CHECKOUT=1
            if is_dry_run || [[ "$BP_ACTION" == "check" || "$BP_ACTION" == "doctor" || "$BP_ACTION" == "repair" ]]; then
                debug "dev checkout at $script_dir (non-destructive action)"
            else
                info "using your existing checkout at $script_dir"
            fi
        fi
        BP_VENV_DIR="${VENV:-.venv}"
        return 0
    fi

    # Case 2: piped via curl|bash, standalone download, or foreign cwd —
    # bootstrap into a managed directory.
    local target=""
    target="$(default_install_dir)"
    if [[ -e "$target" ]] && ! is_breachpilot_checkout "$target" && ! is_managed_install "$target"; then
        fatal "install dir exists but is not a BreachPilot install: $target (choose --install-dir)."
    fi
    BP_SOURCE_DIR="$target"
    BP_MANAGED=1
    BP_VENV_DIR="$target/.venv"
    debug "bootstrap mode → managed dir $target"
}

# ---------------------------------------------------------------------------
# Version resolution: --version → GitHub Release → newest tag → main
# ---------------------------------------------------------------------------
github_api_get() {
    # github_api_get <path> <dest> — GET api.github.com with clean errors.
    local path="$1" dest="$2"
    if ! net_fetch "${BP_API}${path}" "$dest"; then
        return 1
    fi
    return 0
}

json_string_field() {
    # json_string_field <file> <field> — extract "field": "value" without jq.
    local file="$1" field="$2"
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); v=d.get(sys.argv[2],""); print(v if isinstance(v,str) else "")' \
        "$file" "$field" 2>/dev/null || sed -n "s/^[[:space:]]*\"${field}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$file" | head -n 1
}

resolve_version() {
    # Sets BP_RESOLVED_REF (tag/branch/SHA) + BP_VERSION_LABEL + BP_VERSION_SOURCE.
    note_stage "resolve-version"

    if [[ -n "$BP_DESIRED_VERSION" ]]; then
        BP_RESOLVED_REF="$BP_DESIRED_VERSION"
        BP_VERSION_LABEL="$BP_DESIRED_VERSION"
        BP_VERSION_SOURCE="explicit --version"
        debug "explicit version: $BP_RESOLVED_REF"
        return 0
    fi

    local tmp=""
    tmp="$(make_temp_dir version)"

    # 1. Latest stable GitHub Release (non-draft, non-prerelease).
    if github_api_get "/releases/latest" "$tmp/release.json"; then
        local tag=""
        tag="$(json_string_field "$tmp/release.json" "tag_name")"
        local draft="" prerelease=""
        draft="$(python3 -c 'import json;print(json.load(open("'"$tmp"'/release.json")).get("draft",""))' 2>/dev/null)"
        prerelease="$(python3 -c 'import json;print(json.load(open("'"$tmp"'/release.json")).get("prerelease",""))' 2>/dev/null)"
        if [[ -n "$tag" && "$draft" != "True" && "$prerelease" != "True" ]]; then
            BP_RESOLVED_REF="$tag"
            BP_VERSION_LABEL="$tag"
            BP_VERSION_SOURCE="GitHub Release"
            debug "latest release: $tag"
            return 0
        fi
        debug "latest release unusable (404 or draft/prerelease) — trying tags"
    else
        debug "no usable GitHub Release endpoint (rate limit? none published?) — trying tags"
    fi

    # 2. Newest git tag via the API (works without clone; tolerates rate limits).
    if github_api_get "/tags?per_page=100" "$tmp/tags.json"; then
        local tag=""
        tag="$(python3 -c '
import json
try:
    tags = json.load(open("'"$tmp"'/tags.json"))
    names = [t.get("name","") for t in tags if isinstance(t,dict) and t.get("name")]
    print(names[0] if names else "")
except Exception:
    print("")
' 2>/dev/null)"
        if [[ -n "$tag" ]]; then
            BP_RESOLVED_REF="$tag"
            BP_VERSION_LABEL="$tag"
            BP_VERSION_SOURCE="git tag"
            debug "newest tag: $tag"
            return 0
        fi
    fi

    # 3. Default branch fallback (documented, never silent about it).
    BP_RESOLVED_REF="$BP_DEFAULT_BRANCH"
    BP_VERSION_LABEL="$BP_DEFAULT_BRANCH (default branch — no Releases or tags found)"
    BP_VERSION_SOURCE="default branch"
    warn "no GitHub Releases or tags found — falling back to branch '$BP_DEFAULT_BRANCH'."
    return 0
}

read_install_info() {
    # read_install_info <dir> <field> — read marker metadata.
    local dir="$1" field="$2"
    python3 -c 'import sys; d=dict(l.rstrip("\n").split("=",1) for l in open(sys.argv[1]) if "=" in l); print(d.get(sys.argv[2],""))' \
        "$dir/.install-info" "$field" 2>/dev/null || true
}




# ---------------------------------------------------------------------------
# Download + verify source (tarball; no releases → tags → branch already done)
# ---------------------------------------------------------------------------
download_source() {
    # download_source <ref> <dest_dir> — fetch + extract + validate structure.
    # Sets BP_RESOLVED_SHA when the ref resolves to a commit.
    local ref="$1" dest_parent="$2"
    note_stage "download-source"

    local url="${BP_TARBALL_BASE}/${ref}.tar.gz"
    local tmp=""
    tmp="$(make_temp_dir download)"
    local archive="$tmp/source.tar.gz"

    info "downloading BreachPilot ${ref} ..."
    if ! net_fetch "$url" "$archive"; then
        error "download failed: $url"
        error "  causes: no network, GitHub rate limit (set GITHUB_TOKEN), or bad ref."
        return "$BP_EX_DOWNLOAD"
    fi
    if [[ ! -s "$archive" ]]; then
        error "downloaded archive is empty."
        return "$BP_EX_DOWNLOAD"
    fi

    # Validate it is a real gzip tarball before extraction.
    if ! tar -tzf "$archive" >/dev/null 2>>"$BP_LOG_FILE"; then
        error "downloaded file is not a valid tarball (corrupted or HTML error page)."
        return "$BP_EX_DOWNLOAD"
    fi
    # Path-traversal guard: reject absolute paths and .. components.
    if tar -tzf "$archive" 2>/dev/null | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
        error "archive contains unsafe paths (absolute or '..'). Aborting."
        return "$BP_EX_DOWNLOAD"
    fi

    local extract="$tmp/extract"
    mkdir -p "$extract"
    if ! tar -xzf "$archive" -C "$extract" 2>>"$BP_LOG_FILE"; then
        error "archive extraction failed."
        return "$BP_EX_DOWNLOAD"
    fi
    # codeload wraps in one top-level dir; find the real tree.
    local top=""
    top="$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
    if [[ -z "$top" ]] || ! is_breachpilot_checkout "$top"; then
        error "downloaded source failed structure validation (no main.py/pyproject.toml/tools/)."
        return "$BP_EX_VALIDATE"
    fi

    # Resolve the exact commit SHA for the record (best-effort via API).
    BP_RESOLVED_SHA=""
    local sha_file="$tmp/sha.json"
    if github_api_get "/commits/${ref}" "$sha_file" 2>/dev/null; then
        BP_RESOLVED_SHA="$(json_string_field "$sha_file" "sha")"
    fi
    debug "resolved SHA: ${BP_RESOLVED_SHA:-unknown}"

    if is_dry_run; then
        info "[dry-run] would stage validated source at $dest_parent"
        return 0
    fi
    rm -rf "$dest_parent"
    mkdir -p "$(dirname "$dest_parent")"
    if ! mv "$top" "$dest_parent"; then
        error "cannot move staged source into place."
        return "$BP_EX_DOWNLOAD"
    fi
    ok "source validated: main.py + pyproject.toml + requirements.txt + tools/"
    return 0
}

write_install_info() {
    # write_install_info <dir> — record non-secret install metadata.
    local dir="$1"
    local pyver=""
    pyver="$("$BP_RUN_PY" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}")' 2>/dev/null || echo unknown)"
    {
        printf 'repository=%s\n' "$BP_REPO"
        printf 'version=%s\n' "${BP_VERSION_LABEL:-unknown}"
        printf 'ref=%s\n' "${BP_RESOLVED_REF:-unknown}"
        printf 'commit_sha=%s\n' "${BP_RESOLVED_SHA:-unknown}"
        printf 'installed_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'installer_version=%s\n' "$BP_INSTALLER_VERSION"
        printf 'install_path=%s\n' "$dir"
        printf 'python_version=%s\n' "$pyver"
        printf 'platform=%s/%s\n' "$BP_OS_KIND" "$BP_ARCH"
        printf 'profile=%s\n' "$BP_PROFILE"
    } >"$dir/.install-info" 2>/dev/null || warn "could not write .install-info (non-fatal)"
}

# ---------------------------------------------------------------------------
# Preflight: critical vs optional vs feature-specific
# ---------------------------------------------------------------------------
BP_PREFLIGHT_FAIL=0

preflight_require() {
    # preflight_require <label> <hint...> — critical; failure aborts.
    local label="$1"
    shift
    if ! "$@" >/dev/null 2>&1; then
        error "missing critical dependency: $label"
        error "  fix: $*"
        BP_PREFLIGHT_FAIL=1
        return 1
    fi
    ok "$label"
    return 0
}

preflight_optional() {
    # preflight_optional <label> <hint> <cmd...> — warn-only when missing.
    local label="$1" hint="$2"
    shift 2
    if "$@" >/dev/null 2>&1; then
        ok "$label"
    else
        warn "$label missing (optional) — $hint"
    fi
    return 0
}

parse_python_version() {
    # Echo "major minor" for a python binary, or fail.
    "$1" -c 'import sys; print(f"{sys.version_info[0]} {sys.version_info[1]}")' 2>/dev/null
}

check_python_version() {
    local py="$1" major=0 minor=0 rest=""
    local ver=""
    ver="$(parse_python_version "$py")" || return 1
    # Explicit space split: the installer-wide IFS has no space.
    IFS=' ' read -r major minor rest <<<"$ver"
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    [[ "$major" -gt "$BP_MIN_PYTHON_MAJOR" ]] || [[ "$major" == "$BP_MIN_PYTHON_MAJOR" && "$minor" -ge "$BP_MIN_PYTHON_MINOR" ]]
}

check_privileges_early() {
    # Decide elevation needs BEFORE long work so sudo never prompts mid-run.
    note_stage "privileges"
    if [[ "$BP_OS_KIND" != "debian" && "$BP_OS_KIND" != "kali" && "$BP_OS_KIND" != "macos" ]]; then
        return 0
    fi
    local need_root=0
    if [[ "$BP_WITH_KALI" == "1" || "$BP_WITH_SCANNERS" == "1" ]]; then
        need_root=1
    fi
    if [[ "$BP_IS_ROOT" == "1" ]]; then
        debug "running as root — no sudo needed"
        return 0
    fi
    if [[ "$need_root" == "1" && "$BP_HAVE_SUDO" != "1" ]]; then
        warn "no sudo available — OS packages (nmap, scanners, Kali tools) will be skipped."
        warn "  rerun with sudo access, or install them manually and rerun."
        if [[ "$BP_PROFILE" == "full" ]]; then
            error "profile --full needs OS package installs but sudo is unavailable."
            return 1
        fi
    elif [[ "$need_root" == "1" && -z "$BP_SUDO_CMD" ]]; then
        # Have interactive sudo (TTY) but not passwordless: warm it now.
        info "OS package installation needs elevation — requesting sudo upfront."
        if ! sudo -v 2>>"$BP_LOG_FILE"; then
            warn "sudo authentication failed — OS packages will be skipped."
        fi
    fi
    return 0
}

check_disk_space() {
    note_stage "disk-space"
    local need="$BP_DISK_STANDARD_MB"
    case "$BP_PROFILE" in
        minimal) need="$BP_DISK_MINIMAL_MB" ;;
        full) need="$BP_DISK_FULL_MB" ;;
    esac
    local target="${BP_SOURCE_DIR:-$HOME}"
    [[ -d "$target" ]] || target="$HOME"
    local avail_kb=""
    avail_kb="$(df -k -P "$target" 2>/dev/null | awk 'NR==2 {print $4}')"
    if [[ -z "$avail_kb" || ! "$avail_kb" =~ ^[0-9]+$ ]]; then
        warn "could not determine free disk space — continuing (need ~${need} MB)."
        return 0
    fi
    local avail_mb=$((avail_kb / 1024))
    if [[ "$avail_mb" -lt "$need" ]]; then
        error "insufficient disk space: ${avail_mb} MB free, ~${need} MB needed for --${BP_PROFILE}."
        error "  free space or use --minimal, then rerun."
        return 1
    fi
    ok "${avail_mb} MB free (need ~${need} MB)"
    return 0
}

run_preflight() {
    note_stage "preflight"
    info "[1/9] Checking system"

    local py="${PYTHON:-python3}"
    BP_RUN_PY="$py"
    if ! command -v "$py" >/dev/null 2>&1; then
        printf '  %s Python %s+ is required.\n' "$(_bp_c 31 "✗")" "$BP_MIN_PYTHON_MAJOR.$BP_MIN_PYTHON_MINOR" >&2
        printf '  Found: %s not on PATH\n' "$py" >&2
        if [[ "$BP_OS_KIND" == "macos" ]]; then
            printf '  Install it and rerun:\n    brew install python\n' >&2
        else
            printf '  Install it and rerun:\n    sudo apt install python3 python3-venv\n' >&2
        fi
        exit "$BP_EX_PREFLIGHT"
    fi
    local pyver=""
    pyver="$("$py" --version 2>&1 | head -n 1)"
    if ! check_python_version "$py"; then
        printf '  %s Python %s+ is required.\n' "$(_bp_c 31 "✗")" "$BP_MIN_PYTHON_MAJOR.$BP_MIN_PYTHON_MINOR" >&2
        printf '  Found: %s\n' "$pyver" >&2
        printf '  Install Python %s+ and rerun (or set PYTHON=...).\n' "$BP_MIN_PYTHON_MAJOR.$BP_MIN_PYTHON_MINOR" >&2
        exit "$BP_EX_PREFLIGHT"
    fi
    ok "Python ($pyver)"

    preflight_require "git" "sudo apt install git / brew install git" command -v git || true
    preflight_require "curl" "sudo apt install curl / brew install curl" command -v curl || true
    if ! command -v tar >/dev/null 2>&1; then
        error "tar is required for source extraction."
        BP_PREFLIGHT_FAIL=1
    fi
    if ! "$py" -c 'import venv' >/dev/null 2>&1; then
        if [[ "$BP_OS_KIND" == "debian" || "$BP_OS_KIND" == "kali" ]]; then
            error "Python venv module missing — fix: sudo apt install python3-venv"
        else
            error "Python venv module missing for $py."
        fi
        BP_PREFLIGHT_FAIL=1
    else
        ok "python venv module"
    fi

    # Writable destinations (install dir may not exist yet in bootstrap mode).
    local dest_parent=""
    dest_parent="$(dirname "$BP_SOURCE_DIR")"
    if ! mkdir -p "$dest_parent" 2>/dev/null || [[ ! -w "$dest_parent" ]]; then
        error "install destination not writable: $dest_parent"
        BP_PREFLIGHT_FAIL=1
    fi
    local tmp_probe=""
    if ! tmp_probe="$(mktemp -d "${TMPDIR:-/tmp}/breachpilot-probe-XXXXXX" 2>/dev/null)"; then
        error "temp directory not writable (TMPDIR=${TMPDIR:-/tmp})."
        BP_PREFLIGHT_FAIL=1
    else
        rmdir "$tmp_probe"
        ok "writable install + temp dirs"
    fi

    # Desired-version sanity: never silently install something older than the
    # managed install already present (unless --version pins it explicitly).
    if [[ "$BP_MANAGED" == "1" && -z "$BP_DESIRED_VERSION" && -f "$BP_SOURCE_DIR/.install-info" ]]; then
        local installed_ref=""
        installed_ref="$(read_install_info "$BP_SOURCE_DIR" "ref")"
        if [[ -n "$installed_ref" && -n "${BP_RESOLVED_REF:-}" && "$installed_ref" == "$BP_RESOLVED_REF" ]]; then
            debug "resolved ref matches installed ref ($installed_ref)"
        fi
    fi

    if ! check_network; then
        error "network preflight failed — check DNS/HTTPS/proxy, then rerun."
        BP_PREFLIGHT_FAIL=1
    else
        ok "network (DNS + HTTPS to github.com)"
    fi

    if ! check_privileges_early; then
        BP_PREFLIGHT_FAIL=1
    fi
    if ! check_disk_space; then
        BP_PREFLIGHT_FAIL=1
    fi

    # Feature-specific (never fatal here; each stage degrades gracefully).
    preflight_optional "node (WebUI build)" "WebUI build will be skipped" command -v node
    preflight_optional "npm (WebUI build)" "WebUI build will be skipped" command -v npm
    preflight_optional "docker (sandbox worker)" "sandbox image build skipped" command -v docker
    if [[ "$BP_WITH_CHATGPT" == "1" ]]; then
        preflight_optional "bun (ChatGPT provider)" "opt-in provider setup will warn" command -v bun
    fi

    if [[ "$BP_PREFLIGHT_FAIL" == "1" ]]; then
        printf 'Preflight failed. Fix the items above and rerun.\n' >&2
        printf 'Log: %s\n' "${BP_LOG_FILE:-unavailable}" >&2
        exit "$BP_EX_PREFLIGHT"
    fi
}




# ---------------------------------------------------------------------------
# OS packages (apt / brew) — installs only what is missing
# ---------------------------------------------------------------------------
apt_pkg_installed() {
    dpkg -s "$1" >/dev/null 2>&1
}

apt_update_once() {
    if [[ "${BP_APT_UPDATED:-0}" == "1" ]]; then
        return 0
    fi
    info "updating package index (once) ..."
    if ! $BP_SUDO_CMD apt-get update 2>>"$BP_LOG_FILE"; then
        warn "apt-get update failed (sudo? network?). Package installs may fail."
        return 1
    fi
    BP_APT_UPDATED=1
    return 0
}

apt_install_missing() {
    # apt_install_missing <pkg...> — install only pkgs not already present.
    local missing=() pkg=""
    for pkg in "$@"; do
        if apt_pkg_installed "$pkg"; then
            debug "apt: $pkg already installed"
        else
            missing+=("$pkg")
        fi
    done
    if [[ "${#missing[@]}" == "0" ]]; then
        return 0
    fi
    # NOTE: installer IFS has no space, so join explicitly for display.
    local missing_disp=""
    printf -v missing_disp '%s ' "${missing[@]}"
    if is_dry_run; then
        info "[dry-run] would apt-install: ${missing_disp}"
        return 0
    fi
    if [[ -z "$BP_SUDO_CMD" && "$BP_IS_ROOT" != "1" ]]; then
        warn "no elevation — skipping apt install: ${missing_disp}"
        return 1
    fi
    apt_update_once || true
    if ! $BP_SUDO_CMD apt-get install -y "${missing[@]}" >>"$BP_LOG_FILE" 2>&1; then
        warn "apt install failed for: ${missing_disp}(see log)"
        return 1
    fi
    ok "installed: ${missing_disp}"
    return 0
}

install_system_dependencies() {
    note_stage "system-deps"
    info "[3/9] System dependencies"

    # Installer shell deps (python3-venv needed for `python -m venv`).
    case "$BP_OS_KIND" in
        kali | debian)
            local base_pkgs=(nmap python3-venv tmux curl git)
            if ! apt_install_missing "${base_pkgs[@]}"; then
                record_error "base OS packages incomplete — install manually: sudo apt install -y ${base_pkgs[*]}"
            fi
            # Kali arsenal (modern NetExec names first, legacy fallback).
            if [[ "$BP_WITH_KALI" == "1" ]]; then
                if ! apt_install_missing metasploit-framework exploitdb hydra netexec python3-impacket; then
                    debug "modern Kali names failed — trying legacy fallbacks"
                    apt_install_missing metasploit-framework exploitdb hydra crackmapexec impacket-scripts \
                        || record_error "Kali-only packages unavailable on this distro (fine for read_only recon)."
                fi
            fi
            if [[ "$BP_WITH_SCANNERS" == "1" ]]; then
                apt_install_missing nikto sqlmap gobuster whatweb dirb hashcat john seclists wget \
                    || warn "some scanners unavailable — the engine reports per-scanner hints instead."
                for tool in nuclei feroxbuster wpscan; do
                    if command -v "$tool" >/dev/null 2>&1; then
                        ok "$tool"
                    else
                        warn "$tool not on PATH (manual install, optional — see docs/deployment.md)"
                    fi
                done
            fi
            ;;
        macos)
            if ! command -v brew >/dev/null 2>&1; then
                record_error "Homebrew not found (https://brew.sh). Install nmap/python/tmux/curl manually, then re-run."
                return 0
            fi
            local brew_pkgs=(nmap python tmux curl git)
            if [[ "$BP_WITH_SCANNERS" == "1" ]]; then
                brew_pkgs+=(nikto sqlmap gobuster whatweb john-jumbo hashcat)
            fi
            local missing_brew=() pkg=""
            for pkg in "${brew_pkgs[@]}"; do
                if brew list "$pkg" >/dev/null 2>&1; then
                    debug "brew: $pkg already installed"
                else
                    missing_brew+=("$pkg")
                fi
            done
            if [[ "${#missing_brew[@]}" -gt 0 ]]; then
                if is_dry_run; then
                    info "[dry-run] would brew-install: ${missing_brew[*]}"
                elif ! brew install "${missing_brew[@]}" >>"$BP_LOG_FILE" 2>&1; then
                    record_error "brew install failed for: ${missing_brew[*]}"
                else
                    ok "installed: ${missing_brew[*]}"
                fi
            fi
            if [[ "$BP_WITH_KALI" == "1" ]]; then
                warn "--with-kali-tools has no macOS equivalent (Metasploit/exploitdb are Kali-only); skipping."
            fi
            ;;
        *)
            warn "unknown OS — skipping OS packages. Ensure nmap + python3-venv exist."
            ;;
    esac

    # Core binary report (informational; doctor is the authority later).
    for tool in nmap git curl tmux; do
        if command -v "$tool" >/dev/null 2>&1; then
            ok "$tool ($(command -v "$tool"))"
        else
            warn "$tool still missing."
        fi
    done
}

# ---------------------------------------------------------------------------
# Python venv + requirements (CORE — failures here are fatal)
# ---------------------------------------------------------------------------
setup_python() {
    note_stage "python-env"
    info "[4/9] Python environment"
    local py="${PYTHON:-python3}"

    if is_dry_run; then
        info "[dry-run] would create venv at $BP_SOURCE_DIR/$BP_VENV_DIR + pip install -r requirements.txt"
        return 0
    fi

    mkdir -p "$BP_SOURCE_DIR" || fatal "cannot create $BP_SOURCE_DIR"
    cd "$BP_SOURCE_DIR" || fatal "cannot cd to $BP_SOURCE_DIR"

    if [[ ! -x "$BP_VENV_DIR/bin/python" ]]; then
        info "creating venv ($BP_VENV_DIR) ..."
        if ! "$py" -m venv "$BP_VENV_DIR" >>"$BP_LOG_FILE" 2>&1; then
            printf '  %s venv creation failed.\n' "$(_bp_c 31 "✗")" >&2
            printf '  Debian/Ubuntu fix: sudo apt install python3-venv\n' >&2
            printf '  Log: %s\n' "${BP_LOG_FILE:-unavailable}" >&2
            exit "$BP_EX_FAIL"
        fi
    else
        debug "venv already present at $BP_VENV_DIR"
    fi

    BP_RUN_PY="$BP_SOURCE_DIR/$BP_VENV_DIR/bin/python"
    if [[ ! -x "$BP_RUN_PY" ]]; then
        fatal "venv interpreter missing after creation: $BP_RUN_PY"
    fi
    ok "venv interpreter: $BP_RUN_PY ($("$BP_RUN_PY" --version 2>&1))"

    info "installing Python requirements ..."
    if ! "$BP_RUN_PY" -m pip install --upgrade pip setuptools wheel >>"$BP_LOG_FILE" 2>&1; then
        warn "pip/setuptools/wheel upgrade failed — continuing with existing versions."
    fi
    local req_args=(-r requirements.txt)
    if [[ -f constraints-dev.txt ]]; then
        req_args=(-c constraints-dev.txt -r requirements.txt)
        debug "using pinned constraints-dev.txt"
    fi
    if ! "$BP_RUN_PY" -m pip install "${req_args[@]}" >>"$BP_LOG_FILE" 2>&1; then
        printf '  %s pip install failed — core dependencies are REQUIRED.\n' "$(_bp_c 31 "✗")" >&2
        printf '  Likely cause: no network, or a build dependency missing.\n' >&2
        printf '  Rerun with --verbose, or: %s -m pip install -r requirements.txt\n' "$BP_RUN_PY" >&2
        printf '  Log: %s\n' "${BP_LOG_FILE:-unavailable}" >&2
        exit "$BP_EX_FAIL"
    fi
    ok "Python dependencies installed"

    # Provider-aware: the ollama SDK is only needed for models.provider=ollama.
    local provider=""
    provider="$("$BP_RUN_PY" -c '
try:
    import yaml
    cfg = yaml.safe_load(open("config.yaml")) or {}
    print(str((cfg.get("models") or {}).get("provider") or "ollama"))
except Exception:
    print("ollama")
' 2>/dev/null)"
    debug "active models.provider: $provider"
    if [[ "$provider" == "ollama" ]]; then
        if ! "$BP_RUN_PY" -c 'import ollama' >/dev/null 2>&1; then
            warn "ollama Python SDK missing for provider=ollama — installing extra."
            "$BP_RUN_PY" -m pip install "ollama>=0.6.1" >>"$BP_LOG_FILE" 2>&1 \
                || record_error "could not install ollama SDK (needed for models.provider=ollama)."
        fi
    fi

    # Core import smoke test — success means the env is genuinely usable.
    if ! "$BP_RUN_PY" -c 'import yaml, mcp, uvicorn, fastapi, websockets, questionary, numpy, cryptography' >>"$BP_LOG_FILE" 2>&1; then
        printf '  %s core imports failed — the venv is unusable.\n' "$(_bp_c 31 "✗")" >&2
        printf '  Log: %s\n' "${BP_LOG_FILE:-unavailable}" >&2
        exit "$BP_EX_VALIDATE"
    fi
    ok "core Python imports"
}

# ---------------------------------------------------------------------------
# WebUI (npm ci when a lockfile exists; skip when dist is fresh)
# ---------------------------------------------------------------------------
webui_needs_build() {
    local src="$BP_SOURCE_DIR/webui"
    [[ -f "$src/package.json" ]] || return 1 # no WebUI at all
    [[ -f "$src/dist/index.html" ]] || return 0
    # Rebuild when sources are newer than the bundle.
    if find "$src/src" "$src/package.json" "$src/package-lock.json" -newer "$src/dist/index.html" 2>/dev/null | grep -q .; then
        return 0
    fi
    return 1
}

setup_webui() {
    note_stage "webui"
    info "[5/9] WebUI"
    local src="$BP_SOURCE_DIR/webui"

    if [[ ! -f "$src/package.json" ]]; then
        warn "no webui/package.json — skipping WebUI."
        return 0
    fi
    if [[ -n "${SKIP_WEBUI_BUILD:-}" && "${SKIP_WEBUI_BUILD}" == "1" ]]; then
        warn "SKIP_WEBUI_BUILD=1 — skipping WebUI build."
        return 0
    fi
    if [[ "$BP_PROFILE" == "minimal" ]]; then
        info "minimal profile — skipping WebUI (built on first --web run)."
        return 0
    fi
    if ! webui_needs_build; then
        ok "WebUI bundle already fresh (dist/index.html)"
        return 0
    fi
    if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
        warn "node/npm missing — WebUI build skipped (app auto-builds on first --web if node exists)."
        warn "  install Node 18+ then rerun, or: cd webui && npm install && npm run build"
        return 0
    fi
    local node_major=""
    node_major="$(node --version 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/')"
    if [[ -n "$node_major" && "$node_major" -lt 18 ]]; then
        warn "node $(node --version) < 18 — WebUI build may fail; skipping (needs Node 18+)."
        return 0
    fi

    if is_dry_run; then
        info "[dry-run] would run npm ci/install + npm run build in webui/"
        return 0
    fi
    info "installing WebUI dependencies ..."
    if [[ -f "$src/package-lock.json" ]]; then
        (cd "$src" && npm ci --no-audit --no-fund >>"$BP_LOG_FILE" 2>&1) \
            || { record_error "npm ci failed (see log). WebUI unavailable until: cd webui && npm ci && npm run build"; return 0; }
    else
        (cd "$src" && npm install --no-audit --no-fund >>"$BP_LOG_FILE" 2>&1) \
            || { record_error "npm install failed (see log)."; return 0; }
    fi
    ok "WebUI dependencies"
    info "building WebUI (production bundle) ..."
    if ! (cd "$src" && npm run build >>"$BP_LOG_FILE" 2>&1); then
        record_error "npm run build failed (see log). WebUI unavailable until rebuilt."
        return 0
    fi
    if [[ -f "$src/dist/index.html" ]]; then
        ok "WebUI build (dist/index.html)"
    else
        record_error "build finished but dist/index.html was not produced."
    fi
}

# ---------------------------------------------------------------------------
# Ollama + models (provider-aware; never spawns unmanaged daemons blindly)
# ---------------------------------------------------------------------------
ollama_host_for() {
    # Echo the effective Ollama API base for chat or embed from config.yaml.
    local which="$1" # chat | embed
    "$BP_RUN_PY" -c '
import sys
try:
    import yaml
    cfg = yaml.safe_load(open("config.yaml")) or {}
except Exception:
    cfg = {}
if sys.argv[1] == "embed":
    print(str((cfg.get("ollama") or {}).get("embed_host") or "http://localhost:11434"))
else:
    print(str((cfg.get("ollama") or {}).get("host") or "https://api.ollama.com"))
' "$which" 2>/dev/null || { [[ "$which" == "embed" ]] && printf 'http://localhost:11434' || printf 'https://api.ollama.com'; }
}

ollama_api_ok() {
    # ollama_api_ok <host> — true when /api/version answers.
    local host="$1"
    curl -fsSL --connect-timeout 5 --max-time 15 "${host%/}/api/version" >/dev/null 2>>"$BP_LOG_FILE"
}

active_provider() {
    "$BP_RUN_PY" -c '
try:
    import yaml
    cfg = yaml.safe_load(open("config.yaml")) or {}
    print(str((cfg.get("models") or {}).get("provider") or "ollama"))
except Exception:
    print("ollama")
' 2>/dev/null || printf 'ollama'
}

setup_ollama() {
    note_stage "ollama"
    info "[6/9] Ollama / AI provider"
    local provider=""
    provider="$(active_provider)"
    info "active provider: $provider"

    if [[ "$provider" != "ollama" ]]; then
        ok "non-Ollama provider ($provider) — zero Ollama components needed"
        return 0
    fi
    local host=""
    host="$(ollama_host_for chat)"
    debug "ollama host: $host"

    if [[ "$host" == https://* && "$host" != *localhost* && "$host" != *127.0.0.1* ]]; then
        # Cloud endpoint: no daemon to manage; key is a runtime concern.
        if ollama_api_ok "$host"; then
            ok "Ollama Cloud reachable ($host)"
        else
            warn "Ollama Cloud unreachable — set OLLAMA_API_KEY at runtime (bp --setup-api-keys)."
        fi
        if [[ -z "${OLLAMA_API_KEY:-}" ]]; then
            warn "OLLAMA_API_KEY not set — AI calls will 401 until you run: bp --setup-api-keys"
        fi
        return 0
    fi

    # Local daemon needed.
    if ! command -v ollama >/dev/null 2>&1; then
        if is_dry_run; then
            info "[dry-run] would install ollama (https://ollama.com/install.sh | sh, or brew)"
            return 0
        fi
        case "$BP_OS_KIND" in
            kali | debian)
                if [[ -z "$BP_SUDO_CMD" && "$BP_IS_ROOT" != "1" ]]; then
                    record_error "ollama missing and no elevation to install it (https://ollama.com)."
                elif ! curl -fsSL https://ollama.com/install.sh | ${BP_SUDO_CMD:-} sh >>"$BP_LOG_FILE" 2>&1; then
                    record_error "ollama install failed — install manually from https://ollama.com"
                fi
                ;;
            macos)
                if command -v brew >/dev/null 2>&1; then
                    brew install ollama >>"$BP_LOG_FILE" 2>&1 || record_error "brew install ollama failed."
                else
                    record_error "ollama missing and no Homebrew (https://ollama.com)."
                fi
                ;;
        esac
    fi
    if ! command -v ollama >/dev/null 2>&1; then
        return 0
    fi
    ok "ollama binary ($(command -v ollama))"

    # Start the daemon only if nothing answers, preferring real services.
    if ollama_api_ok "http://localhost:11434"; then
        ok "ollama daemon already running"
        return 0
    fi
    if is_dry_run; then
        info "[dry-run] would start ollama daemon"
        return 0
    fi
    local started=0
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q ollama; then
        if ${BP_SUDO_CMD:-} systemctl start ollama >>"$BP_LOG_FILE" 2>&1; then started=1; fi
    elif command -v service >/dev/null 2>&1; then
        if ${BP_SUDO_CMD:-} service ollama start >>"$BP_LOG_FILE" 2>&1; then started=1; fi
    elif [[ "$BP_OS_KIND" == "macos" ]] && command -v brew >/dev/null 2>&1 && brew services list 2>/dev/null | grep -q ollama; then
        if brew services start ollama >>"$BP_LOG_FILE" 2>&1; then started=1; fi
    fi
    if [[ "$started" == "0" ]]; then
        info "starting 'ollama serve' in the background (log: $HOME/.local/state/breachpilot/ollama-serve.log)"
        mkdir -p "$HOME/.local/state/breachpilot" 2>/dev/null || true
        # Last resort only: track PID + log so it is not an orphan mystery.
        # shellcheck disable=SC2094
        (nohup ollama serve >"$HOME/.local/state/breachpilot/ollama-serve.log" 2>&1 &) || true
        echo $! >"$HOME/.local/state/breachpilot/ollama-serve.pid" 2>/dev/null || true
    fi
    local i=0
    for i in $(seq 1 20); do
        ollama_api_ok "http://localhost:11434" && break
        sleep 1
    done
    if ollama_api_ok "http://localhost:11434"; then
        ok "ollama daemon running"
    else
        record_error "ollama installed but the daemon is not answering on :11434."
    fi
}

pull_models() {
    note_stage "models"
    local provider=""
    provider="$(active_provider)"
    if [[ "$provider" != "ollama" ]]; then
        debug "skipping model pull (provider=$provider)"
        return 0
    fi
    if [[ "$BP_SKIP_MODELS" == "1" ]]; then
        info "skipping model pull (--skip-models)"
        return 0
    fi
    if ! command -v ollama >/dev/null 2>&1; then
        warn "ollama CLI missing — skipping model pull."
        return 0
    fi
    local host=""
    host="$(ollama_host_for chat)"
    if [[ "$host" == https://* && "$host" != *localhost* && "$host" != *127.0.0.1* ]]; then
        info "cloud models need no pull (verified by --doctor at validation)."
        return 0
    fi
    # Local daemon: pull the default chat + embedding models (real names from
    # config.yaml/schema: glm-5.2:cloud default alias target, nomic-embed-text).
    local chat_model="" embed_model=""
    chat_model="$("$BP_RUN_PY" -c '
try:
    import yaml
    cfg = yaml.safe_load(open("config.yaml")) or {}
    reg = (cfg.get("models") or {}).get("registry") or {}
    alias = (cfg.get("models") or {}).get("default_alias") or "glm"
    print(str(reg.get(alias) or "glm-5.2:cloud"))
except Exception:
    print("glm-5.2:cloud")
' 2>/dev/null)"
    embed_model="nomic-embed-text"
    if is_dry_run; then
        info "[dry-run] would: ollama pull $chat_model; ollama pull $embed_model"
        return 0
    fi
    info "[7/9] Models (best-effort; failures never fail the install)"
    if ollama pull "$chat_model" >>"$BP_LOG_FILE" 2>&1; then
        ok "model: $chat_model"
    else
        warn "pull failed for $chat_model (daemon running? disk space?). Rerun: ollama pull $chat_model"
    fi
    if ollama pull "$embed_model" >>"$BP_LOG_FILE" 2>&1; then
        ok "embedding model: $embed_model"
    else
        warn "pull failed for $embed_model (needed for semantic memory)."
    fi
}




# ---------------------------------------------------------------------------
# Optional tooling: ChatGPT runtime, sandbox image (both best-effort)
# ---------------------------------------------------------------------------
setup_chatgpt_runtime() {
    [[ "$BP_WITH_CHATGPT" == "1" ]] || return 0
    note_stage "chatgpt-runtime"
    info "ChatGPT provider runtime (--with-chatgpt)"
    # The app prefers bun, falls back to node (doctor chatgpt sub-check).
    if ! command -v bun >/dev/null 2>&1 && ! command -v node >/dev/null 2>&1; then
        warn "neither bun nor node found — install bun (https://bun.sh), then rerun."
        return 0
    fi
    local entry="oauth/packages/openai-oauth/src/cli.ts"
    if [[ ! -f "$BP_SOURCE_DIR/$entry" ]]; then
        warn "vendored openai-oauth not present ($entry missing) — skipping."
        warn "  see docs/providers.md for the expected oauth/ layout."
        return 0
    fi
    if is_dry_run; then
        info "[dry-run] would run bun/node install in oauth/"
        return 0
    fi
    if command -v bun >/dev/null 2>&1; then
        (cd "$BP_SOURCE_DIR/oauth" && bun install --frozen-lockfile >>"$BP_LOG_FILE" 2>&1) \
            || (cd "$BP_SOURCE_DIR/oauth" && bun install >>"$BP_LOG_FILE" 2>&1) \
            || warn "bun install failed in oauth/ — see docs/providers.md"
    else
        warn "bun missing, node present — run the oauth install manually (docs/providers.md)."
        return 0
    fi
    ok "openai-oauth dependencies"
}

setup_sandbox_image() {
    # Sandbox is default-ON and fail-closed (doctor _check_sandbox fails when
    # the worker image is missing), so build it when docker exists. Skippable
    # via BP_NO_SANDBOX_IMAGE=1 for air-gapped/manual flows.
    if [[ -n "${BP_NO_SANDBOX_IMAGE:-}" ]]; then
        debug "BP_NO_SANDBOX_IMAGE set — skipping worker image build"
        return 0
    fi
    [[ "$BP_PROFILE" == "minimal" ]] && return 0
    if ! command -v docker >/dev/null 2>&1; then
        debug "no docker — skipping sandbox image build"
        return 0
    fi
    if ! docker info >/dev/null 2>>"$BP_LOG_FILE"; then
        warn "docker daemon not running — skipping worker image build (start docker, then: docker build -t breachpilot-sandbox:latest docker/sandbox)."
        return 0
    fi
    if docker image inspect breachpilot-sandbox:latest >/dev/null 2>&1; then
        ok "sandbox worker image present"
        return 0
    fi
    if [[ ! -f "$BP_SOURCE_DIR/docker/sandbox/Dockerfile" ]]; then
        warn "docker/sandbox/Dockerfile missing — skipping image build."
        return 0
    fi
    if is_dry_run; then
        info "[dry-run] would: docker build -t breachpilot-sandbox:latest docker/sandbox"
        return 0
    fi
    info "building sandbox worker image (one-time, a few minutes) ..."
    if docker build -t breachpilot-sandbox:latest "$BP_SOURCE_DIR/docker/sandbox" >>"$BP_LOG_FILE" 2>&1; then
        ok "sandbox worker image built"
    else
        warn "sandbox image build failed (see log) — sandboxed runs will report SANDBOX_UNAVAILABLE."
    fi
}

# ---------------------------------------------------------------------------
# Launchers (breachpilot + bp) and idempotent PATH wiring
# ---------------------------------------------------------------------------
BP_PATH_MARK_BEGIN="# >>> Added by BreachPilot install.sh >>>"
BP_PATH_MARK_END="# <<< Added by BreachPilot install.sh <<<"

write_launcher() {
    # write_launcher <bin_dir> <name> — launcher resolves the install dir
    # at RUNTIME from its own symlink, so moved installs keep working.
    local bin_dir="$1" name="$2"
    local launcher="$bin_dir/$name"
    if is_dry_run; then
        info "[dry-run] would write launcher $launcher"
        return 0
    fi
    cat >"$launcher" <<'LAUNCHER_EOF'
#!/usr/bin/env bash
# breachpilot launcher (generated by install.sh). Resolves the install dir
# from its own location so it works from any cwd and survives moves.
set -euo pipefail
_LAUNCHER_SRC="${BASH_SOURCE[0]}"
while [[ -L "$_LAUNCHER_SRC" ]]; do
    _LAUNCHER_SRC="$(readlink "$_LAUNCHER_SRC")"
    case "$_LAUNCHER_SRC" in
        /*) : ;;
        *) _LAUNCHER_SRC="$(dirname "${BASH_SOURCE[0]}")/$_LAUNCHER_SRC" ;;
    esac
done
_BIN_DIR="$(cd "$(dirname "$_LAUNCHER_SRC")" && pwd)"
# Managed layout: <install>/.venv + <install>/main.py, marker .install-info.
# Checkout layout:  <repo>/.venv (or $VENV) + <repo>/main.py.
_ROOT=""
_CANDIDATE="$(cd "$_BIN_DIR/.." 2>/dev/null && pwd)"
if [[ -f "$_CANDIDATE/.install-info" && -f "$_CANDIDATE/main.py" ]]; then
    _ROOT="$_CANDIDATE"
elif [[ -n "${BREACHPILOT_HOME:-}" && -f "$BREACHPILOT_HOME/main.py" ]]; then
    _ROOT="$BREACHPILOT_HOME"
else
    echo "breachpilot: install not found (set BREACHPILOT_HOME=<dir> containing main.py)" >&2
    exit 1
fi
cd "$_ROOT" || { echo "breachpilot: cannot cd to $_ROOT" >&2; exit 1; }
_VENV_CANDIDATES=("${VENV:-.venv}" ".venv")
_PY=""
for _V in "${_VENV_CANDIDATES[@]}"; do
    if [[ -x "$_ROOT/$_V/bin/python" ]]; then _PY="$_ROOT/$_V/bin/python"; break; fi
done
_PY="${_PY:-python3}"
exec "$_PY" "$_ROOT/main.py" "$@"
LAUNCHER_EOF
    chmod +x "$launcher"
}

install_launchers() {
    note_stage "launchers"
    if [[ "$BP_NO_PATH" == "1" ]]; then
        info "skipping launchers (--no-path)"
        return 0
    fi
    info "[8/9] Launchers"
    local bin_dir="$HOME/.local/bin"
    if [[ "$BP_IS_ROOT" == "1" && -n "${SUDO_USER:-}" ]]; then
        # Root-via-sudo: still a user install for the invoking user is safer
        # to reason about — keep ~/.local/bin (root's home) but say so.
        warn "installing launchers into root's $bin_dir (ran via sudo)."
    fi
    if is_dry_run; then
        info "[dry-run] would install breachpilot + bp into $bin_dir and wire PATH"
        return 0
    fi
    if ! mkdir -p "$bin_dir" 2>/dev/null; then
        record_error "cannot create $bin_dir"
        return 0
    fi
    write_launcher "$bin_dir" "breachpilot"
    ok "breachpilot -> $bin_dir/breachpilot"
    if ln -sf "$bin_dir/breachpilot" "$bin_dir/bp" 2>/dev/null || cp -f "$bin_dir/breachpilot" "$bin_dir/bp"; then
        ok "bp -> $bin_dir/bp"
    else
        record_error "could not create $bin_dir/bp"
    fi
    # Remove the deprecated natai alias if a previous install left it.
    if [[ -e "$bin_dir/natai" ]]; then
        rm -f "$bin_dir/natai" 2>/dev/null || true
        debug "removed deprecated natai alias"
    fi
    ensure_path_block "$bin_dir"
}

ensure_path_block() {
    local bin_dir="$1"
    case ":$PATH:" in
        *":$bin_dir:"*)
            ok "$bin_dir already on PATH"
            return 0
            ;;
    esac
    local rc_file=""
    case "${SHELL:-}" in
        */zsh) rc_file="$HOME/.zshrc" ;;
        */bash) rc_file="$HOME/.bashrc" ;;
        *) rc_file="$HOME/.profile" ;;
    esac
    if grep -q "Added by BreachPilot install.sh" "$rc_file" 2>/dev/null; then
        ok "$bin_dir already wired into $rc_file"
        return 0
    fi
    {
        printf '\n%s\n' "$BP_PATH_MARK_BEGIN"
        printf 'case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH";; esac\n'
        printf '%s\n' "$BP_PATH_MARK_END"
    } >>"$rc_file" || { warn "could not append PATH block to $rc_file — add $bin_dir to PATH manually."; return 0; }
    ok "added $bin_dir to PATH in $rc_file (open a new terminal first)"
}

remove_path_blocks() {
    local rc=""
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        [[ -f "$rc" ]] || continue
        if grep -q "Added by BreachPilot install.sh" "$rc" 2>/dev/null; then
            if is_dry_run; then
                info "[dry-run] would remove PATH block from $rc"
                continue
            fi
            sed -i "/# >>> Added by BreachPilot install.sh >>>/,/# <<< Added by BreachPilot install.sh <<</d" "$rc" \
                && ok "removed PATH block from $rc" \
                || warn "could not edit $rc — remove the BreachPilot block manually."
        fi
    done
}

# ---------------------------------------------------------------------------
# Validation: structure + imports + launchers + WebUI + config + doctor
# ---------------------------------------------------------------------------
validate_installation() {
    # validate_installation — returns 0 only when the install REALLY works.
    note_stage "validate"
    info "[9/9] Validation"
    local failures=0

    # 1. Expected tree.
    local f=""
    for f in main.py pyproject.toml requirements.txt config.yaml mission.yaml tools mcp_server.py mcp_exploit_server.py; do
        if [[ ! -e "$BP_SOURCE_DIR/$f" ]]; then
            record_error "missing expected file: $f"
            failures=$((failures + 1))
        fi
    done
    [[ "$failures" == "0" ]] && ok "repository structure"

    # 2. Venv interpreter + core imports.
    if [[ ! -x "$BP_RUN_PY" ]]; then
        record_error "venv interpreter missing: $BP_RUN_PY"
        failures=$((failures + 1))
    elif ! "$BP_RUN_PY" -c 'import yaml, mcp, uvicorn, fastapi, websockets, questionary, numpy, cryptography' >>"$BP_LOG_FILE" 2>&1; then
        record_error "core Python imports failed in $BP_RUN_PY"
        failures=$((failures + 1))
    else
        ok "venv + core imports"
    fi

    # 3. Config parses (doctor covers schema; here: YAML must load).
    if ! "$BP_RUN_PY" -c 'import yaml; yaml.safe_load(open("config.yaml"))' >>"$BP_LOG_FILE" 2>&1; then
        record_error "config.yaml does not parse"
        failures=$((failures + 1))
    else
        ok "config.yaml parses"
    fi

    # 4. Launchers execute (unless --no-path).
    if [[ "$BP_NO_PATH" != "1" && "$BP_DRY_RUN" != "1" ]]; then
        if [[ -x "$HOME/.local/bin/breachpilot" ]]; then
            # --help must exit 0 without needing keys/network.
            if "$HOME/.local/bin/breachpilot" --help >/dev/null 2>>"$BP_LOG_FILE"; then
                ok "launcher executes (breachpilot --help)"
            else
                record_error "launcher runs but 'breachpilot --help' failed"
                failures=$((failures + 1))
            fi
        else
            record_error "launcher missing: $HOME/.local/bin/breachpilot"
            failures=$((failures + 1))
        fi
    fi

    # 5. WebUI bundle (required unless minimal or explicitly skipped).
    if [[ "$BP_PROFILE" != "minimal" && -z "${SKIP_WEBUI_BUILD:-}" && -f "$BP_SOURCE_DIR/webui/package.json" ]]; then
        if [[ -f "$BP_SOURCE_DIR/webui/dist/index.html" ]]; then
            ok "WebUI bundle (dist/index.html)"
        else
            record_error "WebUI bundle missing (dist/index.html not built)"
            failures=$((failures + 1))
        fi
    fi

    # 6. --doctor --json: machine-readable verdict (excluding AI-provider auth
    #    and sandbox-image states, which need keys/docker at runtime).
    if is_dry_run; then
        info "[dry-run] would run: python main.py --doctor"
        return 0
    fi
    local doctor_json=""
    doctor_json="$(make_temp_dir doctor)/doctor.json"
    local doctor_rc=0
    (cd "$BP_SOURCE_DIR" && "$BP_RUN_PY" main.py --doctor --json >"$doctor_json" 2>>"$BP_LOG_FILE") || doctor_rc=$?
    if [[ ! -s "$doctor_json" ]]; then
        record_error "--doctor produced no output (rc=$doctor_rc)"
        return 1
    fi
    local doctor_fail=""
    doctor_fail="$("$BP_RUN_PY" -c '
import json, sys
rep = json.load(open(sys.argv[1]))
# Provider-auth + sandbox-image + port-busy states are runtime concerns, not
# install defects: keys (OLLAMA_API_KEY/OPENCODE_GO_API_KEY/~/.codex/auth.json)
# are provisioned by the operator AFTER install, the sandbox image builds when
# docker is available, and ports may be busy from a running instance.
RUNTIME = ("ollama_reachable", "model_registry", "chatgpt_provider",
           "opencode_go_provider", "sandbox", "browser")
bad = [c.get("name","?") for c in rep.get("checks", [])
       if not c.get("ok") and not str(c.get("name","")).startswith("port_")
       and c.get("name") not in RUNTIME
       and c.get("name") not in ("optional_tools", "linux_privilege")]
print(" ".join(bad))
' "$doctor_json" 2>>"$BP_LOG_FILE")"
    if [[ -n "$doctor_fail" ]]; then
        record_error "--doctor core checks failing: $doctor_fail"
        failures=$((failures + 1))
    else
        ok "BreachPilot doctor (core checks)"
    fi
    if [[ "$doctor_rc" != "0" ]]; then
        warn "--doctor exit=$doctor_rc (often provider keys/sandbox/ports — see 'bp --doctor')."
    fi

    if [[ "$failures" -gt 0 ]]; then
        return "$BP_EX_VALIDATE"
    fi
    return 0
}




# ---------------------------------------------------------------------------
# User-data preservation (update path)
# ---------------------------------------------------------------------------
preserve_user_data() {
    # preserve_user_data <live_dir> <stage_dir> — copy persistent items from
    # the live install into the staged tree BEFORE activation.
    local live="$1" stage="$2" item=""
    for item in "${BP_PRESERVE_ITEMS[@]}"; do
        if [[ -e "$live/$item" ]]; then
            debug "preserving $item"
            if is_dry_run; then
                continue
            fi
            rm -rf "$stage/$item" 2>/dev/null || true
            if ! cp -a "$live/$item" "$stage/$item" 2>>"$BP_LOG_FILE"; then
                warn "could not preserve $item — continuing (your live copy is untouched)."
            fi
        fi
    done
    # Never carry installer metadata or venvs across versions.
    rm -rf "$stage/.venv" "$stage/venv" "$stage/__pycache__" 2>/dev/null || true
}

backup_live_install() {
    # backup_live_install <live_dir> — copy (not move) aside for rollback.
    local live="$1"
    local parent="" stamp=""
    parent="$(dirname "$live")"
    stamp="$(date '+%Y%m%d-%H%M%S')"
    BP_UPDATE_BACKUP="${parent}/.breachpilot-backup-${stamp}"
    if is_dry_run; then
        info "[dry-run] would back up $live"
        return 0
    fi
    if ! cp -a "$live" "$BP_UPDATE_BACKUP" 2>>"$BP_LOG_FILE"; then
        error "cannot back up existing install — refusing to update without a backup."
        return "$BP_EX_UPDATE"
    fi
    debug "backup at $BP_UPDATE_BACKUP"
    return 0
}

restore_backup() {
    [[ -n "$BP_UPDATE_BACKUP" && -d "$BP_UPDATE_BACKUP" ]] || return 1
    [[ -n "$BP_SOURCE_DIR" ]] || return 1
    rm -rf "$BP_SOURCE_DIR" 2>/dev/null || true
    mv "$BP_UPDATE_BACKUP" "$BP_SOURCE_DIR" || return 1
    BP_UPDATE_BACKUP=""
    return 0
}

# ---------------------------------------------------------------------------
# --check (read-only diagnostics)
# ---------------------------------------------------------------------------
run_check() {
    note_stage "check"
    local target="$BP_SOURCE_DIR"
    if [[ ! -d "$target" ]]; then
        target="$(default_install_dir)"
    fi
    printf '\n%s\n\n' "$(_bp_c 1 "BreachPilot Installation Check")"

    printf 'Platform\n'
    printf '  OS                   %s\n' "${BP_OS_NAME:-$BP_OS_KIND}"
    printf '  Architecture         %s\n' "$BP_ARCH"
    printf '  Shell                %s\n' "${SHELL:-unknown}"
    printf '  Package manager      %s\n' "${BP_PKG_MGR:-none}"
    printf '\nCore\n'
    if is_breachpilot_checkout "$target"; then
        printf '  Installation         %s %s\n' "$(_bp_c 32 "✓")" "$target"
        if [[ -f "$target/.install-info" ]]; then
            printf '  Version              %s\n' "$(read_install_info "$target" "version")"
            printf '  Commit               %s\n' "$(read_install_info "$target" "commit_sha")"
        else
            printf '  Version              %s\n' "(dev checkout — no install metadata)"
            if command -v git >/dev/null 2>&1 && [[ -d "$target/.git" ]]; then
                printf '  Commit               %s\n' "$(git -C "$target" rev-parse --short HEAD 2>/dev/null || echo unknown)"
            fi
        fi
        local py="${PYTHON:-python3}"
        local vpy="$target/${VENV:-.venv}/bin/python"
        [[ -x "$vpy" ]] && py="$vpy"
        if command -v "$py" >/dev/null 2>&1 && check_python_version "$py"; then
            printf '  Python               %s %s\n' "$(_bp_c 32 "✓")" "$("$py" --version 2>&1)"
        else
            printf '  Python               %s needs 3.11+\n' "$(_bp_c 31 "✗")"
        fi
        [[ -x "$vpy" ]] && printf '  Virtualenv           %s %s\n' "$(_bp_c 32 "✓")" "$vpy" \
            || printf '  Virtualenv           %s missing\n' "$(_bp_c 33 "--")"
        if "$py" -c 'import yaml, mcp, uvicorn, fastapi, websockets, questionary' >/dev/null 2>&1; then
            printf '  Dependencies         %s importable\n' "$(_bp_c 32 "✓")"
        else
            printf '  Dependencies         %s incomplete\n' "$(_bp_c 31 "✗")"
        fi
        [[ -f "$target/webui/dist/index.html" ]] && printf '  WebUI                %s built\n' "$(_bp_c 32 "✓")" \
            || printf '  WebUI                %s not built\n' "$(_bp_c 33 "--")"
    else
        printf '  Installation         %s not found at %s\n' "$(_bp_c 33 "--")" "$target"
    fi

    printf '\nServices\n'
    if command -v ollama >/dev/null 2>&1; then
        printf '  Ollama               %s %s\n' "$(_bp_c 32 "✓")" "$(command -v ollama)"
    else
        printf '  Ollama               %s not on PATH\n' "$(_bp_c 33 "--")"
    fi
    if curl -fsSL --connect-timeout 3 --max-time 8 http://localhost:11434/api/version >/dev/null 2>&1; then
        printf '  Ollama API           %s reachable\n' "$(_bp_c 32 "✓")"
    else
        printf '  Ollama API           %s not answering\n' "$(_bp_c 33 "--")"
    fi

    printf '\nTools (optional — missing entries never fail the install)\n'
    local t=""
    for t in nmap tmux searchsploit msfconsole hydra impacket-secretsdump nuclei nikto sqlmap gobuster feroxbuster whatweb wpscan dirb hashcat john nxc docker bun node npm; do
        if command -v "$t" >/dev/null 2>&1; then
            printf '  %-22s %s\n' "$t" "$(_bp_c 32 "✓")"
        else
            printf '  %-22s %s\n' "$t" "$(_bp_c 33 "--")"
        fi
    done
    printf '\nFull verdict: bp --doctor (or ./install.sh --doctor)\n'
    return 0
}

# ---------------------------------------------------------------------------
# Actions: install / update / repair / doctor / uninstall
# ---------------------------------------------------------------------------
print_summary() {
    local version_label="${BP_VERSION_LABEL:-$(read_install_info "$BP_SOURCE_DIR" "version")}"
    [[ -n "$version_label" ]] || version_label="checkout"
    local width=54
    local rule=""
    rule="$(printf '━%.0s' $(seq 1 "$width"))"
    printf '\n%s\n' "$rule"
    if [[ "$BP_FAILED" == "1" ]]; then
        printf '%s\n' "$(_bp_c 31 "Installation completed with errors.")"
        printf 'BreachPilot is not ready to run.\n'
        printf '\nFailures:\n'
        local e=""
        for e in "${BP_ERRORS[@]}"; do
            printf '  • %s\n' "$e"
        done
        printf '\nRun:\n  bp --doctor\n'
        printf '\nLog:\n  %s\n' "${BP_LOG_FILE:-unavailable}"
    else
        printf '%s\n' "$(_bp_c 32 "✓ BreachPilot installed successfully")"
        printf '\nVersion:  %s\n' "$version_label"
        printf 'Path:     %s\n' "$BP_SOURCE_DIR"
        printf 'Command:  bp\n'
        printf 'WebUI:    http://127.0.0.1:8765\n'
        printf '\nRun:\n  bp\n'
    fi
    printf '%s\n' "$rule"
}

perform_install() {
    # Fresh install into BP_SOURCE_DIR (checkout in place, or staged download).
    if [[ "$BP_MANAGED" == "1" && "$BP_DEV_CHECKOUT" != "1" ]]; then
        # Bootstrap/update-staged path already prepared BP_SOURCE_DIR.
        :
    fi
    cd "$BP_SOURCE_DIR" || fatal "cannot cd to $BP_SOURCE_DIR"

    run_preflight
    install_system_dependencies
    setup_python
    setup_webui
    setup_ollama
    setup_chatgpt_runtime
    setup_sandbox_image
    pull_models
    install_launchers
    if [[ "$BP_MANAGED" == "1" ]]; then
        write_install_info "$BP_SOURCE_DIR"
    fi
    local rc=0
    validate_installation || rc=$?
    print_summary
    if [[ "$rc" != "0" ]]; then
        printf '\n%s\n' "$(_bp_c 31 "Validation failed — see failures above.")"
        exit "$BP_EX_VALIDATE"
    fi
    if [[ "$BP_FAILED" == "1" ]]; then
        exit "$BP_EX_FAIL"
    fi
}

perform_update() {
    note_stage "update"
    if [[ "$BP_DEV_CHECKOUT" == "1" && "$BP_ALLOW_DEV" != "1" ]]; then
        printf 'error: %s looks like your development checkout (has .git, no .install-info).\n' "$BP_SOURCE_DIR" >&2
        printf 'Refusing to update it. Options:\n' >&2
        printf '  • manage it with git yourself (git pull), then ./install.sh --repair\n' >&2
        printf '  • rerun with --allow-dev to force a staged update (your git state is left alone; source is replaced)\n' >&2
        printf '  • use --install-dir PATH for a separate managed install\n' >&2
        exit "$BP_EX_ARGS"
    fi

    local installed="unknown"
    [[ -f "$BP_SOURCE_DIR/.install-info" ]] && installed="$(read_install_info "$BP_SOURCE_DIR" "version")"
    info "Installed: $installed"
    resolve_version
    info "Available: $BP_VERSION_LABEL"
    printf 'Repository:    %s\n' "$BP_REPO"
    printf 'Version:       %s\n' "$BP_VERSION_LABEL"
    printf 'Install path:  %s\n' "$BP_SOURCE_DIR"
    printf 'Source:        GitHub (%s)\n' "$BP_VERSION_SOURCE"

    if [[ -n "$installed" && "$installed" == "$BP_VERSION_LABEL" && -z "$BP_DESIRED_VERSION" ]]; then
        local live_sha=""
        live_sha="$(read_install_info "$BP_SOURCE_DIR" "commit_sha")"
        if [[ -n "$live_sha" && -n "${BP_RESOLVED_SHA:-}" && "$live_sha" == "$BP_RESOLVED_SHA" ]]; then
            ok "BreachPilot is already up to date."
            return 0
        fi
        if [[ -z "${BP_RESOLVED_SHA:-}" ]]; then
            ok "BreachPilot is already up to date (same ref: $installed)."
            return 0
        fi
    fi

    if [[ "$BP_NONINTERACTIVE" != "1" && "$BP_ASSUME_YES" != "1" ]]; then
        confirm "Update $BP_SOURCE_DIR to $BP_VERSION_LABEL?" || { info "update cancelled."; return 0; }
    fi

    local stage_parent=""
    stage_parent="$(make_temp_dir update)"
    local staged="$stage_parent/new"
    if ! download_source "$BP_RESOLVED_REF" "$staged"; then
        error "update aborted: could not fetch $BP_RESOLVED_REF."
        exit "$BP_EX_DOWNLOAD"
    fi

    # Build + validate the staged tree BEFORE touching the live install.
    local saved_source="$BP_SOURCE_DIR" saved_py="$BP_RUN_PY" saved_venv="$BP_VENV_DIR"
    BP_SOURCE_DIR="$staged"
    BP_VENV_DIR="$staged/.venv"
    preserve_user_data "$saved_source" "$staged"
    run_preflight
    install_system_dependencies
    setup_python
    setup_webui
    setup_chatgpt_runtime
    setup_sandbox_image
    # NOTE: ollama/models/launchers intentionally NOT run against staging;
    # they are host-global and run after activation.
    local rc=0
    validate_installation || rc=$?
    if [[ "$rc" != "0" || "$BP_FAILED" == "1" ]]; then
        error "staged build failed validation — live install untouched."
        exit "$BP_EX_VALIDATE"
    fi

    # Atomic activation: backup, swap, verify, drop backup. Roll back on error.
    if ! backup_live_install "$saved_source"; then
        exit "$BP_EX_UPDATE"
    fi
    BP_UPDATE_STAGED=1
    BP_UPDATE_BACKUP="${BP_UPDATE_BACKUP:-}"
    local backup="$BP_UPDATE_BACKUP"
    if is_dry_run; then
        info "[dry-run] would activate staged build at $saved_source"
        BP_SOURCE_DIR="$saved_source"
        BP_RUN_PY="$saved_py"
        BP_VENV_DIR="$saved_venv"
        return 0
    fi
    # Move live aside first so the path is never missing: live -> trash,
    # staged -> live. On any failure, restore from backup.
    local trash="${saved_source}.activating"
    rm -rf "$trash" 2>/dev/null || true
    if ! mv "$saved_source" "$trash"; then
        error "cannot move live install aside — restoring backup."
        BP_SOURCE_DIR="$saved_source"
        restore_backup || true
        exit "$BP_EX_UPDATE"
    fi
    if ! mv "$staged" "$saved_source"; then
        error "cannot activate staged build — restoring backup."
        mv "$trash" "$saved_source" 2>/dev/null || restore_backup || true
        BP_SOURCE_DIR="$saved_source"
        exit "$BP_EX_UPDATE"
    fi
    rm -rf "$trash" 2>/dev/null || true

    BP_SOURCE_DIR="$saved_source"
    BP_VENV_DIR="$saved_source/.venv"
    BP_RUN_PY="$saved_source/.venv/bin/python"
    [[ -x "$BP_RUN_PY" ]] || BP_RUN_PY="${PYTHON:-python3}"
    BP_UPDATE_STAGED=0

    setup_ollama
    pull_models
    install_launchers
    write_install_info "$BP_SOURCE_DIR"

    rc=0
    validate_installation || rc=$?
    if [[ "$rc" != "0" ]]; then
        error "activated build failed validation — rolling back."
        if restore_backup; then
            BP_SOURCE_DIR="$saved_source"
            ok "rollback complete — previous installation restored."
        else
            error "ROLLBACK FAILED — backup retained at: $backup"
        fi
        exit "$BP_EX_UPDATE"
    fi
    rm -rf "$backup" 2>/dev/null || warn "could not remove backup $backup (harmless)."
    BP_UPDATE_BACKUP=""
    BP_RUN_PY="$saved_py"
    [[ -x "$BP_SOURCE_DIR/.venv/bin/python" ]] && BP_RUN_PY="$BP_SOURCE_DIR/.venv/bin/python"
    print_summary
}

perform_repair() {
    note_stage "repair"
    if [[ ! -d "$BP_SOURCE_DIR" ]]; then
        fatal "nothing to repair at $BP_SOURCE_DIR (use ./install.sh for a fresh install)."
    fi
    cd "$BP_SOURCE_DIR" || fatal "cannot cd to $BP_SOURCE_DIR"
    info "repairing $BP_SOURCE_DIR (config + user data untouched)"

    if [[ ! -x "$BP_VENV_DIR/bin/python" ]]; then
        warn "venv missing — recreating."
        rm -rf "$BP_VENV_DIR" 2>/dev/null || true
    fi
    run_preflight
    setup_python
    setup_webui
    setup_ollama
    setup_chatgpt_runtime
    pull_models
    install_launchers
    local rc=0
    validate_installation || rc=$?
    print_summary
    [[ "$rc" == "0" ]] || exit "$BP_EX_VALIDATE"
}

perform_doctor() {
    note_stage "doctor"
    if ! is_breachpilot_checkout "$BP_SOURCE_DIR"; then
        fatal "no BreachPilot install at $BP_SOURCE_DIR."
    fi
    local py="${PYTHON:-python3}"
    [[ -x "$BP_SOURCE_DIR/${VENV:-.venv}/bin/python" ]] && py="$BP_SOURCE_DIR/${VENV:-.venv}/bin/python"
    (cd "$BP_SOURCE_DIR" && exec "$py" main.py --doctor)
}

perform_uninstall() {
    note_stage "uninstall"
    local target="$BP_SOURCE_DIR"
    if [[ ! -d "$target" ]]; then
        target="$(default_install_dir)"
    fi
    printf 'This will remove:\n'
    printf '  • managed app files: %s\n' "$target"
    printf '  • launchers: ~/.local/bin/{breachpilot,bp}\n'
    printf '  • the BreachPilot PATH block in shell rc files\n'
    printf 'It preserves: config.yaml, .env, secr.json, mission.yaml, reports/,\n'
    printf 'research_workspace/, exploit_workspace/, swarm_workspace/, api_runtime.db, logs/\n'
    if [[ "$BP_ASSUME_YES" != "1" && "$BP_NONINTERACTIVE" != "1" ]]; then
        confirm "Uninstall BreachPilot at $target?" || { info "uninstall cancelled."; exit "$BP_EX_OK"; }
    fi

    local bin_dir="$HOME/.local/bin"
    if is_dry_run; then
        info "[dry-run] would remove $target (+ launchers + PATH block), preserving user data"
        remove_path_blocks
        return 0
    fi

    # Preserve user data OUT of the tree first (so rm -rf cannot take it).
    local keep=""
    keep="$(make_temp_dir uninstall-keep)"
    local item=""
    for item in "${BP_PRESERVE_ITEMS[@]}"; do
        if [[ -e "$target/$item" ]]; then
            cp -a "$target/$item" "$keep/$item" 2>/dev/null || warn "could not stage $item for preservation."
        fi
    done
    # Refuse to delete what is not ours.
    if [[ -d "$target" ]]; then
        if [[ "$BP_MANAGED" != "1" ]] && ! is_managed_install "$target"; then
            printf 'error: %s is not installer-managed (no .install-info).\n' "$target" >&2
            printf 'Refusing to delete it. Remove it manually if you really mean it.\n' >&2
            exit "$BP_EX_ARGS"
        fi
        rm -rf "$target" || fatal "could not remove $target"
        ok "removed $target"
    fi
    # Restore preserved data next to the install location.
    local restore_base="$(dirname "$target")/breachpilot-user-data"
    if [[ -n "$(ls -A "$keep" 2>/dev/null)" ]]; then
        mkdir -p "$restore_base" 2>/dev/null || true
        cp -a "$keep/." "$restore_base/" 2>/dev/null || warn "could not restore user data — staged copy retained."
        ok "user data preserved at $restore_base"
    fi
    rm -f "$bin_dir/breachpilot" "$bin_dir/bp" "$bin_dir/natai" 2>/dev/null || true
    ok "removed launchers"
    remove_path_blocks
    printf '\nUninstalled. User data preserved at %s\n' "$restore_base"
    printf 'Open a new terminal for PATH changes to take effect.\n'
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
print_banner() {
    [[ "$BP_QUIET" == "1" ]] && return 0
    printf '\n%s\n' "$(_bp_c 1 "╭──────────────────────────────────────────────╮")"
    printf '%s\n' "$(_bp_c 1 "│            BreachPilot Installer             │")"
    printf '%s\n\n' "$(_bp_c 1 "╰──────────────────────────────────────────────╯")"
}

main() {
    parse_args "$@"
    install_traps
    detect_environment
    init_logging
    detect_platform
    resolve_source_dir

    case "$BP_ACTION" in
        check)
            run_check
            exit "$BP_EX_OK"
            ;;
        doctor)
            perform_doctor
            ;;
        uninstall)
            perform_uninstall
            exit "$BP_EX_OK"
            ;;
        repair)
            print_banner
            perform_repair
            exit "$BP_EX_OK"
            ;;
        update)
            print_banner
            resolve_version
            # Bootstrap-update: no local install → behave like a fresh
            # managed install of the resolved version.
            if [[ ! -d "$BP_SOURCE_DIR" ]] || ! is_breachpilot_checkout "$BP_SOURCE_DIR"; then
                info "no existing install at $BP_SOURCE_DIR — performing fresh install."
                local stage_parent=""
                stage_parent="$(make_temp_dir bootstrap)"
                if ! download_source "$BP_RESOLVED_REF" "$stage_parent/new"; then
                    exit "$BP_EX_DOWNLOAD"
                fi
                BP_SOURCE_DIR="$stage_parent/new"
                BP_MANAGED=1
                BP_VENV_DIR="$BP_SOURCE_DIR/.venv"
                perform_install
                # Move the validated tree to its managed home.
                if ! is_dry_run; then
                    rm -rf "$(default_install_dir)" 2>/dev/null || true
                    mkdir -p "$(dirname "$(default_install_dir)")"
                    mv "$BP_SOURCE_DIR" "$(default_install_dir)" || fatal "cannot move install into place."
                    BP_SOURCE_DIR="$(default_install_dir)"
                    BP_VENV_DIR="$BP_SOURCE_DIR/.venv"
                    BP_RUN_PY="$BP_SOURCE_DIR/.venv/bin/python"
                    install_launchers
                    write_install_info "$BP_SOURCE_DIR"
                fi
                exit "$BP_EX_OK"
            fi
            perform_update
            exit "$BP_EX_OK"
            ;;
        install)
            print_banner
            if [[ "$BP_MANAGED" == "1" && "$BP_DEV_CHECKOUT" != "1" && ! -d "$BP_SOURCE_DIR" ]]; then
                # Piped/standalone with no install yet: fetch, then install.
                resolve_version
                printf 'Repository:    %s\n' "$BP_REPO"
                printf 'Version:       %s\n' "$BP_VERSION_LABEL"
                printf 'Install path:  %s\n' "$BP_SOURCE_DIR"
                printf 'Source:        GitHub (%s)\n' "$BP_VERSION_SOURCE"
                local stage_parent=""
                stage_parent="$(make_temp_dir bootstrap)"
                if ! download_source "$BP_RESOLVED_REF" "$stage_parent/new"; then
                    exit "$BP_EX_DOWNLOAD"
                fi
                local final_dir="$BP_SOURCE_DIR"
                BP_SOURCE_DIR="$stage_parent/new"
                BP_VENV_DIR="$BP_SOURCE_DIR/.venv"
                perform_install
                if ! is_dry_run; then
                    mkdir -p "$(dirname "$final_dir")"
                    mv "$BP_SOURCE_DIR" "$final_dir" || fatal "cannot move install into place."
                    BP_SOURCE_DIR="$final_dir"
                    BP_VENV_DIR="$BP_SOURCE_DIR/.venv"
                    BP_RUN_PY="$BP_SOURCE_DIR/.venv/bin/python"
                    install_launchers
                    write_install_info "$BP_SOURCE_DIR"
                fi
                exit "$BP_EX_OK"
            fi
            # Checkout install (existing tree, in place).
            BP_VERSION_LABEL="${BP_VERSION_LABEL:-checkout}"
            perform_install
            exit "$BP_EX_OK"
            ;;
        *)
            printf 'error: unknown action: %s\n' "$BP_ACTION" >&2
            exit "$BP_EX_ARGS"
            ;;
    esac
}

main "$@"
