#!/usr/bin/env bash
# One-shot host bootstrap for the BreachPilot engine.
#
# Actually installs everything (unlike scripts/setup-linux.sh, which only
# checks and prints hints): OS-level prereqs (nmap, tmux, optional Kali
# tooling), Ollama, the Python venv + requirements, then pulls the default
# model + embedding model and runs `python main.py --doctor`.
#
# Idempotent: safe to re-run. Run from the repository root:
#     ./install.sh
#     ./install.sh --uninstall   # remove the `breachpilot`/`bp` commands + PATH line
#
# Env knobs: PYTHON=python3  VENV=.venv  INSTALL_KALI_TOOLS=1  INSTALL_SCANNERS=1  SKIP_MODEL_PULL=1
#            ADD_TO_PATH=1            # 0 skips installing the `breachpilot`/`bp` commands
set -euo pipefail

# --- --uninstall (run before anything else) --------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
    BIN_DIR="$HOME/.local/bin"
    echo "==> Removing the \`breachpilot\` and \`bp\` commands"
    rm -f "$BIN_DIR/breachpilot" && echo "  [OK] removed $BIN_DIR/breachpilot" || echo "  [--] $BIN_DIR/breachpilot was not present"
    rm -f "$BIN_DIR/bp" && echo "  [OK] removed $BIN_DIR/bp" || echo "  [--] $BIN_DIR/bp was not present"
    rm -f "$BIN_DIR/natai" && echo "  [OK] removed deprecated $BIN_DIR/natai" || true
    # Strip the guarded PATH block from any rc file we may have touched.
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        [[ -f "$rc" ]] || continue
        if grep -q "Added by BreachPilot install.sh" "$rc"; then
            sed -i '/# >>> Added by BreachPilot install.sh >>>/,/# <<< Added by BreachPilot install.sh <<</d' "$rc"
            echo "  [OK] removed PATH block from $rc"
        fi
    done
    echo
    echo "Uninstalled. Open a new terminal (or \`source ~/.bashrc\`) for PATH changes to take effect."
    exit 0
fi

PYTHON="${PYTHON:-python3}"
VENV="${VENV:-.venv}"
INSTALL_KALI_TOOLS="${INSTALL_KALI_TOOLS:-1}"
SKIP_MODEL_PULL="${SKIP_MODEL_PULL:-0}"
ADD_TO_PATH="${ADD_TO_PATH:-1}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# --- detect OS ---------------------------------------------------------------
OS_KIND="unknown"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in
        debian|ubuntu|kali|linuxmint|pop) OS_KIND="debian" ;;
    esac
    case "${ID_LIKE:-}" in
        *debian*|*ubuntu*) OS_KIND="debian" ;;
    esac
elif [[ "$(uname -s)" == "Darwin" ]]; then
    OS_KIND="macos"
fi

have() { command -v "$1" >/dev/null 2>&1; }

# --- 1. OS-level prerequisites (best-effort; never aborts the install) -----
echo "==> Installing OS-level prerequisites ($OS_KIND)"
case "$OS_KIND" in
    debian)
        # Only hit apt if something's actually missing — avoids a sudo prompt
        # (and a non-interactive sudo failure aborting the whole script) when
        # nmap/python3-venv/tmux/curl/git are already installed.
        if have nmap && "$PYTHON" -c "import venv" >/dev/null 2>&1 && have tmux && have curl && have git; then
            echo "  [OK] nmap, python3-venv, tmux, curl, git already present — skipping apt-get"
        else
            sudo apt-get update \
                || echo "  [!] apt-get update failed (sudo password? network?). Continuing — install missing prereqs manually if needed."
            sudo apt-get install -y nmap python3-venv tmux curl git \
                || echo "  [!] apt-get install failed (sudo password? network?). Continuing — install missing prereqs manually if needed."
        fi
        if [[ "$INSTALL_KALI_TOOLS" == "1" ]]; then
            # Only present on Kali; missing packages are tolerated so this stays
            # safe on plain Ubuntu/Debian. Best-effort: never aborts.
            # NOTE: CrackMapExec was archived upstream and renamed to NetExec
            # (binary nxc); impacket-scripts is transitional toward
            # python3-impacket. Try modern names first, fall back to legacy.
            # No output suppression: a bare `|| echo` keeps this non-fatal
            # while still showing WHICH package name failed.
            sudo apt-get install -y metasploit-framework exploitdb hydra netexec python3-impacket \
                || sudo apt-get install -y metasploit-framework exploitdb hydra crackmapexec impacket-scripts \
                || echo "  [--] some Kali-only packages unavailable on this distro (fine if staying in read_only)"
        fi
        if [[ "${INSTALL_SCANNERS:-1}" == "1" ]]; then
            # Web scanners / crackers / wordlists shelled out to by run_web_scan
            # + run_hash_crack (tools/mcp_tools/web_scan.py, cracking.py).
            # Per-package attempts: one distro-missing name must not block the
            # rest. Best-effort: never aborts. Skip with INSTALL_SCANNERS=0.
            if have nikto && have sqlmap && have gobuster && have whatweb \
                && have dirb && have hashcat && have john; then
                echo "  [OK] web scanners + crackers already present — skipping apt-get"
            else
                sudo apt-get update \
                    || echo "  [!] apt-get update failed (sudo password? network?). Scanner installs below may fail."
                for _pkg in nikto sqlmap gobuster whatweb dirb hashcat john seclists wget; do
                    if dpkg -s "$_pkg" >/dev/null 2>&1; then
                        echo "  [OK] $_pkg already installed"
                    else
                        sudo apt-get install -y "$_pkg" \
                            && echo "  [OK] $_pkg installed" \
                            || echo "  [--] $_pkg unavailable on this distro (the engine will report a hint instead)"
                    fi
                done
                unset _pkg
                # Not apt-installable anywhere — point at the manual installs.
                for _tool in nuclei feroxbuster wpscan; do
                    have "$_tool" \
                        || echo "  [--] $_tool not on PATH (manual install, optional — see docs/deployment.md)"
                done
                unset _tool
            fi
        fi
        ;;
    macos)
        if have brew; then
            brew install nmap python tmux curl \
                || echo "  [!] brew install failed. Continuing — install missing prereqs manually if needed."
        else
            echo "  [!] Homebrew not found (https://brew.sh). Install nmap/python/tmux/curl manually, then re-run."
        fi
        ;;
    *)
        echo "  [!] Unknown OS — skipping OS-package install. Ensure nmap + python3-venv are installed,"
        echo "      then continue. (The venv + \`breachpilot\` steps below will still run if python3 is present.)"
        ;;
esac

# --- 2. Ollama (best-effort) -----------------------------------------------
echo "==> Ensuring Ollama is installed and running"
if ! have ollama; then
    case "$OS_KIND" in
        debian) curl -fsSL https://ollama.com/install.sh | sh \
                    || echo "  [!] ollama install failed — install it manually from https://ollama.com" ;;
        macos)  have brew && { brew install ollama || echo "  [!] brew install ollama failed"; } ;;
    esac
fi
# Start the daemon if it isn't up (best-effort; non-fatal if already running).
if have ollama; then
    if ! curl -sf http://localhost:11434/api/version >/dev/null 2>&1; then
        echo "  -> starting ollama serve in the background"
        (nohup ollama serve >/tmp/ollama-serve.log 2>&1 &) || true
        # wait for it to come up
        for _ in $(seq 1 20); do
            curl -sf http://localhost:11434/api/version >/dev/null 2>&1 && break
            sleep 1
        done
    fi
    echo "  [OK] ollama ($(command -v ollama))"
else
    echo "  [!] ollama still not on PATH — AI-backed flows will fail until you install it."
fi

# --- 2b. openai-oauth (ChatGPT provider, best-effort / opt-in) ------------
# Only needed if you set models.provider: chatgpt. Requires bun (bun.sh).
# Never aborts the install if bun or the checkout is missing.
if [[ -d "$REPO_ROOT/oauth" ]] && have bun; then
    echo "==> Preparing vendored openai-oauth (ChatGPT provider) via bun install"
    (cd "$REPO_ROOT/oauth" && bun install) \
        || echo "  [!] bun install failed in oauth/ — ChatGPT provider won't be runnable until it succeeds. See docs/providers.md."
else
    echo "==> Skipping openai-oauth setup (no oauth/ checkout or bun not on PATH)."
    echo "    ChatGPT provider is opt-in: install bun (https://bun.sh), then run 'bun install' in oauth/. See docs/providers.md."
fi

# --- 3. Python venv + requirements (resilient) ----------------------------
# python3 itself is the one true hard requirement: without it nothing works.
if ! have "$PYTHON"; then
    echo "  [!] '$PYTHON' not found. Install Python 3.11+ and re-run (or set PYTHON=...)."
    exit 1
fi
echo "==> Creating venv ($VENV) with $($PYTHON --version)"
VENV_OK=1
if ! "$PYTHON" -m venv "$VENV"; then
    echo "  [!] venv creation failed (is python3-venv installed? Debian/Ubuntu: sudo apt-get install python3-venv)."
    echo "      Continuing — \`breachpilot\` will fall back to system python3, but deps may be missing."
    VENV_OK=0
fi
# Use the venv interpreter directly when available (no `source activate` needed,
# so a failed venv doesn't abort the script under `set -e`).
VENV_PY="$REPO_ROOT/$VENV/bin/python"
RUN_PY="$PYTHON"
if [[ "$VENV_OK" == "1" ]] && [[ -x "$VENV_PY" ]]; then
    RUN_PY="$VENV_PY"
    echo "==> Upgrading pip + installing requirements"
    "$RUN_PY" -m pip install --upgrade pip \
        || echo "  [!] pip upgrade failed — continuing"
    "$RUN_PY" -m pip install -r requirements.txt \
        || echo "  [!] pip install -r requirements.txt failed (network?). Re-run install.sh once available — \`breachpilot\` still installs."
else
    echo "  [!] no usable venv interpreter; skipping pip install. \`breachpilot\` will use system python3."
fi

# --- 4. Pull models (best-effort) -----------------------------------------
if [[ "$SKIP_MODEL_PULL" != "1" ]] && have ollama; then
    echo "==> Pulling default model + embedding model (best-effort)"
    ollama pull glm-5.2:cloud        || echo "  [--] glm-5.2:cloud pull failed (daemon running? reachable?)"
    ollama pull nomic-embed-text     || echo "  [--] nomic-embed-text pull failed (needed for semantic memory)"
else
    echo "==> Skipping model pull (SKIP_MODEL_PULL=1 or ollama absent)"
fi

# --- 5. Doctor (best-effort) ----------------------------------------------
echo "==> Running --doctor"
"$RUN_PY" main.py --doctor || echo "  [!] --doctor reported failures above; fix them before running the engine."

# --- 6. Install the `breachpilot` command to ~/.local/bin -----------------------
BIN_DIR="$HOME/.local/bin"
if [[ "$ADD_TO_PATH" == "1" ]]; then
    echo "==> Installing \`breachpilot\` command"
    mkdir -p "$BIN_DIR"
    # Write a tiny launcher that always runs from the repo root, so
    # config.yaml / mission.yaml / reports/ resolve regardless of cwd.
    cat > "$BIN_DIR/breachpilot" <<EOF
#!/usr/bin/env bash
# breachpilot — BreachPilot launcher (generated by install.sh)
# Always runs from the repo root so config.yaml/mission.yaml/reports/ resolve.
cd "$REPO_ROOT" || { echo "breachpilot: repo not found at $REPO_ROOT" >&2; exit 1; }
# Use the venv interpreter when it exists, else fall back to system python3.
if [[ -x "$REPO_ROOT/$VENV/bin/python" ]]; then
    PY="$REPO_ROOT/$VENV/bin/python"
else
    PY="python3"
fi
exec "\$PY" "$REPO_ROOT/main.py" "\$@"
EOF
    chmod +x "$BIN_DIR/breachpilot"
    echo "  [OK] breachpilot -> $BIN_DIR/breachpilot"
    # Short command for daily use.
    ln -sf "$BIN_DIR/breachpilot" "$BIN_DIR/bp" 2>/dev/null || cp "$BIN_DIR/breachpilot" "$BIN_DIR/bp"
    echo "  [OK] bp -> $BIN_DIR/bp"
    # Deprecated alias for backwards compatibility
    ln -sf "$BIN_DIR/breachpilot" "$BIN_DIR/natai" 2>/dev/null || cp "$BIN_DIR/breachpilot" "$BIN_DIR/natai"
    echo "  [OK] natai (deprecated alias) -> $BIN_DIR/natai"

    # --- 7. Ensure ~/.local/bin is on PATH (guarded, idempotent) -----------
    case ":$PATH:" in
        *":$BIN_DIR:"*) echo "  [OK] $BIN_DIR already on PATH" ;;
        *)
            # Pick the rc file matching the user's shell.
            RC_FILE=""
            case "${SHELL:-}" in
                */zsh)  RC_FILE="$HOME/.zshrc" ;;
                */bash) RC_FILE="$HOME/.bashrc" ;;
                *)      RC_FILE="$HOME/.profile" ;;
            esac
            if [[ -z "$RC_FILE" ]]; then
                echo "  [!] could not detect shell (\$SHELL empty). Add $BIN_DIR to PATH manually."
            elif grep -q "Added by BreachPilot install.sh" "$RC_FILE" 2>/dev/null; then
                # Block already present from a prior run — don't duplicate it.
                echo "  [OK] $BIN_DIR already wired into $RC_FILE (left as-is)"
            else
                # Guarded block so re-runs never duplicate the PATH entry.
                cat >> "$RC_FILE" <<'EOF'

# >>> Added by BreachPilot install.sh >>>
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH";; esac
# <<< Added by BreachPilot install.sh <<<
EOF
                echo "  [OK] added $BIN_DIR to PATH in $RC_FILE"
                echo "       run \`source $RC_FILE\` (or open a new terminal) before first use"
            fi
            ;;
    esac
else
    echo "==> Skipping \`breachpilot\` command install (ADD_TO_PATH=0)"
fi

echo
echo "Done. Next steps:"
echo "  bp                               # launch BreachPilot from any directory"
echo "  breachpilot                      # interactive menu (after \`source ~/.bashrc\` / new terminal)"
echo "  breachpilot --target 10.0.0.50 --mode attack --goal backdoor"
echo "  (or, inside the venv)  python main.py ..."
echo
echo "Reminder: only run against networks you own or are explicitly authorized to test."
