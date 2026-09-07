#!/usr/bin/env bash
# Linux/macOS bootstrap for the BreachPilot engine.
#
# Idempotent: safe to re-run. Creates the venv, installs Python deps, checks
# for the external tools the engine uses (nmap, ollama, optional Kali
# tooling), prints install hints for anything missing, and finally runs
# `python main.py --doctor`.
#
# This does NOT install or run anything against a target. It only prepares the
# operator's host. Run it from the repository root.
set -euo pipefail

PYTHON="${PYTHON:-python3}"
VENV="${VENV:-.venv}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "  [!] '$PYTHON' not found. Install Python 3.11+ (apt install python3 / brew install python) or set PYTHON=..."
    exit 1
fi

echo "==> Creating venv ($VENV) with $($PYTHON --version)"
"$PYTHON" -m venv "$VENV"

# Active venv for the rest of the script.
# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "==> Upgrading pip + installing requirements"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "==> Checking external tools"
check() {
    local name="$1"; local hint="$2"
    if command -v "$name" >/dev/null 2>&1; then
        echo "  [OK] $name ($(command -v "$name"))"
    else
        echo "  [--] $name missing  -> $hint"
    fi
}

check nmap      "sudo apt install -y nmap  (or: brew install nmap)"
check tmux      "sudo apt install -y tmux  (or: brew install tmux)"
check searchsploit "sudo apt install -y exploitdb   (Kali-only; optional unless using the exploit engine)"
check msfconsole "sudo apt install -y metasploit-framework  (optional; Kali-only)"
check hydra     "sudo apt install -y hydra  (optional)"
check impacket-secretsdump "pip install impacket  (or: apt install impacket-scripts)"
check bun       "curl -fsSL https://bun.sh/install | bash  (only needed for the ChatGPT provider; see docs/providers.md)"

# Provider-aware: the Ollama *daemon* is only needed when models.provider is
# ollama (the default). A non-Ollama provider (opencode_go / chatgpt) runs
# with zero Ollama components — nothing here then touches Ollama.
OLLAMA_PROVIDER="ollama"  # matches python's tools.config.get_ai_provider default
if [[ -f "config.yaml" ]] && command -v "$PYTHON" >/dev/null 2>&1; then
    OLLAMA_PROVIDER="$("$PYTHON" - <<'PYEOF'
try:
    import yaml
    cfg = yaml.safe_load(open("config.yaml")) or {}
    print(str((cfg.get("models") or {}).get("provider") or "ollama"))
except Exception:
    print("ollama")
PYEOF
)"
fi

if [[ "$OLLAMA_PROVIDER" == "ollama" ]]; then
    check ollama    "curl -fsSL https://ollama.com/install.sh | sh  (or: brew install ollama)"

    echo "==> Pulling default model (best-effort)"
    ollama pull glm-5.2:cloud 2>/dev/null || echo "  [--] ollama pull skipped (is the ollama daemon running?)"
else
    echo "==> Skipping Ollama daemon checks/models (models.provider: $OLLAMA_PROVIDER — no Ollama needed)"
fi

# Best-effort: prepare the vendored openai-oauth checkout if bun is available.
# ChatGPT provider is opt-in (models.provider: chatgpt); never aborts setup.
if [[ -d "$PWD/oauth" ]] && command -v bun >/dev/null 2>&1; then
    echo "==> Preparing vendored openai-oauth (ChatGPT provider) via bun install"
    (cd "$PWD/oauth" && bun install) || echo "  [!] bun install failed in oauth/ — see docs/providers.md"
fi

echo "==> Running --doctor"
python main.py --doctor || echo "  [!] --doctor reported failures above; fix them before running the engine."

echo
echo "Done. Activate the venv with:  source $VENV/bin/activate"
echo "Then run:                      python main.py           (interactive menu)"
echo "                               python main.py --doctor  (re-check)"
