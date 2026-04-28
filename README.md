# NetCheckAI

**Turn Nmap into a guided, repeatable defensive assessment workflow — without losing control.**

This project combines a Python controller, an MCP tool server, and tightly restricted scan/search tooling to help defenders assess **approved private networks** faster and more consistently.

Instead of dumping raw output and hoping for the best, it uses a **triage-first pipeline** with structured findings, remediation guidance, and run-to-run comparison.

---

## Why this is useful

Most internal scans fail for one of two reasons:
1. They’re too shallow and miss real risk.
2. They’re too noisy and waste hours chasing low-value output.

This tool is built to avoid both.

### What you get

- **Triage-first scanning** so deep scans focus on what matters.
- **Defensive-only guardrails** across command execution and intel search.
- **Repeatable reporting** in Markdown, HTML, and CSV.
- **Run history + diffing** so you can track what’s new, still open, or resolved.
- **Human-in-the-loop approvals** so the operator remains in control.

---

## Core safety model (designed-in, not bolted-on)

This project is intentionally constrained for defensive local-network assessment.

- Accepts only **explicitly approved private IPv4 CIDRs** (RFC1918 ranges).
- Rejects public, loopback, multicast, unspecified, and overly broad scopes.
- Uses **Nmap only** for scanning.
- Blocks unsafe command shapes and shell metacharacters in terminal execution paths.
- Blocks offensive or environment-leaking patterns in vulnerability-intel searches.
- Treats Nmap banners and host data as untrusted input to the AI controller.

If you need unrestricted offensive tooling, this is not that project. If you need a safer, auditable internal assessment workflow, this is exactly that.

---

## Architecture at a glance

- `main.py` — AI controller, MCP client orchestration, policy workflow, output generation.
- `mcp_server.py` — MCP server exposing restricted tool surfaces.
- `tools/nmap_tools.py` — scan validation, allowlists, profiles, parsing, and evidence capture.
- `tools/search_tools.py` — defensive vulnerability-intel search wrapper.
- `tools/report_generator.py` — Markdown/HTML/CSV report generation + comparison logic.
- `config.yaml` — defaults for profiles, approvals, reports, search cache, and history behavior.

---

## Quick start

### 1) Install dependencies

```bash
python -m pip install -r requirements.txt
```

Install Nmap and ensure `nmap` is on `PATH` (or set `nmap.path` in `config.yaml`).

### 2) Set up your model runtime

Ollama is expected for model execution:

```bash
ollama signin
ollama show kimi-k2.6:cloud
```

### 3) Run a baseline scan

```bash
python main.py --subnet 192.168.1.0/24
```

Alternative launcher:

```bash
python app.py --subnet 192.168.1.0/24
```

---

## Profiles built for real workflows

Use `--profile` to match depth to your objective:

| Profile | Purpose |
|---|---|
| `quick` | Fast reachability and path checks (no port-depth). |
| `standard` | Best default: host discovery + triage + selective deep follow-up. |
| `deep` | Broader safe service probing for high-confidence service understanding. |
| `web` | HTTP/TLS-focused checks via safe NSE scripts. |
| `windows` | SMB-focused security checks for Windows-heavy environments. |
| `udp-light` | Limited UDP visibility under strict timing caps. |

Example:

```bash
python main.py --subnet 10.0.0.0/24 --profile standard
```

---

## Keep operators in control with approval modes

- `auto` (default): AI proposes next scans, you approve.
- `review`: you choose actions from a menu.
- `manual`: explicit approval required for every action.

```bash
python main.py --subnet 192.168.1.0/24 --approval-mode review
```

---

## Reports that teams can actually use

Generate output with `--output`:

```bash
# markdown (default)
python main.py --subnet 192.168.1.0/24 --output markdown

# html
python main.py --subnet 192.168.1.0/24 --output html

# csv
python main.py --subnet 192.168.1.0/24 --output csv

# all formats
python main.py --subnet 192.168.1.0/24 --output all
```

Per run, the tool stores artifacts in `reports/<timestamp>/`:

- `network_summary.md` — prioritized findings, evidence, remediation, and confidence.
- `network_summary.html` — stakeholder-ready visual summary.
- `findings.csv` — structured records for spreadsheets, tickets, or SIEM workflows.
- `raw_nmap/` + `xml_nmap/` — preserved evidence for auditability and re-processing.

---

## Trend your security posture over time

The system stores timestamped runs and compares with prior results to classify findings as:

- **new**
- **open**
- **resolved**

This makes it practical to answer: *“Are we getting better?”* — not just *“What is open right now?”*

---

## Optional vulnerability-intel enrichment

If configured, the tool can pull defensive public intel to enrich findings.

If your SerpAPI plan requires a key:

```bash
export SERPAPI_API_KEY="your_key_here"
```

---

## Test

```bash
python -m pytest tests/ -v
```

---

## Configuration highlights

`config.yaml` includes settings for scan behavior, approvals, output formats, cache, and run history.

```yaml
nmap:
  default_profile: "standard"

approval:
  default_mode: "auto"

reports:
  default_formats:
    - "markdown"
  base_dir: "reports"

search:
  cache_ttl_seconds: 3600
  cache_max_entries: 100

history:
  retention_runs: 10
  compare_with_previous: true
```

---

## Who this is for

- Security engineers who want faster internal visibility.
- Blue teams that need evidence-backed remediation output.
- Consultants who need repeatable and auditable scan/report cycles.
- DevSecOps teams who want safe automation without giving up governance.

---

## Bottom line

If you want a safer, AI-assisted way to run **defensive internal network assessments** that produce decision-ready outputs, this project gives you a strong operating model out of the box.
