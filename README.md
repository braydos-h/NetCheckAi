# NetSentry Scout

> **Turn noisy network scans into executive-ready risk insights in minutes.**

NetSentry Scout is a **defensive-first**, **Nmap-only** local network assessment platform that combines:
- a policy-locked MCP server,
- an AI analyst controller,
- and a triage workflow that focuses effort where risk is highest.

If you need a fast way to answer: **“What’s exposed, what’s risky, and what should we fix first?”** — this is built for you.

---

## Why Teams Choose NetSentry Scout

### 🚀 Ship a credible network risk report fast
Run one command and generate:
- a network-level security summary,
- per-host findings,
- raw Nmap evidence files for audit trails.

### 🎯 Prioritize risk, not just open ports
Instead of deep-scanning every host, the platform performs **triage-first analysis** and ranks suspicious hosts using:
- risky services,
- unusually high port exposure,
- old-looking versions,
- unknown services,
- admin-facing surfaces.

### 🛡️ Built-in safety guardrails by design
This project is intentionally constrained for defensive use:
- only approved private RFC1918 ranges,
- strict command allowlist,
- blocked offensive tools/patterns,
- no exploitation workflows.

### 🤖 AI + deterministic controls
Get the speed and context of AI with hard technical boundaries enforced at multiple layers.

---

## What You Get

- **Controller** that orchestrates scan flow, ranking, reporting, and stream output.
- **Restricted MCP tools** that only allow safe Nmap command shapes.
- **Structured reports** for both technical and non-technical stakeholders.
- **Optional vulnerability-intel enrichment** for remediation context.

### Output Artifacts
- `reports/network_summary.md` — high-level posture and prioritized actions.
- `reports/host_<ip>.md` — host-by-host findings and remediation notes.
- `reports/raw_nmap/<ip>_scan.txt` — evidence-grade raw scan output.

---

## Quick Start (2 Minutes)

### 1) Install dependencies

```powershell
python -m pip install -r requirements.txt
```

Install Nmap and ensure `nmap` is on PATH (or set `nmap.path` in `config.yaml`).

### 2) Ensure model availability (Ollama)

```powershell
ollama signin
ollama show kimi-k2.6:cloud
```

### 3) Run your first assessment

```powershell
python main.py --subnet 192.168.1.0/24
```

That’s it. The tool discovers hosts, triages exposure, drills deeper where needed, and writes reports automatically.

---

## Core Workflow (Risk-First)

The platform enforces this sequence:

1. `nmap -sn <subnet>`
2. `nmap -sV --top-ports 100 --open <subnet>`
3. `nmap -sV --top-ports 1000 <ip>` (selected hosts)
4. `nmap -sV -sC -O <ip>` (selected hosts)
5. `nmap --script vuln -sV <ip>` (optional selected hosts)

This keeps scans efficient and focused on likely high-impact issues.

---

## Safety Boundaries (Non-Negotiable)

- Scans only user-provided private IPv4 CIDRs (e.g. `192.168.1.0/24`).
- Rejects public, loopback, multicast, unspecified, out-of-config, and overly broad ranges.
- Uses Nmap only (no exploitation, brute force, privilege abuse, payload delivery, or host modification).
- `run_limited_terminal` blocks metacharacters and unsafe/offensive tools.
- Banner output is treated as untrusted input.
- Search enrichment blocks private host details and offensive exploit-query patterns.

If you are building a security process that must remain clearly defensive and auditable, these guardrails are a feature—not a limitation.

---

## Common Usage

Default run:

```powershell
python main.py --subnet 192.168.1.0/24
```

IDE-friendly launcher:

```powershell
python app.py --subnet 192.168.1.0/24
```

Multiple approved ranges:

```powershell
python main.py --subnet 192.168.1.0/24 --subnet 10.0.0.0/24
```

HTTP MCP transport:

```powershell
python main.py --subnet 192.168.1.0/24 --mcp-transport http --http-port 8000
```

Model override:

```powershell
python main.py --subnet 192.168.1.0/24 --model kimi-k2.6:cloud
```

Disable web search:

```powershell
python main.py --subnet 192.168.1.0/24 --no-search
```

Plain terminal output:

```powershell
python main.py --subnet 192.168.1.0/24 --plain
```

---

## Repository Structure

- `main.py` — AI controller, MCP client, scan policy, reporting loop.
- `mcp_server.py` — FastMCP server exposing restricted Nmap tools.
- `tools/nmap_tools.py` — Nmap validation, allowlist enforcement, triage ranking, raw evidence writing.
- `tools/search_tools.py` — restricted vulnerability-intelligence search.
- `config.yaml` — defaults for model, transport, Nmap, reporting, and safety caps.

---

## Validation & Guardrail Examples

Rejected before scan execution:

```powershell
python main.py --subnet 8.8.8.0/24
python main.py --subnet 127.0.0.0/8
```

Blocked terminal input examples:

```text
curl http://example.com
nmap -A 192.168.1.10
nmap -sV 192.168.1.10; whoami
```

Allowed terminal Nmap examples:

```text
nmap -sn 192.168.1.0/24
nmap -sV --top-ports 100 --open 192.168.1.0/24
nmap -sV --top-ports 1000 192.168.1.10
nmap -sV -sC -O 192.168.1.10
nmap --script vuln -sV 192.168.1.10
```

---

## Ideal For

- Internal security baselining
- MSP/MSSP recurring hygiene checks
- IT teams needing fix-first prioritization
- Leadership updates backed by technical evidence

---

## Responsible Use

Use only on networks and devices you own or are explicitly authorized to assess. This project is designed for defensive analysis and remediation planning.
