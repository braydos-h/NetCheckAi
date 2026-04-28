# Defensive Local Network Assessment Tool

Python controller plus MCP server for defensive Nmap-only assessment of explicitly approved local RFC1918 networks.
It now uses a triage-first workflow so the AI does not waste time deep-scanning every live IP.

## Safety Boundaries

- Scans only user-provided private IPv4 CIDRs such as `192.168.1.0/24`.
- Rejects public, loopback, multicast, unspecified, out-of-config, and overly broad ranges.
- Uses Nmap only. No exploitation, brute force, login bypass, payload upload, reverse shells, or system modification.
- `run_limited_terminal` accepts only the approved Nmap command shapes and blocks shell metacharacters plus unsafe tools like `curl`, `wget`, `nc`, `ssh`, `hydra`, `metasploit`, `sudo`, `powershell`, `bash`, and similar commands.
- `search_vulnerability_intel` can search public vulnerability/advisory information, but blocks private IPs, local host details, exploit/payload terms, and offensive query patterns.
- Nmap banner text is treated as untrusted input by the controller prompt.

## Files

- `main.py`: Ollama controller, MCP client, scan-order policy, streaming loop, report generation.
- `mcp_server.py`: FastMCP server exposing restricted Nmap tools.
- `tools/nmap_tools.py`: Safe Nmap wrappers, validation, command allowlist, triage ranking, raw output writing, XML parsing, scan profiles.
- `tools/search_tools.py`: Restricted SerpAPI DuckDuckGo search for defensive vulnerability intelligence.
- `tools/report_generator.py`: Structured report generation (Markdown, HTML, CSV) with severity, evidence, remediation, and comparison logic.
- `config.yaml`: Defaults for model, MCP, Nmap, reports, approval, history, and safety caps.
- `reports/<timestamp>/`: Timestamped assessment runs.
- `reports/latest`: Symlink or junction to the most recent run.

## Install

```powershell
python -m pip install -r requirements.txt
```

Install Nmap if needed and make sure `nmap` is on PATH, or set `nmap.path` in `config.yaml`.

Ollama must be installed and signed in for cloud models:

```powershell
ollama signin
ollama show kimi-k2.6:cloud
```

Optional vulnerability-intelligence search uses SerpAPI DuckDuckGo. If your account requires a key:

```powershell
$env:SERPAPI_API_KEY = "your_key_here"
```

## Usage

Default stdio MCP transport:

```powershell
python main.py --subnet 192.168.1.0/24
```

Or run the IDE-friendly launcher:

```powershell
python app.py --subnet 192.168.1.0/24
```

If you omit `--subnet` in an interactive terminal, the app prompts for approved subnets.

Multiple approved subnets:

```powershell
python main.py --subnet 192.168.1.0/24 --subnet 10.0.0.0/24
```

Local HTTP MCP transport on `127.0.0.1`:

```powershell
python main.py --subnet 192.168.1.0/24 --mcp-transport http --http-port 8000
```

Override the model:

```powershell
python main.py --subnet 192.168.1.0/24 --model kimi-k2.6:cloud
```

### Scan Profiles

Choose a predefined safe scan profile with `--profile`:

| Profile | Description |
|---------|-------------|
| `quick` | Ping sweep + traceroute only; no port scanning. |
| `standard` | Current workflow: ping sweep, triage with top ports, selective deeper scans. |
| `deep` | Selected safe service scripts: `-sV -sC -O` on hosts. |
| `web` | HTTP title, headers, TLS cert/cipher checks via safe NSE scripts. |
| `windows` | SMB security mode and protocol checks via safe NSE scripts. |
| `udp-light` | Limited top UDP ports with strict timeout. |

```powershell
python main.py --subnet 192.168.1.0/24 --profile web
```

### Approval Modes

Control how scan actions are approved:

- `--approval-mode auto`: AI proposes each next scan; you approve (default).
- `--approval-mode review`: You pick scan actions from a menu.
- `--approval-mode manual`: You must explicitly approve every action.

```powershell
python main.py --subnet 192.168.1.0/24 --approval-mode review
```

### Output Formats

Generate richer reports in multiple formats:

```powershell
# Markdown only (default)
python main.py --subnet 192.168.1.0/24 --output markdown

# HTML report
python main.py --subnet 192.168.1.0/24 --output html

# CSV findings
python main.py --subnet 192.168.1.0/24 --output csv

# All formats
python main.py --subnet 192.168.1.0/24 --output all
```

Reports are written under `reports/<timestamp>/` and include:
- `network_summary.md` — Improved Markdown with severity, evidence, affected host/port, confidence, remediation, and "next scan recommended".
- `network_summary.html` — Styled HTML report with comparison cards.
- `findings.csv` — Structured findings for spreadsheets or SIEM ingestion.
- `host_<ip>.md` — Legacy per-host Markdown reports.
- `raw_nmap/` — Raw Nmap text evidence.
- `xml_nmap/` — Parsed XML Nmap output for structured processing.

### Run History & Comparisons

Each run is stored in a timestamped folder. The tool automatically compares findings with the previous run and classifies them as **new**, **open**, or **resolved** when both runs exist.

```powershell
# Previous run comparison happens automatically when multiple runs exist
reports/
  latest -> 20260428_123000/ (junction)
  20260428_123000/
    findings.csv
    network_summary.md
    network_summary.html
  20260427_090000/
    findings.csv
    ...
```

### Faster AI Workflow

The controller now gives the AI compact structured host summaries instead of huge raw Nmap text. Search results are cached per service/version, and the controller can stop early when enough evidence is collected.

### Running Tests

```powershell
python -m pytest tests/ -v
```

## Config Sections

Key sections in `config.yaml`:

```yaml
nmap:
  default_profile: "standard"   # quick | standard | deep | web | windows | udp-light

approval:
  default_mode: "auto"          # auto | review | manual

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
