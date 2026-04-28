# NetCheckAI

> AI-assisted defensive network assessment for approved private networks.

[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Nmap](https://img.shields.io/badge/Nmap-required-00457C)](https://nmap.org/)
[![MCP](https://img.shields.io/badge/MCP-tool%20server-111827)](https://modelcontextprotocol.io/)
[![Ollama](https://img.shields.io/badge/Ollama-supported-000000)](https://ollama.com/)
[![Tests](https://img.shields.io/badge/tests-pytest-0A7BBB)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)

NetCheckAI turns Nmap into a governed, repeatable, AI-assisted assessment workflow for internal networks. It combines a Python orchestration layer, a restricted MCP tool server, safe Nmap wrappers, vulnerability-intelligence lookup, per-host AI sub-agents, and deterministic evidence-backed reports.

It is built for defenders who need speed without giving up control: every scan is constrained to approved RFC1918 IPv4 ranges, every host-level action is gated by discovery evidence, and every report preserves the raw artifacts needed for audit and follow-up.

---

## Product Overview

NetCheckAI helps security engineers, blue teams, consultants, and DevSecOps teams assess approved local networks with a workflow that is more selective than a raw scanner and more auditable than a free-form AI agent.

The project exists to solve a common operational problem: internal scans either produce too little context or too much noise. NetCheckAI starts with discovery, performs triage, ranks hosts by observable risk, then sends deeper scans only where the evidence justifies them.

| Dimension | What NetCheckAI Does |
|---|---|
| Primary use case | Defensive local-network discovery, triage, service review, and remediation reporting |
| Target users | Security engineers, consultants, blue teams, lab operators, DevSecOps teams |
| Control model | Runtime-approved private CIDRs, strict command allowlists, tool-call budgets, optional manual approval |
| AI role | Plans assessment flow, selects suspicious hosts, enriches findings, and summarizes remediation |
| Evidence model | Nmap text output, Nmap XML, per-host report files, structured findings, JSONL activity logs |
| Output | Markdown network summary, per-host Markdown reports, optional HTML and CSV reports |

### Key Differentiators

| Differentiator | Why It Matters |
|---|---|
| Triage-first scanning | Avoids blindly deep-scanning every live host and focuses time on exposed services that matter |
| Safety enforced in code | Scope and command restrictions live in Python validation, not just in prompts |
| MCP-native tool boundary | The model can only call exposed defensive tools through the MCP server |
| Parallel host sub-agents | Suspicious hosts can be assessed concurrently with per-host tool budgets |
| Deterministic reporting | Reports are generated from parsed XML, policy state, and structured sub-agent output |
| Audit-ready artifacts | Raw Nmap output, XML, activity logs, and generated reports are stored per run |

---

## Screenshots And Demo

This repository contains a CLI experience and generated report artifacts, not a browser frontend. Suggested screenshots for the project page:

| Screenshot | Suggested File | Description |
|---|---|---|
| CLI run header | `docs/images/cli-run.png` | Model, approved scope, transport, profile, and approval mode |
| Activity log | `docs/images/activity-log.png` | Ping sweep, triage, sub-agent activity, blocked actions, and report generation |
| Network summary | `docs/images/network-summary.png` | Executive summary, scope coverage, findings by priority, and host inventory |
| Host report | `docs/images/host-report.png` | Evidence model, inferred role, open ports, and recommended follow-up |
| CSV export | `docs/images/findings-csv.png` | Structured findings ready for ticketing, spreadsheets, or SIEM ingestion |

```markdown
![CLI assessment run](docs/images/cli-run.png)
![Network summary report](docs/images/network-summary.png)
![Per-host evidence report](docs/images/host-report.png)
```

---

## Feature Breakdown

### Core Features

| Feature | Details |
|---|---|
| Approved subnet assessment | Accepts explicit private IPv4 CIDRs only |
| Ping sweep discovery | Starts with `nmap -sn` before any port-level scan |
| Triage scan | Scans only hosts discovered alive, using profile-specific subnet arguments |
| Host selection | Scores open services and ranks hosts by exposure indicators |
| Deeper host scans | Supports basic, service/script/OS, and vulnerability-script scans in enforced order |
| Report generation | Produces network summaries, host reports, CSV, and HTML |
| Run artifacts | Stores raw Nmap output, XML Nmap output, MCP server logs, and JSONL activity logs |
| Interactive menu | Uses `questionary` for guided local runs and saved preferences |

### Developer Features

| Feature | Details |
|---|---|
| MCP tool server | `mcp_server.py` exposes restricted scan and lookup tools over stdio or local HTTP |
| Typed Python data models | Dataclasses model parsed hosts, ports, findings, CVEs, and sub-agent results |
| Test suite | Pytest coverage for scope validation, allowlists, report generation, parsing, and sub-agents |
| Config-first behavior | `config.yaml` controls profiles, limits, reporting, search, history, and transport |
| Deterministic parsers | Nmap XML is parsed into structured host and port records |
| CLI flags | Supports transport, model, reports directory, approval mode, output formats, profiles, and sub-agent controls |

### Performance Features

| Feature | Details |
|---|---|
| Discovery batching | Independent discovery and triage tool calls can be executed concurrently |
| Parallel sub-agents | Suspicious hosts can be processed concurrently with configurable limits |
| Context compaction | Older tool results are compacted for sub-agent model loops |
| XML registry | Parsed Nmap XML is cached in-memory during a run to avoid repeat parsing |
| Search caching | Vulnerability intelligence and NVD lookups use lightweight TTL/LRU-style caches |
| Output limits | Nmap output and report inputs are capped to keep model context bounded |

### Security Features

| Feature | Details |
|---|---|
| RFC1918 scope enforcement | Public, loopback, multicast, unspecified, and oversized ranges are rejected |
| Runtime-approved scope | Host scans must stay inside explicitly approved subnets |
| Discovery prerequisite | Host-level scans require prior ping sweep evidence |
| Triage prerequisite | Host-level scans can require triage before deeper scanning |
| Command allowlist | `run_limited_terminal` accepts only known safe Nmap command shapes |
| Active-check gate | Optional generated checks require discovered-live + triaged host evidence, host approval, and per-command approval |
| Shell metacharacter rejection | Command and search inputs reject shell metacharacters |
| Offensive term blocking | Search blocks terms such as exploit payloads, brute force tooling, and Metasploit references |
| Private data protection | Private IP addresses and local hostnames are blocked from public web search |
| Local-only HTTP MCP | HTTP transport may bind only to `127.0.0.1` or `localhost` |
| Secrets handling | API keys are read from environment variables and redacted in search URLs |

### AI Features

| Feature | Details |
|---|---|
| Ollama controller | Main assessment loop uses an Ollama chat model configured in `config.yaml` |
| MCP tool calling | Model actions are constrained to MCP-exposed defensive tools |
| Per-host sub-agents | Focused workers assess suspicious hosts after triage completes |
| Structured sub-agent findings | Sub-agents return JSON-style findings with risk, evidence, remediation, researched services, and CVEs |
| Defensive system prompts | Prompts prohibit unauthorized targets, brute force, payloads, persistence, and unapproved active behavior |
| User-approved active checks | Optional mode lets sub-agents propose custom Python or reviewed commands for approved hosts only |
| CVE enrichment | Known product/version strings can be checked against NVD CVE API 2.0 |

### Enterprise-Relevant Features

| Capability | Current State |
|---|---|
| Audit trail | JSONL activity log per run |
| Evidence retention | Raw and XML Nmap artifacts stored under timestamped run directories |
| Report exports | Markdown, HTML, and CSV |
| Configurable limits | Max hosts, tool calls, searches, subnet size, report input size, timeouts, and concurrency |
| Approval modes | `auto`, `review`, and `manual` workflows |
| Trend comparison | A comparison helper exists in `tools/report_generator.py`; full historical comparison is configured but only partially wired into the current main reporting path |
| RBAC / multi-user | Not implemented in this repository |
| Central database | Not implemented in this repository |

---

## Architecture

NetCheckAI is a local-first Python application with an MCP server boundary around scanning and vulnerability-intelligence operations.

```mermaid
flowchart LR
    Operator[Operator / CLI] --> Controller[main.py<br/>Assessment Controller]
    Controller --> Ollama[Ollama Model<br/>kimi-k2.6:cloud by default]
    Controller --> MCPClient[MCP Client Session]
    MCPClient --> MCPServer[mcp_server.py<br/>Restricted Tool Server]
    MCPServer --> Nmap[SafeNmapRunner<br/>Nmap Execution]
    MCPServer --> Search[VulnerabilitySearch<br/>SerpAPI DuckDuckGo]
    MCPServer --> NVD[NVDClient<br/>CVE API 2.0]
    Controller --> SubAgents[Parallel Host Sub-Agents]
    SubAgents --> Nmap
    SubAgents --> Search
    SubAgents --> NVD
    Nmap --> Artifacts[reports/&lt;run_id&gt;<br/>raw_nmap + xml_nmap]
    Controller --> Reports[Markdown / HTML / CSV<br/>Host Reports + Network Summary]
    Reports --> Artifacts
```

### Frontend Stack

There is no web frontend in the current repository. The user interface is a terminal application:

| Component | Technology |
|---|---|
| CLI entrypoint | `main.py` |
| Friendly launcher | `app.py` |
| Interactive prompts | `questionary` |
| Activity display | Plain terminal output with JSONL audit trail |
| Generated report UI | Static HTML report produced by `tools/report_generator.py` |

### Backend Stack

| Layer | Implementation |
|---|---|
| Language | Python |
| Controller | `main.py` |
| Tool server | `mcp_server.py` using MCP `FastMCP` |
| Scanner | Nmap via `subprocess.run` / `asyncio.create_subprocess_exec` with `shell=False` |
| Config | YAML via `PyYAML` |
| LLM runtime | Ollama Python client |
| HTTP transport | `uvicorn` + `starlette` for local MCP HTTP mode |
| Tests | `pytest` and `pytest-asyncio` |

### MCP Tool Surface

| Tool | Purpose | Guardrails |
|---|---|---|
| `run_nmap_ping_sweep(subnet)` | Discovery with `nmap -sn` | Approved private subnet only |
| `run_nmap_triage_scan(subnet)` | Top-port triage for discovered live hosts | Requires ping sweep |
| `run_nmap_basic_scan(ip)` | Service/version detection on one host | Requires discovered live host |
| `run_nmap_service_scan(ip)` | `-sV -sC -O` service/script/OS scan | Requires basic scan |
| `run_nmap_vuln_scan(ip)` | Nmap `vuln` NSE scripts | Requires service scan |
| `run_limited_terminal(command)` | Compatibility wrapper for allowlisted Nmap commands | Rejects all non-allowlisted commands |
| `search_vulnerability_intel(query)` | Defensive public vulnerability/advisory search | Sanitized, no private IPs, no offensive terms |
| `search_cve_intel(query)` | NVD CVE lookup for known product/version strings | Sanitized query, rate-limited and cached |

Active custom checks are not exposed through the MCP server. They are local host sub-agent tools only, and are available only when `--active-checks` or `active_checks.enabled` is set.

### Auth And Identity

NetCheckAI does not implement user accounts, OAuth, SSO, RBAC, or API authentication. Trust is currently local and operator-driven:

| Area | Current Behavior |
|---|---|
| Operator identity | Local terminal user |
| Scan authorization | Explicit `--subnet` values or interactive subnet selection |
| MCP HTTP exposure | Localhost-only binding |
| Approval | CLI approval modes and policy checks |

### Database

There is no database engine, ORM, migration system, or schema file in the current codebase. Runtime state is kept in memory and persisted as files under `reports/<run_id>/`.

| Data | Storage |
|---|---|
| Activity events | `reports/<run_id>/activity.jsonl` |
| Raw scan output | `reports/<run_id>/raw_nmap/*.txt` |
| Structured scan output | `reports/<run_id>/xml_nmap/*.xml` |
| Network summary | `reports/<run_id>/network_summary.md` |
| Host reports | `reports/<run_id>/host_<ip>.md` |
| CSV findings | `reports/<run_id>/findings.csv` |
| HTML summary | `reports/<run_id>/network_summary.html` |
| Interactive preferences | `~/.config/ai-powered-nmap/history.yaml` |

### Deployment Model

NetCheckAI is designed to run locally on an operator workstation or assessment VM with Nmap installed. It can use either stdio MCP transport in a single process tree or a localhost HTTP MCP server for workflows that benefit from parallelism.

```mermaid
sequenceDiagram
    participant U as Operator
    participant C as main.py
    participant M as MCP Server
    participant N as Nmap
    participant A as Host Sub-Agents
    participant R as Reports

    U->>C: python main.py --subnet 192.168.1.0/24
    C->>M: Start MCP session with approved scope
    C->>M: run_nmap_ping_sweep
    M->>N: nmap -sn approved subnet
    N-->>M: Live hosts + XML
    C->>M: run_nmap_triage_scan
    M->>N: Top-port scan only live hosts
    N-->>M: Open services + XML
    C->>A: Spawn per-host assessors
    A->>N: Basic/service/vuln scans as allowed
    A-->>C: Structured findings
    C->>R: Generate Markdown, HTML, CSV, host reports
```

---

## Folder Structure

```text
NetCheckAi/
+-- app.py
+-- config.yaml
+-- LICENSE
+-- main.py
+-- mcp_server.py
+-- README.md
+-- requirements.txt
+-- reports/
|   +-- 20260428_085908/
|   |   +-- activity.jsonl
|   |   +-- host_192.168.1.1.md
|   |   +-- host_192.168.1.130.md
|   |   +-- host_192.168.1.208.md
|   |   +-- mcp_server.log
|   |   +-- network_summary.md
|   |   +-- raw_nmap/
|   |   +-- xml_nmap/
|   +-- 20260428_101321/
|       +-- activity.jsonl
|       +-- mcp_server.log
|       +-- raw_nmap/
|       +-- xml_nmap/
+-- tests/
|   +-- __init__.py
|   +-- test_command_allowlist.py
|   +-- test_cve_lookup.py
|   +-- test_nmap_runner.py
|   +-- test_report_generation.py
|   +-- test_search_sanitization.py
|   +-- test_sub_agents.py
|   +-- test_subnet_validation.py
|   +-- test_triage_parsing.py
+-- tools/
    +-- __init__.py
    +-- activity_log.py
    +-- cve_lookup.py
    +-- interactive_ui.py
    +-- nmap_tools.py
    +-- report_generator.py
    +-- search_tools.py
    +-- sub_agents.py
```

Generated Python cache directories (`__pycache__/`) and `.pytest_cache/` may exist locally and are not required for operation.

---

## Installation

### Prerequisites

| Requirement | Notes |
|---|---|
| Python | Python 3.12+ is recommended based on local cache and dependency usage |
| Nmap | Must be installed and available on `PATH`, or configured via `nmap.path` |
| Ollama | Required for AI controller and sub-agent model calls |
| Network authorization | Only scan networks you own or are explicitly authorized to assess |
| Optional SerpAPI key | Enables configured public vulnerability-intelligence search if required by your plan |
| Optional NVD API key | Improves NVD API rate limits |

### 1. Clone And Enter The Repository

```bash
git clone <your-repo-url> NetCheckAi
cd NetCheckAi
```

### 2. Create A Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Python Dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Install And Verify Nmap

```bash
nmap --version
```

If Nmap is not on `PATH`, set its executable path in `config.yaml`:

```yaml
nmap:
  path: "C:\\Program Files (x86)\\Nmap\\nmap.exe"
```

### 5. Configure Ollama

The default model in `config.yaml` is:

```yaml
ollama:
  model: "kimi-k2.6:cloud"
```

Verify your Ollama runtime can access the configured model:

```bash
ollama show kimi-k2.6:cloud
```

You can override the model at runtime:

```bash
python main.py --subnet 192.168.1.0/24 --model <ollama-model-name>
```

### 6. Configure Optional Intelligence Keys

```bash
export SERPAPI_API_KEY="your-serpapi-key"
export NVD_API_KEY="your-nvd-api-key"
```

On Windows PowerShell:

```powershell
$env:SERPAPI_API_KEY="your-serpapi-key"
$env:NVD_API_KEY="your-nvd-api-key"
```

### 7. Run A Local Assessment

```bash
python main.py --subnet 192.168.1.0/24
```

Alternative launcher:

```bash
python app.py --subnet 192.168.1.0/24
```

If you run `python main.py` with no arguments in an interactive terminal, NetCheckAI opens the guided menu.

---

## Configuration

The main configuration file is `config.yaml`.

### Scan Profiles

| Profile | Purpose | Nmap Behavior |
|---|---|---|
| `quick` | Fast discovery and path visibility | Ping sweep plus traceroute-style subnet profile; no host port depth |
| `standard` | Default defensive workflow | Ping sweep, top-100 triage, selective top-1000 service detection |
| `deep` | Broader selected service review | More complete service scripts and OS detection for selected hosts |
| `web` | HTTP/TLS-focused review | HTTP title, headers, TLS certificate and cipher checks |
| `windows` | SMB-focused review | SMB security mode and protocol checks |
| `udp-light` | Limited UDP visibility | Top UDP ports with strict timeout |

Example:

```bash
python main.py --subnet 10.0.0.0/24 --profile web
```

### Approval Modes

| Mode | Behavior |
|---|---|
| `auto` | Model proposes actions; policy enforces whether they can run |
| `review` | Actions are shown as pending in the CLI |
| `manual` | Operator must approve each scan action |

```bash
python main.py --subnet 192.168.1.0/24 --approval-mode manual
```

### Output Formats

| Format | File |
|---|---|
| `markdown` | `network_summary.md` and per-host Markdown reports |
| `html` | `network_summary.html` |
| `csv` | `findings.csv` |
| `all` | Markdown, HTML, and CSV |

```bash
python main.py --subnet 192.168.1.0/24 --output all
```

---

## Environment Variables

| Variable | Used By | Required | Description |
|---|---|---:|---|
| `APPROVED_SUBNETS` | `mcp_server.py` | MCP server direct use only | Comma-separated approved private CIDRs when launching the MCP server manually |
| `REPORTS_DIR` | `mcp_server.py` | No | Overrides where MCP server scan artifacts are written |
| `DISABLE_VULN_SEARCH` | `main.py`, `mcp_server.py` | No | Set to `1` to disable public vulnerability-intelligence search |
| `SERPAPI_API_KEY` | `tools/search_tools.py` | No | API key for the configured SerpAPI DuckDuckGo endpoint |
| `NVD_API_KEY` | `tools/cve_lookup.py` | No | API key for NVD CVE API 2.0 |

The configured environment variable names for SerpAPI and NVD can be changed in `config.yaml`:

```yaml
search:
  api_key_env: "SERPAPI_API_KEY"

cve_lookup:
  api_key_env: "NVD_API_KEY"
```

---

## CLI Reference

```bash
python main.py [options]
```

| Option | Description |
|---|---|
| `--subnet <cidr>` | Approved RFC1918 subnet. Can be passed multiple times |
| `--mcp-transport stdio\|http` | MCP transport mode |
| `--model <name>` | Ollama model override |
| `--reports-dir <path>` | Base directory for generated reports |
| `--max-hosts <n>` | Override max host-level assessment count |
| `--config <path>` | YAML config path |
| `--http-port <port>` | Local HTTP MCP port |
| `--plain` | Disable any remaining fancy formatting |
| `--no-search` | Disable public vulnerability-intelligence search |
| `--profile <name>` | Scan profile: `quick`, `standard`, `deep`, `web`, `windows`, `udp-light` |
| `--approval-mode <mode>` | `auto`, `review`, or `manual` |
| `--output <format>` | `markdown`, `html`, `csv`, or `all` |
| `--no-sub-agents` | Disable parallel per-host sub-agents |
| `--sub-agent-concurrency <n>` | Max concurrent host sub-agent scans |
| `--max-sub-agent-rounds <n>` | Max model/tool rounds per sub-agent |
| `--active-checks` | Enable user-approved active custom checks for scan-discovered, triaged hosts |

---

## API Documentation

NetCheckAI does not expose a conventional REST API in the current repository. Its programmatic interface is the MCP tool server in `mcp_server.py`.

### Start The MCP Server Directly

Stdio transport:

```bash
python mcp_server.py \
  --transport stdio \
  --approved-subnets 192.168.1.0/24 \
  --reports-dir reports/manual
```

Local HTTP transport:

```bash
python mcp_server.py \
  --transport http \
  --host 127.0.0.1 \
  --port 8000 \
  --approved-subnets 192.168.1.0/24 \
  --reports-dir reports/manual
```

The HTTP transport intentionally rejects non-localhost binds.

### MCP Tool Examples

#### `run_nmap_ping_sweep`

Request:

```json
{
  "subnet": "192.168.1.0/24"
}
```

Response shape:

```text
COMMAND: nmap -sn 192.168.1.0/24
TARGET: 192.168.1.0/24
RAW_REPORT: none
OUTPUT:
EXIT_CODE: 0
STDOUT:
...

LIVE_HOSTS:
2 live host(s) discovered in 192.168.1.0/24:
- 192.168.1.1
- 192.168.1.10
```

#### `run_nmap_triage_scan`

Request:

```json
{
  "subnet": "192.168.1.0/24"
}
```

Response includes triage hints and a compact summary when XML parsing succeeds:

```text
TRIAGE_HINTS:
Use this ranked list to choose only suspicious hosts for deeper scans.
- 192.168.1.1: medium triage score 3; remote login surface: 22/tcp ssh OpenSSH 8.4

COMPACT_SUMMARY:
- 192.168.1.1 ports=[22/tcp:ssh/OpenSSH-8.4; 80/tcp:http]
```

#### `run_nmap_basic_scan`

Request:

```json
{
  "ip": "192.168.1.1"
}
```

Blocked response example:

```text
BLOCKED: 192.168.1.1 was not reported alive by the prerequisite ping sweep; refusing host scan.
```

#### `search_vulnerability_intel`

Request:

```json
{
  "query": "Apache HTTPD 2.4.41"
}
```

Blocked response example:

```text
BLOCKED: do not send private IP addresses or local hostnames to web search.
```

#### `search_cve_intel`

Request:

```json
{
  "query": "OpenSSH 8.4"
}
```

Response shape:

```text
CVE results for: OpenSSH 8.4

- CVE-...
  CVSS: ...
  CWE: ...
  Published: ...
  Description: ...
  References: ...
```

---

## Database Schema Overview

There is no database schema in the current repository. The effective data model is file-backed and represented by Python dataclasses.

| Entity | Source | Key Fields |
|---|---|---|
| `ParsedHost` | `tools/nmap_tools.py` | `ip`, `hostname`, `os_name`, `ports`, `trace_hops` |
| `ParsedPort` | `tools/nmap_tools.py` | `protocol`, `portid`, `state`, `service_name`, `product`, `service_version`, `cpe` |
| `Finding` | `tools/report_generator.py` | `title`, `severity`, `host`, `port`, `service`, `evidence`, `confidence`, `remediation`, `cve_refs` |
| `CVEEntry` | `tools/cve_lookup.py` | `cve_id`, `description`, `cvss_score`, `severity`, `cwe`, `published`, `references` |
| `StructuredFinding` | `tools/sub_agents.py` | `risk_level`, `title`, `open_ports`, `evidence`, `remediation`, `services_researched`, `cves_found` |
| `ActivityEvent` | `tools/activity_log.py` | `timestamp`, `category`, `message`, `detail`, `host`, `severity` |

```mermaid
erDiagram
    ParsedHost ||--o{ ParsedPort : has
    ParsedHost ||--o{ Finding : produces
    StructuredFinding ||--o{ Finding : enriches
    CVEEntry }o--o{ Finding : references
    ActivityEvent }o--|| Run : logs

    ParsedHost {
      string ip
      string hostname
      string os_name
    }

    ParsedPort {
      string protocol
      string portid
      string state
      string service_name
      string product
      string service_version
    }

    Finding {
      string title
      string severity
      string host
      string port
      string evidence
      string remediation
    }
```

---

## Usage Examples

### Standard Internal Assessment

```bash
python main.py --subnet 192.168.1.0/24 --profile standard --output all
```

### Multiple Approved Subnets

```bash
python main.py \
  --subnet 192.168.1.0/24 \
  --subnet 10.10.0.0/24 \
  --profile standard
```

### Manual Approval Mode

```bash
python main.py \
  --subnet 192.168.1.0/24 \
  --approval-mode manual \
  --output markdown
```

### Local HTTP MCP Transport

```bash
python main.py \
  --subnet 192.168.1.0/24 \
  --mcp-transport http \
  --http-port 8000
```

### Disable Public Search

```bash
python main.py \
  --subnet 192.168.1.0/24 \
  --no-search
```

### Web-Focused Scan Profile

```bash
python main.py \
  --subnet 192.168.1.0/24 \
  --profile web \
  --output html
```

### Run Without Parallel Sub-Agents

```bash
python main.py \
  --subnet 192.168.1.0/24 \
  --no-sub-agents
```

---

## Reports

Each run creates a timestamped directory:

```text
reports/<run_id>/
+-- activity.jsonl
+-- mcp_server.log
+-- network_summary.md
+-- network_summary.html
+-- findings.csv
+-- host_<ip>.md
+-- raw_nmap/
+-- xml_nmap/
```

### Network Summary Sections

| Section | Purpose |
|---|---|
| Executive Summary | Counts approved subnets, live hosts, open-port hosts, selected hosts, and severity totals |
| Scope And Coverage | Documents live host counts, triage status, scan depth, and skipped-host reasons |
| Scan Type Status | Shows scan status and evidence sources |
| Findings By Priority | Prioritized remediation table with observed and inferred evidence |
| Host Inventory | Lists host roles inferred from unauthenticated network evidence |
| Limitations And Follow-Up | Documents unauthenticated scope, triage limits, UDP gaps, and recommended next steps |

---

## Deployment

### Local Workstation Or Assessment VM

This is the primary supported deployment model.

```bash
python -m pip install -r requirements.txt
python main.py --subnet 192.168.1.0/24
```

### Docker

No `Dockerfile` or `docker-compose.yml` is present in the current repository. Containerization is possible, but would need to account for:

| Concern | Requirement |
|---|---|
| Nmap binary | Install Nmap in the image |
| Network mode | Container must be able to reach the approved local subnet |
| Reports | Mount `reports/` as a volume |
| Ollama | Connect to a reachable Ollama runtime |
| Permissions | Avoid privileged mode unless the chosen scan profile truly requires it |

Minimal starter Dockerfile:

```dockerfile
FROM python:3.12-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends nmap \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["python", "main.py"]
```

### Vercel

Vercel is not a good fit for the current codebase because NetCheckAI needs local network access, subprocess execution, Nmap, and long-running scan workflows. The generated static HTML report can be published separately if sensitive network details are removed.

### AWS

For AWS-hosted internal assessment, run NetCheckAI on a controlled EC2 instance inside the VPC you are authorized to assess.

| AWS Component | Suggested Use |
|---|---|
| EC2 | Assessment runner with Nmap installed |
| Security Groups | Restrict inbound access to the operator only |
| EBS | Store reports and raw scan artifacts |
| SSM Session Manager | Operator access without opening SSH |
| Secrets Manager / SSM Parameter Store | Optional storage for SerpAPI and NVD keys |

### Kubernetes

No Kubernetes manifests are present in this repository. A Kubernetes deployment would usually be unnecessary unless NetCheckAI is being wrapped into a larger internal platform. Network visibility from pods, Nmap privileges, and strict scope controls must be reviewed carefully before cluster deployment.

### Self-Hosting

Recommended self-hosted setup:

| Component | Recommendation |
|---|---|
| Host | Dedicated assessment VM on the authorized network |
| Runtime | Python virtual environment |
| Scanner | System Nmap package |
| Model | Local or cloud-backed Ollama model |
| Reports | Persist `reports/` and back it up according to your evidence retention policy |
| Network | Run from a segment with intentional visibility into approved targets |

---

## Performance Characteristics

| Area | Behavior |
|---|---|
| Scaling unit | Approved subnet and selected suspicious hosts |
| Default subnet limit | `max_subnet_addresses: 1024` |
| Default host cap | `max_hosts: 32` |
| Tool-call cap | `max_tool_calls: 40` |
| Search cap | `max_searches: 10` |
| Sub-agent concurrency | `sub_agents.concurrency: 4` |
| Nmap timeout | `nmap.timeout_seconds: 180` |
| Vulnerability scan timeout | `nmap.vuln_timeout_seconds: 300` |
| Search timeout | `search.timeout_seconds: 20` |
| NVD rate limit | `cve_lookup.rate_limit_seconds: 6.0` |

NetCheckAI scales by narrowing the assessment path: broad discovery first, targeted triage second, and deeper host assessment only where open services indicate risk. This keeps routine `/24` assessments more manageable than scanning every live host with every deep profile.

The current implementation is not a distributed scanner. It is optimized for local defensive workflows where auditability, scope control, and selective depth matter more than raw horizontal throughput.

---

## Security Model

NetCheckAI is intentionally defensive and constrained.

### Scope Validation

| Control | Implementation |
|---|---|
| Private IPv4 only | `validate_subnet`, `validate_ip_token`, RFC1918 network checks |
| Approved subnet only | Runtime `approved_subnets` policy |
| Max subnet size | `safety.max_subnet_addresses` |
| Max host scans | `safety.max_hosts` |
| Max tool/search calls | `safety.max_tool_calls`, `safety.max_searches` |

### Command Safety

| Control | Implementation |
|---|---|
| No shell execution | Nmap calls use argument lists and `shell=False` |
| Blocked terms | Commands reject tools such as curl, wget, nc, ssh, hydra, Metasploit, shells, and Python |
| Shell metacharacters | Characters including ampersand, semicolon, pipe, redirects, backticks, dollar signs, newlines, and carriage returns are rejected |
| Known command shapes | `classify_safe_nmap_command` allows only approved Nmap patterns |

### Search Safety

| Control | Implementation |
|---|---|
| Query length limit | 180 characters |
| Private IP rejection | RFC1918 and loopback-like private IP patterns are blocked |
| Offensive term rejection | Payloads, brute force, Metasploit, Hydra, and exploit-db style terms are blocked |
| API key redaction | SerpAPI URLs redact `api_key` before returning output |

### What Is Not Present

| Capability | Status |
|---|---|
| Encryption at rest | Not implemented beyond local filesystem controls |
| RBAC | Not implemented |
| Audit log signing | Not implemented |
| Central secret manager | Not implemented |
| Rate-limited web API | No public web API exists |
| Sandbox isolation | Tool restrictions are implemented in code; OS-level sandboxing is not included |

---

## Developer Experience

### Run Tests

```bash
python -m pytest tests/ -v
```

The test suite covers:

| Test File | Coverage |
|---|---|
| `test_subnet_validation.py` | RFC1918 validation, loopback/multicast rejection, subnet size caps |
| `test_command_allowlist.py` | Safe Nmap command shapes and blocked terminal commands |
| `test_search_sanitization.py` | Query validation and data-leak prevention |
| `test_nmap_runner.py` | Nmap command construction and discovery-before-host-scan enforcement |
| `test_triage_parsing.py` | Nmap text parsing and triage scoring |
| `test_report_generation.py` | Markdown/HTML/CSV output, deterministic evidence sections, CVE handling |
| `test_cve_lookup.py` | NVD parsing, formatting, caching, and disabled mode |
| `test_sub_agents.py` | Ollama response normalization, tool-call parsing, and sub-agent budget wiring |

### Local Development Loop

```bash
python -m pytest tests/ -v
python main.py --subnet 192.168.1.0/24 --profile standard --output all
```

### Type Safety

The codebase uses Python type hints and dataclasses extensively, but no static type-checker configuration such as `mypy.ini` or `pyproject.toml` is present.

### Linting And Formatting

No formatter or linter configuration is present in the current repository. If adding one, prefer a minimal setup that does not obscure security-sensitive diffs:

```bash
python -m pip install ruff
ruff check .
```

### CI/CD

No GitHub Actions, GitLab CI, or other CI/CD configuration is present in the current repository. A practical first workflow would run:

```bash
python -m pip install -r requirements.txt
python -m pytest tests/ -v
```

---

## Roadmap

This roadmap is inferred from the implementation shape, tests, and configuration. It avoids claiming features that are not currently implemented.

| Priority | Item | Rationale |
|---|---|---|
| Near-term | Add GitHub Actions test workflow | The pytest suite is already in place |
| Near-term | Add `pyproject.toml` with tool config | Centralize package metadata, formatting, linting, and test settings |
| Near-term | Add example sanitized reports | Improve onboarding without exposing real local-network data |
| Near-term | Wire historical comparison into main report path | Comparison helpers and config exist, but full run-to-run reporting is only partially connected |
| Mid-term | Add Docker support | Useful for repeatable assessment environments |
| Mid-term | Add structured JSON report export | Easier integration with ticketing, SIEM, or GRC workflows |
| Mid-term | Add full-port maintenance-window profile | Current workflow favors top-port triage and selective depth |
| Mid-term | Add report redaction utilities | Help teams safely share artifacts externally |
| Longer-term | Add signed audit logs | Strengthen evidence integrity for regulated environments |
| Longer-term | Add optional multi-user service wrapper | Would require auth, RBAC, storage, and a careful threat model |

---

## Contributing

Contributions should preserve the project's defensive operating model. The most valuable changes are those that improve safety, auditability, reporting clarity, parser correctness, and operator control.

### Development Principles

| Principle | Expectation |
|---|---|
| Keep scope enforcement in code | Do not rely on prompts alone for security boundaries |
| Preserve evidence | Raw and structured artifacts should remain available for audit |
| Prefer deterministic reporting | AI can enrich findings, but reports should be grounded in parsed evidence |
| Gate active validation | Custom active checks must require code-level scope checks, host approval, per-command approval, timeouts, and audit logs |
| Test safety changes | Scope, command, and search guardrails need regression tests |

### Suggested Workflow

```bash
git checkout -b feature/your-change
python -m pip install -r requirements.txt
python -m pytest tests/ -v
```

Before opening a pull request:

| Check | Command |
|---|---|
| Tests pass | `python -m pytest tests/ -v` |
| README still accurate | Review changed flags, config, tools, and report outputs |
| No sensitive artifacts | Remove private scan data unless intentionally sanitized |
| Safety preserved | Confirm new tool paths cannot scan outside approved scope |

---

## License

NetCheckAI is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for the full license text.

---

## Footer

NetCheckAI is for authorized defensive assessment only. It is designed to make internal network review faster, more consistent, and more accountable while keeping the operator in control of scope, evidence, and action.
