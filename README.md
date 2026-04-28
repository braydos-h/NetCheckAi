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
- `tools/nmap_tools.py`: Safe Nmap wrappers, validation, command allowlist, triage ranking, raw output writing.
- `tools/search_tools.py`: Restricted SerpAPI DuckDuckGo search for defensive vulnerability intelligence.
- `config.yaml`: Defaults for model, MCP, Nmap, reports, and safety caps.
- `reports/network_summary.md`: Final summary report.
- `reports/host_<ip>.md`: Per-host report.
- `reports/raw_nmap/<ip>_scan.txt`: Raw Nmap evidence.

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

Disable web search for a run:

```powershell
python main.py --subnet 192.168.1.0/24 --no-search
```

Plain terminal output without Rich formatting:

```powershell
python main.py --subnet 192.168.1.0/24 --plain
```

## Scan Flow

The controller and server both enforce this order:

1. Discovery: `nmap -sn <subnet>`
2. Triage service/version scan: `nmap -sV --top-ports 100 --open <subnet>`
3. Basic service/version scan for selected hosts only: `nmap -sV --top-ports 1000 <ip>`
4. Deeper service/default-script/OS scan for selected hosts: `nmap -sV -sC -O <ip>`
5. Optional vulnerability enumeration: `nmap --script vuln -sV <ip>`

The triage tool appends ranked hints based on risky services, many open ports, old-looking versions, unknown services, and admin surfaces. The AI is instructed to use those hints and advisory searches to pick only suspicious hosts for deeper scans.

## Validation Examples

These should be rejected before any Nmap execution:

```powershell
python main.py --subnet 8.8.8.0/24
python main.py --subnet 127.0.0.0/8
```

Terminal tool examples that are blocked:

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

## Notes

Use this only on networks and devices you own or are authorized to assess. The reports are defensive and remediation-focused; they intentionally avoid exploit instructions.
