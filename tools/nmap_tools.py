"""Safe Nmap wrappers for local defensive network assessment.

The MCP server and the main controller both use this module so that scope
validation is enforced in code, not only by the language-model prompt.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Literal


CommandKind = Literal["ping_sweep", "triage_scan", "basic_scan", "service_scan", "vuln_scan"]

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

DENIED_TERMS = {
    "bash",
    "bash.exe",
    "bash-i",
    "cmd",
    "cmd.exe",
    "chmod",
    "curl",
    "curl.exe",
    "hydra",
    "metasploit",
    "msfconsole",
    "nc",
    "nc.exe",
    "netcat",
    "perl",
    "php",
    "powershell",
    "powershell.exe",
    "pwsh",
    "python",
    "python.exe",
    "python3",
    "rm",
    "ruby",
    "sh",
    "sh.exe",
    "ssh",
    "ssh.exe",
    "sudo",
    "telnet",
    "wget",
    "wget.exe",
    "zsh",
}

SHELL_METACHARS = set("&;|<>`$\\\n\r")


@dataclass(frozen=True)
class SafeNmapSettings:
    """Runtime settings for the safe Nmap wrapper."""

    approved_subnets: tuple[ipaddress.IPv4Network, ...]
    allowed_private_cidrs: tuple[ipaddress.IPv4Network, ...] = RFC1918_NETWORKS
    reports_dir: Path = Path("reports")
    nmap_path: str = "nmap"
    nmap_timeout_seconds: int = 180
    vuln_timeout_seconds: int = 300
    triage_top_ports: int = 100
    max_output_chars: int = 60_000
    max_subnet_addresses: int = 1024

    @property
    def raw_nmap_dir(self) -> Path:
        return self.reports_dir / "raw_nmap"


@dataclass(frozen=True)
class ClassifiedCommand:
    """A terminal command after it has matched one approved Nmap shape."""

    kind: CommandKind
    target: str
    argv: tuple[str, ...]


@dataclass
class SafeNmapRunner:
    """Stateful safe Nmap runner.

    State is intentionally simple: it prevents direct service/vuln scans before
    earlier reconnaissance steps have completed in this process.
    """

    settings: SafeNmapSettings
    completed_ping_sweeps: set[str] = field(default_factory=set)
    triaged_subnets: set[str] = field(default_factory=set)
    basic_scanned_hosts: set[str] = field(default_factory=set)
    service_scanned_hosts: set[str] = field(default_factory=set)
    vuln_scanned_hosts: set[str] = field(default_factory=set)

    def run_nmap_ping_sweep(self, subnet: str) -> str:
        network = validate_subnet(
            subnet,
            self.settings.allowed_private_cidrs,
            self.settings.max_subnet_addresses,
        )
        if not any(network.subnet_of(approved) for approved in self.settings.approved_subnets):
            return f"BLOCKED: subnet {network} is not in the runtime-approved scan scope."

        argv = (self._nmap_binary(), "-sn", str(network))
        result = self._run_nmap(argv, timeout=self.settings.nmap_timeout_seconds)
        self._write_raw(f"{safe_name(str(network))}_ping_sweep.txt", result)
        if nmap_completed(result):
            self.completed_ping_sweeps.add(str(network))
        return format_tool_result(argv, str(network), result)

    def run_nmap_triage_scan(self, subnet: str) -> str:
        network = validate_subnet(
            subnet,
            self.settings.allowed_private_cidrs,
            self.settings.max_subnet_addresses,
        )
        if not any(network.subnet_of(approved) for approved in self.settings.approved_subnets):
            return f"BLOCKED: subnet {network} is not in the runtime-approved scan scope."
        if str(network) not in self.completed_ping_sweeps:
            return f"BLOCKED: run_nmap_ping_sweep must complete before triage scan for {network}."

        top_ports = str(self.settings.triage_top_ports)
        argv = (self._nmap_binary(), "-sV", "--top-ports", top_ports, "--open", str(network))
        result = self._run_nmap(argv, timeout=self.settings.nmap_timeout_seconds)
        self._write_raw(f"{safe_name(str(network))}_triage_scan.txt", result)
        if nmap_completed(result):
            self.triaged_subnets.add(str(network))
        return format_tool_result(argv, str(network), result) + "\n\nTRIAGE_HINTS:\n" + build_triage_hints(result)

    def run_nmap_basic_scan(self, ip: str) -> str:
        target = self._validate_host_for_scan(ip, require_ping_sweep=True)
        if isinstance(target, str):
            return target

        argv = (self._nmap_binary(), "-sV", "--top-ports", "1000", str(target))
        result = self._run_nmap(argv, timeout=self.settings.nmap_timeout_seconds)
        self._append_host_raw(str(target), "basic scan", argv, result)
        if nmap_completed(result):
            self.basic_scanned_hosts.add(str(target))
        return format_tool_result(argv, str(target), result, self._host_raw_path(str(target)))

    def run_nmap_service_scan(self, ip: str) -> str:
        target = self._validate_host_for_scan(ip, require_ping_sweep=True)
        if isinstance(target, str):
            return target
        if str(target) not in self.basic_scanned_hosts:
            return f"BLOCKED: run_nmap_basic_scan must complete before service scan for {target}."

        argv = (self._nmap_binary(), "-sV", "-sC", "-O", str(target))
        result = self._run_nmap(argv, timeout=self.settings.nmap_timeout_seconds)
        self._append_host_raw(str(target), "service/script/os scan", argv, result)
        if nmap_completed(result):
            self.service_scanned_hosts.add(str(target))
        return format_tool_result(argv, str(target), result, self._host_raw_path(str(target)))

    def run_nmap_vuln_scan(self, ip: str) -> str:
        target = self._validate_host_for_scan(ip, require_ping_sweep=True)
        if isinstance(target, str):
            return target
        if str(target) not in self.service_scanned_hosts:
            return f"BLOCKED: run_nmap_service_scan must complete before vulnerability script scan for {target}."

        argv = (self._nmap_binary(), "--script", "vuln", "-sV", str(target))
        result = self._run_nmap(argv, timeout=self.settings.vuln_timeout_seconds)
        self._append_host_raw(str(target), "vulnerability script scan", argv, result)
        if nmap_completed(result):
            self.vuln_scanned_hosts.add(str(target))
        return format_tool_result(argv, str(target), result, self._host_raw_path(str(target)))

    def run_limited_terminal(self, command: str) -> str:
        try:
            classified = classify_safe_nmap_command(command)
        except ValueError as exc:
            return f"BLOCKED: {exc}"

        if classified.kind == "ping_sweep":
            return self.run_nmap_ping_sweep(classified.target)
        if classified.kind == "triage_scan":
            return self.run_nmap_triage_scan(classified.target)
        if classified.kind == "basic_scan":
            return self.run_nmap_basic_scan(classified.target)
        if classified.kind == "service_scan":
            return self.run_nmap_service_scan(classified.target)
        if classified.kind == "vuln_scan":
            return self.run_nmap_vuln_scan(classified.target)
        return "BLOCKED: unsupported command type."

    def _validate_host_for_scan(
        self,
        ip: str,
        *,
        require_ping_sweep: bool,
    ) -> ipaddress.IPv4Address | str:
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return f"BLOCKED: {ip!r} is not a valid IP address."

        if target.version != 4:
            return "BLOCKED: only IPv4 local network scans are supported."
        if not is_rfc1918_address(target):
            return f"BLOCKED: {target} is not an RFC1918 private IPv4 address."
        if not any(target in network for network in self.settings.approved_subnets):
            return f"BLOCKED: {target} is outside the runtime-approved scan scope."
        if require_ping_sweep and not any(
            target in ipaddress.ip_network(subnet) for subnet in self.completed_ping_sweeps
        ):
            return f"BLOCKED: run_nmap_ping_sweep must complete before host scans for {target}."
        return target

    def _run_nmap(self, argv: tuple[str, ...], *, timeout: int) -> str:
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                shell=False,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return (
                "ERROR: Nmap executable was not found. Configure nmap_path in "
                "config.yaml or install Nmap and add it to PATH."
            )
        except subprocess.TimeoutExpired:
            return f"ERROR: Nmap command timed out after {timeout} seconds."

        output = "\n".join(
            part
            for part in (
                f"EXIT_CODE: {completed.returncode}",
                "STDOUT:",
                completed.stdout.strip(),
                "STDERR:",
                completed.stderr.strip(),
            )
            if part is not None
        ).strip()
        return output

    def _nmap_binary(self) -> str:
        configured = self.settings.nmap_path
        if configured and configured.lower() != "nmap":
            return configured

        resolved = shutil.which("nmap")
        if resolved:
            return resolved

        windows_default = Path(r"C:\Program Files (x86)\Nmap\nmap.exe")
        if windows_default.exists():
            return str(windows_default)
        return configured

    def _host_raw_path(self, ip: str) -> Path:
        return self.settings.raw_nmap_dir / f"{safe_name(ip)}_scan.txt"

    def _write_raw(self, filename: str, content: str) -> Path:
        self.settings.raw_nmap_dir.mkdir(parents=True, exist_ok=True)
        path = self.settings.raw_nmap_dir / filename
        path.write_text(content, encoding="utf-8")
        return path

    def _append_host_raw(
        self,
        ip: str,
        label: str,
        argv: Iterable[str],
        content: str,
    ) -> Path:
        self.settings.raw_nmap_dir.mkdir(parents=True, exist_ok=True)
        path = self._host_raw_path(ip)
        command = " ".join(argv)
        section = f"\n\n## {label}\nCOMMAND: {command}\n\n{content.strip()}\n"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(section)
        return path


def validate_subnet(
    subnet: str,
    allowed_private_cidrs: Iterable[ipaddress.IPv4Network] = RFC1918_NETWORKS,
    max_subnet_addresses: int | None = None,
) -> ipaddress.IPv4Network:
    """Parse and validate a user-approved local IPv4 subnet."""

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"{subnet!r} is not a valid CIDR subnet.") from exc

    if network.version != 4:
        raise ValueError("Only IPv4 subnets are supported.")
    if not any(network.subnet_of(rfc1918) for rfc1918 in RFC1918_NETWORKS):
        raise ValueError(f"{network} is outside RFC1918 private ranges.")
    if not any(network.subnet_of(allowed) for allowed in allowed_private_cidrs):
        raise ValueError(f"{network} is outside allowed RFC1918 private ranges.")
    if network.is_loopback or network.is_multicast or network.is_unspecified:
        raise ValueError(f"{network} is not an allowed local LAN range.")
    if max_subnet_addresses is not None and network.num_addresses > max_subnet_addresses:
        raise ValueError(
            f"{network} contains {network.num_addresses} addresses, above the "
            f"configured max_subnet_addresses={max_subnet_addresses}."
        )
    return network


def parse_ipv4_networks(values: Iterable[str]) -> tuple[ipaddress.IPv4Network, ...]:
    networks: list[ipaddress.IPv4Network] = []
    for value in values:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4 or not any(network.subnet_of(rfc1918) for rfc1918 in RFC1918_NETWORKS):
            raise ValueError(f"Configured allowed range {network} is not an RFC1918 IPv4 network.")
        networks.append(network)
    return tuple(networks)


def is_rfc1918_address(value: ipaddress._BaseAddress) -> bool:
    return value.version == 4 and any(value in network for network in RFC1918_NETWORKS)


def classify_safe_nmap_command(command: str) -> ClassifiedCommand:
    """Validate a terminal command and classify it as one safe Nmap operation."""

    if not command or not command.strip():
        raise ValueError("empty commands are not allowed.")
    if any(char in command for char in SHELL_METACHARS):
        raise ValueError("shell metacharacters are not allowed.")

    lowered = command.lower()
    for term in DENIED_TERMS:
        if re.search(rf"(^|[\s/\\]){re.escape(term)}($|[\s/\\])", lowered):
            raise ValueError(f"blocked term {term!r} is not allowed.")

    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise ValueError("command could not be parsed safely.") from exc

    if not tokens:
        raise ValueError("empty commands are not allowed.")
    executable = Path(tokens[0]).name.lower()
    if executable not in {"nmap", "nmap.exe"}:
        raise ValueError("only nmap commands are allowed.")

    args = tokens[1:]
    if len(args) == 2 and args[0] == "-sn":
        validate_subnet(args[1])
        return ClassifiedCommand("ping_sweep", str(ipaddress.ip_network(args[1], strict=False)), tuple(tokens))

    if sorted(args[:-1]) == sorted(["-sV", "--top-ports", "1000"]):
        target = validate_ip_token(args[-1])
        return ClassifiedCommand("basic_scan", str(target), tuple(tokens))

    if sorted(args[:-1]) == sorted(["-sV", "--top-ports", "100", "--open"]):
        network = validate_subnet(args[-1])
        return ClassifiedCommand("triage_scan", str(network), tuple(tokens))

    if len(args) == 4 and sorted(args[:-1]) == sorted(["-sV", "-sC", "-O"]):
        target = validate_ip_token(args[-1])
        return ClassifiedCommand("service_scan", str(target), tuple(tokens))

    if len(args) == 4 and sorted(args[:-1]) == sorted(["--script", "vuln", "-sV"]):
        target = validate_ip_token(args[-1])
        return ClassifiedCommand("vuln_scan", str(target), tuple(tokens))

    if len(args) == 3 and sorted(args[:-1]) == sorted(["--script=vuln", "-sV"]):
        target = validate_ip_token(args[-1])
        return ClassifiedCommand("vuln_scan", str(target), tuple(tokens))

    raise ValueError("command does not match the approved safe Nmap command allowlist.")


def validate_ip_token(value: str) -> ipaddress.IPv4Address:
    try:
        target = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{value!r} is not a valid IP address.") from exc
    if target.version != 4:
        raise ValueError("only IPv4 targets are supported.")
    if not is_rfc1918_address(target):
        raise ValueError(f"{target} is not an RFC1918 private IPv4 address.")
    return target


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def nmap_completed(output: str) -> bool:
    return not output.startswith("ERROR:")


def build_triage_hints(output: str) -> str:
    hosts = parse_nmap_hosts(output)
    if not hosts:
        return "No open services were parsed from the triage output."

    scored: list[tuple[int, str, list[str]]] = []
    for host, services in hosts.items():
        score = 0
        reasons: list[str] = []
        open_count = len(services)
        if open_count >= 8:
            score += 3
            reasons.append(f"many open ports ({open_count})")
        elif open_count >= 4:
            score += 2
            reasons.append(f"several open ports ({open_count})")

        for service in services:
            port = service["port"]
            name = service["service"].lower()
            version = service["version"].lower()
            label = f"{port} {service['service']} {service['version']}".strip()

            if name in {"telnet", "ftp", "tftp"}:
                score += 4
                reasons.append(f"insecure cleartext service: {label}")
            elif name in {"microsoft-ds", "netbios-ssn", "smb"} or port.startswith(("139/", "445/")):
                score += 4
                reasons.append(f"SMB/NetBIOS exposure: {label}")
            elif name in {"ms-wbt-server", "rdp"} or port.startswith("3389/"):
                score += 4
                reasons.append(f"RDP exposure: {label}")
            elif name in {"vnc", "snmp", "redis", "mongodb", "elasticsearch", "mysql", "postgresql"}:
                score += 3
                reasons.append(f"sensitive service exposed: {label}")
            elif name in {"http", "https", "http-proxy"}:
                score += 2
                reasons.append(f"web/admin surface possible: {label}")
            elif name in {"ssh"}:
                score += 1
                reasons.append(f"remote login surface: {label}")
            elif name in {"unknown"} or "unknown" in version:
                score += 2
                reasons.append(f"unknown service: {label}")

            if has_old_version_hint(version):
                score += 3
                reasons.append(f"old-looking version string: {label}")

        if not reasons:
            reasons.append("open services found but no obvious high-risk indicator")
        scored.append((score, host, dedupe_preserve_order(reasons)))

    scored.sort(key=lambda item: (-item[0], ip_sort_key(item[1])))
    rows = [
        "Use this ranked list to choose only suspicious hosts for deeper scans.",
        "Run search_vulnerability_intel on service/version strings before vuln scans when useful.",
    ]
    for score, host, reasons in scored:
        severity = "high" if score >= 6 else "medium" if score >= 3 else "low"
        rows.append(f"- {host}: {severity} triage score {score}; " + "; ".join(reasons[:5]))
    return "\n".join(rows)


def parse_nmap_hosts(output: str) -> dict[str, list[dict[str, str]]]:
    hosts: dict[str, list[dict[str, str]]] = {}
    current_host = ""
    for line in output.splitlines():
        report_match = re.match(r"Nmap scan report for (.+)$", line.strip())
        if report_match:
            current_host = extract_host_identifier(report_match.group(1))
            hosts.setdefault(current_host, [])
            continue
        if not current_host:
            continue
        service_match = re.match(r"^(\d+/(?:tcp|udp))\s+open\s+(\S+)\s*(.*)$", line.strip())
        if service_match:
            hosts[current_host].append(
                {
                    "port": service_match.group(1),
                    "service": service_match.group(2),
                    "version": service_match.group(3).strip(),
                }
            )
    return {host: services for host, services in hosts.items() if services}


def extract_host_identifier(raw: str) -> str:
    paren_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", raw)
    if paren_match:
        return paren_match.group(1)
    first = raw.split()[0]
    return first


def has_old_version_hint(version: str) -> bool:
    checks = (
        r"openssh[_\s-]?[1-6]\.",
        r"apache httpd 2\.[0-2]\.",
        r"nginx 0\.",
        r"nginx 1\.(?:0|1|2|3|4|5|6|7|8|9|10|11|12)\.",
        r"samba 3\.",
        r"samba 4\.(?:0|1|2|3|4|5|6|7|8)\.",
        r"proftpd 1\.3\.[0-5]",
        r"vsftpd 2\.",
        r"microsoft-iis/[1-7]\.",
        r"mysql 5\.",
        r"postgresql 9\.",
    )
    return any(re.search(pattern, version) for pattern in checks)


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped


def ip_sort_key(value: str) -> tuple[int, str]:
    try:
        return (0, f"{int(ipaddress.ip_address(value)):012d}")
    except ValueError:
        return (1, value)


def format_tool_result(
    argv: Iterable[str],
    target: str,
    output: str,
    raw_report_path: Path | None = None,
) -> str:
    trimmed = output
    if len(trimmed) > 60_000:
        trimmed = trimmed[:60_000] + "\n\n[Output truncated for model context; full output saved on disk.]"

    path_line = f"RAW_REPORT: {raw_report_path}" if raw_report_path else "RAW_REPORT: none"
    return "\n".join(
        (
            f"COMMAND: {' '.join(argv)}",
            f"TARGET: {target}",
            path_line,
            "OUTPUT:",
            trimmed,
        )
    )
