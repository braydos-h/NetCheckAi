"""Synthetic scan data for demo mode.

Presents a realistic 5-host vulnerable network scenario on 10.0.0.0/24.
All data is crafted to look authentic; no real Nmap ever runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DEMO_SUBNET = "10.0.0.0/24"
DEMO_LIVE_HOSTS = ["10.0.0.1", "10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.0.50"]


@dataclass
class _HostSpec:
    ip: str
    hostname: str
    os_name: str
    os_accuracy: int = 94
    ports: list[dict[str, Any]] = field(default_factory=list)
    vuln_script_output: str = ""


# ---------------------------------------------------------------------------
# Host definitions
# ---------------------------------------------------------------------------

_GATEWAY = _HostSpec(
    ip="10.0.0.1",
    hostname="gateway.local",
    os_name="OpenWrt (Linux 3.10)",
    ports=[
        {
            "protocol": "tcp",
            "portid": "23",
            "state": "open",
            "service_name": "telnet",
            "product": "BusyBox telnetd",
            "service_version": "1.30.1",
            "extrainfo": "OpenWrt router",
            "cpe": ["cpe:/a:busybox:busybox:1.30.1"],
        },
        {
            "protocol": "tcp",
            "portid": "80",
            "state": "open",
            "service_name": "http",
            "product": "uHTTPd",
            "service_version": "1.0",
            "extrainfo": "OpenWrt 19.07",
            "cpe": ["cpe:/a:openwrt:uhttpd:1.0"],
        },
    ],
    vuln_script_output=(
        "80/tcp http:"
        "\n| http-title: OpenWrt - LuCI"
        "\n|_http-server-header: uHTTPd/1.0"
        "\n|_http-cookie-flags: No cookies found"
        "\n| http-default-accounts:"
        "\n|_[ERROR] Could not determine default credentials (page not supported)"
        "\n23/tcp telnet:"
        "\n| telnet-encryption: Telnet server does not support encryption"
        "\n|_banner: (none)"
    ),
)

_WEB = _HostSpec(
    ip="10.0.0.10",
    hostname="web01.internal",
    os_name="Ubuntu 20.04",
    ports=[
        {
            "protocol": "tcp",
            "portid": "22",
            "state": "open",
            "service_name": "ssh",
            "product": "OpenSSH",
            "service_version": "8.2p1",
            "extrainfo": "Ubuntu 20.04",
            "cpe": ["cpe:/a:openssh:openssh:8.2p1"],
        },
        {
            "protocol": "tcp",
            "portid": "80",
            "state": "open",
            "service_name": "http",
            "product": "Apache httpd",
            "service_version": "2.4.49",
            "extrainfo": "(Ubuntu)",
            "cpe": ["cpe:/a:apache:http_server:2.4.49"],
        },
        {
            "protocol": "tcp",
            "portid": "443",
            "state": "open",
            "service_name": "https",
            "product": "Apache httpd",
            "service_version": "2.4.49",
            "extrainfo": "mod_ssl/2.4.49 OpenSSL/1.1.1f (Ubuntu)",
            "cpe": ["cpe:/a:apache:http_server:2.4.49"],
        },
        {
            "protocol": "tcp",
            "portid": "8080",
            "state": "open",
            "service_name": "http-proxy",
            "product": "Apache Tomcat/Coyote",
            "service_version": "1.1",
            "extrainfo": "JSP engine",
            "cpe": ["cpe:/a:apache:tomcat"],
        },
    ],
    vuln_script_output=(
        "80/tcp http:"
        "\n| http-title: Test Site"
        "\n|_http-server-header: Apache/2.4.49 (Ubuntu)"
        "\n| http-enum:"
        "\n|   /.git/HEAD: Potential Git repository"
        "\n|   /phpinfo.php: PHP information page"
        "\n|_  /cgi-bin/: CGI directory"
        "\n| http-csrf:"
        "\n|_  Couldn't find any CSRF vulnerabilities"
        "\n| http-vuln-cve2021-41773:"
        "\n|   VULNERABLE:"
        "\n|   Apache HTTP Server 2.4.49 is affected by a path traversal vulnerability (CVE-2021-41773)."
        "\n|   The flaw can be exploited to map URLs to files outside the configured document root."
        "\n|_  References: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773"
        "\n443/tcp https:"
        "\n| ssl-dh-params: Weak Diffie-Hellman parameters"
        "\n| tls-nextprotoneg:"
        "\n|   h2"
        "\n|_  http/1.1"
    ),
)

_DB = _HostSpec(
    ip="10.0.0.20",
    hostname="db01.internal",
    os_name="Ubuntu 18.04",
    ports=[
        {
            "protocol": "tcp",
            "portid": "3306",
            "state": "open",
            "service_name": "mysql",
            "product": "MySQL",
            "service_version": "5.7.33",
            "extrainfo": "Community Server (GPL)",
            "cpe": ["cpe:/a:mysql:mysql:5.7.33"],
        },
    ],
    vuln_script_output=(
        "3306/tcp mysql:"
        "\n| mysql-empty-password: Root account has no password"
        "\n|_  WARNING: Remote host allows access without a password"
        "\n| mysql-info:"
        "\n|   Protocol: 10"
        "\n|   Version: 5.7.33"
        "\n|   Thread ID: 42"
        "\n|_  Salt: 1234567890abcdef"
        "\n| mysql-enum:"
        "\n|   Accounts with empty password:"
        "\n|     root@localhost"
        "\n|_    mysql.session@localhost"
    ),
)

_WINDOWS = _HostSpec(
    ip="10.0.0.30",
    hostname="workstation01.corp.local",
    os_name="Microsoft Windows 10 Pro 19045",
    ports=[
        {
            "protocol": "tcp",
            "portid": "139",
            "state": "open",
            "service_name": "netbios-ssn",
            "product": "Microsoft Windows netbios-ssn",
            "service_version": "",
            "extrainfo": "",
            "cpe": ["cpe:/o:microsoft:windows_10"],
        },
        {
            "protocol": "tcp",
            "portid": "445",
            "state": "open",
            "service_name": "microsoft-ds",
            "product": "Microsoft Windows Server 2008 R2 - 2012 microsoft-ds",
            "service_version": "",
            "extrainfo": "Workgroup: WORKGROUP",
            "cpe": ["cpe:/o:microsoft:windows_server_2008:r2"],
        },
        {
            "protocol": "tcp",
            "portid": "3389",
            "state": "open",
            "service_name": "ms-wbt-server",
            "product": "Microsoft Terminal Services",
            "service_version": "",
            "extrainfo": "",
            "cpe": ["cpe:/a:microsoft:terminal_services"],
        },
    ],
    vuln_script_output=(
        "445/tcp microsoft-ds:"
        "\n| smb-security-mode:"
        "\n|   account_used: guest"
        "\n|   authentication_level: user"
        "\n|   challenge_response: supported"
        "\n|_  message_signing: disabled (dangerous, but default)"
        "\n| smb-vuln-ms17-010:"
        "\n|   VULNERABLE:"
        "\n|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (MS17-010, EternalBlue)"
        "\n|     State: VULNERABLE"
        "\n|     IDs:  CVE-2017-0144,CVE-2017-0145,CVE-2017-0146,CVE-2017-0147,CVE-2017-0148"
        "\n|     Risk factor: HIGH CVSSv2: 9.3 (HIGH)"
        "\n|     Exploitable with Metasploit: exploit/windows/smb/ms17_010_eternalblue"
        "\n|_  References: https://technet.microsoft.com/en-us/library/security/ms17-010.aspx"
        "\n| smb-protocols:"
        "\n|   dialects:"
        "\n|     NT LM 0.12 (SMBv1) -- DANGEROUS"
        "\n|     2.02"
        "\n|     2.10"
        "\n|_    3.00"
        "\n3389/tcp ms-wbt-server:"
        "\n| rdp-enum-encryption:"
        "\n|   Security layer:"
        "\n|     CredSSP (NLA): SUCCESS"
        "\n|_    CredSSP (NLA): NOT REQUIRED"
        "\n| rdp-vuln-ms12-020:"
        "\n|   NOT VULNERABLE:"
        "\n|_  Not affected by MS12-020"
    ),
)

_IOT = _HostSpec(
    ip="10.0.0.50",
    hostname="cam01.iot",
    os_name="Linux 3.18",
    ports=[
        {
            "protocol": "tcp",
            "portid": "80",
            "state": "open",
            "service_name": "http",
            "product": "Hikvision Embedded Web Server",
            "service_version": "1.0",
            "extrainfo": "",
            "cpe": ["cpe:/a:hikvision:embedded_web_server:1.0"],
        },
        {
            "protocol": "tcp",
            "portid": "554",
            "state": "open",
            "service_name": "rtsp",
            "product": "Hikvision RTSP Server",
            "service_version": "1.0",
            "extrainfo": "",
            "cpe": ["cpe:/a:hikvision:rtsp_server:1.0"],
        },
    ],
    vuln_script_output=(
        "80/tcp http:"
        "\n| http-title: Hikvision - Login"
        "\n|_http-server-header: Hikvision Embedded Web Server"
        "\n| http-default-accounts:"
        "\n|   [+] admin:12345 (Hikvision default credentials)"
        "\n|_  [+] root:12345 (Hikvision default credentials)"
        "\n| http-vuln-cve2017-7921:"
        "\n|   VULNERABLE:"
        "\n|   Hikvision IP camera backdoor allows undocumented command to retrieve"
        "\n|   user configuration including passwords."
        "\n|     State: VULNERABLE"
        "\n|     IDs:  CVE-2017-7921"
        "\n|     Risk factor: HIGH"
        "\n|_  References: https://www.exploit-db.com/exploits/45233/"
        "\n554/tcp rtsp:"
        "\n| rtsp-url-brute:"
        "\n|   RTSP URLs found:"
        "\n|     /h264/ch1/main/av_stream"
        "\n|_    /Streaming/Channels/101"
    ),
)

_ALL_HOSTS: list[_HostSpec] = [_GATEWAY, _WEB, _DB, _WINDOWS, _IOT]


# ---------------------------------------------------------------------------
# Raw text generators (match real Nmap CLI output shape)
# ---------------------------------------------------------------------------


def _make_raw_ping_sweep() -> str:
    lines = [
        "COMMAND: nmap -sn --traceroute 10.0.0.0/24 -oX ...",
        "OUTPUT:",
        "Nmap scan report for gateway.local (10.0.0.1)",
        "Host is up (0.0020s latency).",
        "Nmap scan report for web01.internal (10.0.0.10)",
        "Host is up (0.0030s latency).",
        "Nmap scan report for db01.internal (10.0.0.20)",
        "Host is up (0.0150s latency).",
        "Nmap scan report for workstation01.corp.local (10.0.0.30)",
        "Host is up (0.0080s latency).",
        "Nmap scan report for cam01.iot (10.0.0.50)",
        "Host is up (0.0250s latency).",
        "LIVE_HOSTS:",
    ] + [f"- {ip}" for ip in DEMO_LIVE_HOSTS] + [
        "COMPACT_SUMMARY:",
        "- 10.0.0.1 (gateway.local) OS=OpenWrt (Linux 3.10) ports=[]",
        "- 10.0.0.10 (web01.internal) OS=Ubuntu 20.04 ports=[]",
        "- 10.0.0.20 (db01.internal) OS=Ubuntu 18.04 ports=[]",
        "- 10.0.0.30 (workstation01.corp.local) OS=Microsoft Windows 10 Pro 19045 ports=[]",
        "- 10.0.0.50 (cam01.iot) OS=Linux 3.18 ports=[]",
    ]
    return "\n".join(lines)


def _make_raw_triage_scan() -> str:
    lines = [
        "COMMAND: nmap -sV --top-ports 100 --open -T4 --max-retries 2 10.0.0.0/24 -oX ...",
        "OUTPUT:",
    ]
    for host in _ALL_HOSTS:
        lines.append(f"Nmap scan report for {host.hostname} ({host.ip})")
        lines.append("Host is up (0.00xxs latency).")
        for p in host.ports:
            version_str = f"{p['product']} {p['service_version']}".strip() or ""
            lines.append(f"{p['portid']}/{p['protocol']}  open  {p['service_name']}  {version_str}")
        lines.append("")
    lines.append("LIVE_HOSTS:")
    lines += [f"- {ip}" for ip in DEMO_LIVE_HOSTS]
    lines.append("TRIAGE_HINTS:")
    lines += [
        "Use this ranked list to choose only suspicious hosts for deeper scans.",
        "Run search_vulnerability_intel on service/version strings before vuln scans when useful.",
        "- 10.0.0.50: high triage score 7; risky service rtsp; default credentials risk (iot device); risky management port http",
        "- 10.0.0.30: high triage score 7; old-looking version string: 445/microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds; risky remote service ms-wbt-server; legacy protocol smb",
        "- 10.0.0.10: medium triage score 5; old-looking version string: 80/http Apache httpd 2.4.49; exposed web server",
        "- 10.0.0.20: medium triage score 3; database port open (3306/tcp mysql); risky service mysql",
        "- 10.0.0.1: medium triage score 3; risky service telnet; management port http",
    ]
    return "\n".join(lines)


def _make_raw_basic_scan(host: _HostSpec) -> str:
    lines = [
        f"COMMAND: nmap -sV --top-ports 1000 {host.ip} -oX ...",
        "OUTPUT:",
        f"Nmap scan report for {host.hostname} ({host.ip})",
        "Host is up (0.00xxs latency).",
    ]
    for p in host.ports:
        version_str = f"{p['product']} {p['service_version']}".strip() or ""
        lines.append(f"{p['portid']}/{p['protocol']}  open  {p['service_name']}  {version_str}")
    lines.append("")
    lines.append("LIVE_HOSTS:")
    lines.append(f"- {host.ip}")
    return "\n".join(lines)


def _make_raw_service_scan(host: _HostSpec) -> str:
    lines = [
        f"COMMAND: nmap -sV -sC -O {host.ip} -oX ...",
        "OUTPUT:",
        f"Nmap scan report for {host.hostname} ({host.ip})",
        "Host is up (0.00xxs latency).",
        f"OS detection: {host.os_name}",
    ]
    for p in host.ports:
        extrainfo = f" ({p['extrainfo']})" if p.get("extrainfo") else ""
        lines.append(f"{p['portid']}/{p['protocol']}  open  {p['service_name']}")
        lines.append(f"|     Product: {p['product']} {p['service_version']}{extrainfo}")
        if p.get("cpe"):
            lines.append(f"|_    CPE: {p['cpe'][0]}")
    lines.append("")
    lines.append("LIVE_HOSTS:")
    lines.append(f"- {host.ip}")
    return "\n".join(lines)


def _make_raw_vuln_scan(host: _HostSpec) -> str:
    lines = [
        f"COMMAND: nmap --script vuln -sV {host.ip} -oX ...",
        "OUTPUT:",
        f"Nmap scan report for {host.hostname} ({host.ip})",
        "Host is up (0.00xxs latency).",
    ]
    for p in host.ports:
        lines.append(f"{p['portid']}/{p['protocol']}  open  {p['service_name']}")
    if host.vuln_script_output:
        lines.append(host.vuln_script_output)
    lines.append("")
    lines.append("LIVE_HOSTS:")
    lines.append(f"- {host.ip}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# XML generators (for structured parsing)
# ---------------------------------------------------------------------------

def _escape_xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _host_xml(host: _HostSpec) -> str:
    ports_xml: list[str] = []
    for p in host.ports:
        service_attrs: list[str] = []
        if p.get("product"):
            service_attrs.append(f'product="{_escape_xml(p["product"])}"')
        if p.get("service_version"):
            service_attrs.append(f'version="{_escape_xml(p["service_version"])}"')
        if p.get("extrainfo"):
            service_attrs.append(f'extrainfo="{_escape_xml(p["extrainfo"])}"')
        cpe_xml = "".join(
            f'<cpe>{_escape_xml(c)}</cpe>' for c in p.get("cpe", [])
        )
        attr_str = (" " + " ".join(service_attrs)) if service_attrs else ""
        ports_xml.append(
            f'<port protocol="{_escape_xml(p["protocol"])}" portid="{_escape_xml(p["portid"])}">'
            f'<state state="{_escape_xml(p["state"])}"/>'
            f'<service name="{_escape_xml(p["service_name"])}"{attr_str}>{cpe_xml}</service>'
            f'</port>'
        )
    ports_block = f"<ports>{''.join(ports_xml)}</ports>" if ports_xml else "<ports/>"
    os_block = ""
    if host.os_name:
        os_block = (
            f'<os><osmatch name="{_escape_xml(host.os_name)}" accuracy="{host.os_accuracy}"/>'
            f'</os>'
        )
    hostname_block = ""
    if host.hostname:
        hostname_block = (
            f'<hosthint><hostname name="{_escape_xml(host.hostname)}" type="PTR"/></hosthint>'
        )
    return (
        f"<host>"
        f'<status state="up" reason="arp-response"/>'
        f'<address addr="{_escape_xml(host.ip)}" addrtype="ipv4"/>'
        f"{hostname_block}"
        f"{ports_block}"
        f"{os_block}"
        f"</host>"
    )


def _build_xml(hosts: list[_HostSpec]) -> str:
    body = "".join(_host_xml(h) for h in hosts)
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<nmaprun scanner="nmap" args="demo">'
        f'{body}'
        f'<runstats><finished time="0" timestr="demo"/>'
        f'<hosts up="{len(hosts)}" down="0" total="{len(hosts)}"/>'
        f'</runstats></nmaprun>'
    )


# ---------------------------------------------------------------------------
# Search / CVE fake responses
# ---------------------------------------------------------------------------

def _make_search_response(query: str) -> str:
    q = query.lower()
    responses: dict[str, str] = {
        "apache httpd 2.4.49": (
            "CVE-2021-41773: Path traversal and file disclosure in Apache HTTP Server 2.4.49. "
            "An attacker could use a path traversal attack to map URLs to files outside the expected document root. "
            "CVSS 7.5 (HIGH). Remediation: upgrade to 2.4.50 or later."
        ),
        "apache httpd": (
            "CVE-2021-41773 and CVE-2021-42013 affect Apache HTTP Server 2.4.49. Path traversal and RCE possible. "
            "Fix: upgrade to latest stable release."
        ),
        "busybox telnetd": (
            "BusyBox telnetd historically lacks encryption and strong authentication. "
            "Replace with SSH and disable telnet entirely."
        ),
        "openwrt 19.07": (
            "OpenWrt 19.07 reached end-of-life in 2021. No security updates are provided. "
            "Upgrade to a supported release (e.g., 23.05 or later)."
        ),
        "mysql 5.7.33": (
            "MySQL 5.7.33 is an older release. Check Oracle CPU for recent patches. "
            "CVE-2021-2144 (CVSS 6.5) and CVE-2021-2170 are known for 5.7.x. "
            "Enforce strong auth and disable remote root access."
        ),
        "mysql 5.7": (
            "MySQL 5.7 has known vulnerabilities. Always enforce password policies. "
            "CVE-2021-2144: InnoDB corruption issues."
        ),
        "microsoft smbv1": (
            "SMBv1 is deprecated and has multiple critical vulnerabilities (MS17-010/EternalBlue). "
            "Disable SMBv1 via PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol."
        ),
        "microsoft windows server 2008 r2": (
            "Windows Server 2008 R2 is end-of-life. No security patches. "
            "Strongly recommend migration. MS17-010 (EternalBlue) is unpatched if updates stopped."
        ),
        "rdp nla": (
            "RDP without NLA exposes the server to brute-force before session creation. "
            "Enable Network Level Authentication (NLA) via Group Policy."
        ),
        "hikvision embedded web server": (
            "CVE-2017-7921: Hikvision backdoor allows unauthenticated retrieval of user config including passwords. "
            "Change default admin/root account and update firmware."
        ),
        "hikvision ip camera": (
            "CVE-2017-7921 affects Hikvision IP cameras with firmware before V5.5.0. "
            "Recommend firmware update and strong passwords."
        ),
        "tomcat coyote 1.1": (
            "Apache Tomcat should be kept patched. Common issues include default creds and exposed manager. "
            "Check for CVE-2022-34305 and CVE-2022-42252."
        ),
    }
    # Try exact matches first, then substring
    for key, value in responses.items():
        if key in q:
            return value
    return f"Intel: {query} -- review latest vendor advisories for known CVEs."


def _make_cve_response(query: str) -> str:
    q = query.lower()
    if "apache httpd 2.4.49" in q:
        return (
            "CVE-2021-41773 | CVSS 7.5 | HIGH\n"
            "Summary: Path traversal and file disclosure in Apache HTTP Server 2.4.49.\n"
            "Remediation: Upgrade to Apache HTTP Server >= 2.4.50.\n"
            "References: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773"
        )
    if "mysql 5.7.33" in q or "mysql 5.7" in q:
        return (
            "CVE-2021-2144 | CVSS 6.5 | MEDIUM\n"
            "Summary: MySQL InnoDB denial of service / data corruption.\n"
            "Remediation: Apply latest Oracle Critical Patch Update or upgrade to MySQL 8.0.\n"
            "References: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2144"
        )
    if "windows server 2008" in q or "smbv1" in q or "microsoft smb" in q:
        return (
            "CVE-2017-0144 | CVSS 8.1 | HIGH\n"
            "Summary: EternalBlue / MS17-010 remote code execution in SMBv1.\n"
            "Remediation: Disable SMBv1, apply MS17-010, or upgrade OS.\n"
            "References: https://technet.microsoft.com/en-us/library/security/ms17-010.aspx"
        )
    if "hikvision" in q:
        return (
            "CVE-2017-7921 | CVSS 8.1 | HIGH\n"
            "Summary: Hikvision IP camera undocumented command to retrieve user config/passwords.\n"
            "Remediation: Update firmware, change defaults, firewall camera from WAN.\n"
            "References: https://www.exploit-db.com/exploits/45233/"
        )
    return (
        f"CVE search result for {query}: no direct match in demo data. "
        f"Check NVD for latest entries."
    )


# ---------------------------------------------------------------------------
# Public lookup helpers
# ---------------------------------------------------------------------------

def get_demo_host(ip: str) -> _HostSpec | None:
    for h in _ALL_HOSTS:
        if h.ip == ip:
            return h
    return None


def raw_ping_sweep() -> str:
    return _make_raw_ping_sweep()


def raw_triage_scan() -> str:
    return _make_raw_triage_scan()


def raw_basic_scan(ip: str) -> str:
    host = get_demo_host(ip)
    if not host:
        return f"COMMAND: nmap -sV --top-ports 1000 {ip} -oX ...\nOUTPUT:\nNote: Host seems down."
    return _make_raw_basic_scan(host)


def raw_service_scan(ip: str) -> str:
    host = get_demo_host(ip)
    if not host:
        return f"COMMAND: nmap -sV -sC -O {ip} -oX ...\nOUTPUT:\nNote: Host seems down."
    return _make_raw_service_scan(host)


def raw_vuln_scan(ip: str) -> str:
    host = get_demo_host(ip)
    if not host:
        return f"COMMAND: nmap --script vuln -sV {ip} -oX ...\nOUTPUT:\nNote: Host seems down."
    return _make_raw_vuln_scan(host)


def search_intel(query: str) -> str:
    return _make_search_response(query)


def cve_intel(query: str) -> str:
    return _make_cve_response(query)


def raw_terminal(command: str) -> str:
    return f"COMMAND: {command}\nOUTPUT:\nDEMO: Simulated terminal output. No real command executed."


def nmap_xml_for_scan(scan_name: str) -> str:
    """Return XML matching scan_name, or generic XML."""
    if scan_name in ("10.0.0.0_24_ping_sweep", "10.0.0.0/24_ping_sweep"):
        return _build_xml(_ALL_HOSTS)
    if "triage" in scan_name.lower():
        return _build_xml(_ALL_HOSTS)
    for host in _ALL_HOSTS:
        if host.ip in scan_name:
            return _build_xml([host])
    return _build_xml(_ALL_HOSTS)


def nmap_xml_for_all() -> str:
    """Return full XML for all demo hosts."""
    return _build_xml(_ALL_HOSTS)


# ---------------------------------------------------------------------------
# Pre-baked sub-agent findings (injected directly in demo mode)
# ---------------------------------------------------------------------------

def get_demo_sub_findings() -> list[Any]:
    """Return list of StructuredFinding-like dicts for demo mode."""
    return [
        {
            "risk_level": "critical",
            "title": "Telnet exposed with default credentials and outdated firmware",
            "open_ports": [
                {"port": "23/tcp", "service": "telnet", "version": "BusyBox telnetd 1.30.1"},
                {"port": "80/tcp", "service": "http", "version": "uHTTPd 1.0"},
            ],
            "evidence": (
                "Gateway 10.0.0.1 exposes telnet (23/tcp) with no encryption and no strong authentication. "
                "OpenWrt 19.07 firmware is end-of-life, no longer receiving security patches."
            ),
            "severity_reason": "Unencrypted management protocol and unsupported firmware create direct attack surface.",
            "remediation": (
                "Disable telnet. Upgrade OpenWrt to a supported release (23.05+). "
                "Restrict admin access to HTTPS on a dedicated management interface."
            ),
            "services_researched": ["BusyBox telnetd 1.30.1", "uHTTPd 1.0"],
            "host": "10.0.0.1",
            "cves_found": ["CVE placeholder"],
            "active_checks": [],
        },
        {
            "risk_level": "high",
            "title": "Apache HTTPD 2.4.49 path traversal (CVE-2021-41773)",
            "open_ports": [
                {"port": "22/tcp", "service": "ssh", "version": "OpenSSH 8.2p1"},
                {"port": "80/tcp", "service": "http", "version": "Apache httpd 2.4.49"},
                {"port": "443/tcp", "service": "https", "version": "Apache httpd 2.4.49"},
                {"port": "8080/tcp", "service": "http-proxy", "version": "Apache Tomcat/Coyote 1.1"},
            ],
            "evidence": (
                "Web server 10.0.0.10 runs Apache 2.4.49, confirmed vulnerable to path traversal via CVE-2021-41773. "
                "Vuln scan output documented vulnerable state. Possible .git and phpinfo exposure observed."
            ),
            "severity_reason": "Confirmed high-severity CVE with direct authentication bypass/data disclosure impact.",
            "remediation": (
                "Upgrade Apache to >= 2.4.50 immediately. Remove .git and phpinfo.php from web roots. "
                "Enable WAF rules for traversal patterns."
            ),
            "services_researched": ["Apache httpd 2.4.49", "OpenSSH 8.2p1"],
            "host": "10.0.0.10",
            "cves_found": ["CVE-2021-41773"],
            "active_checks": [],
        },
        {
            "risk_level": "high",
            "title": "MySQL 5.7.33 root account with no password",
            "open_ports": [
                {"port": "3306/tcp", "service": "mysql", "version": "MySQL 5.7.33"},
            ],
            "evidence": (
                "Database host 10.0.0.20 exposes MySQL 5.7.33 with root@localhost having no password. "
                "Vuln scan confirmed empty-password configuration."
            ),
            "severity_reason": "Unauthenticated administrative database access allows data exfiltration and modification.",
            "remediation": (
                "Set a strong root password. Disable remote root login. Bind MySQL to localhost only. "
                "Upgrade to MySQL 8.0 or later for improved authentication defaults."
            ),
            "services_researched": ["MySQL 5.7.33"],
            "host": "10.0.0.20",
            "cves_found": ["CVE-2021-2144"],
            "active_checks": [],
        },
        {
            "risk_level": "critical",
            "title": "SMBv1 enabled - EternalBlue/MS17-010 (CVE-2017-0144)",
            "open_ports": [
                {"port": "139/tcp", "service": "netbios-ssn", "version": "Microsoft Windows netbios-ssn"},
                {"port": "445/tcp", "service": "microsoft-ds", "version": "Microsoft Windows Server 2008 R2"},
                {"port": "3389/tcp", "service": "ms-wbt-server", "version": "Microsoft Terminal Services"},
            ],
            "evidence": (
                "Workstation 10.0.0.30 has SMBv1 dialect enabled. NSE vuln scan confirmed MS17-010 vulnerability. "
                "RDP NLA is not enforced."
            ),
            "severity_reason": "Confirmed EternalBlue RCE with easy exploitability and wormable behavior.",
            "remediation": (
                "Disable SMBv1 immediately. Patch with MS17-010 if OS cannot be upgraded. "
                "Enforce NLA for all RDP connections. Migrate to a supported Windows version."
            ),
            "services_researched": ["Microsoft SMBv1", "Microsoft Terminal Services"],
            "host": "10.0.0.30",
            "cves_found": ["CVE-2017-0144"],
            "active_checks": [],
        },
        {
            "risk_level": "high",
            "title": "Hikvision IP camera backdoor and default credentials (CVE-2017-7921)",
            "open_ports": [
                {"port": "80/tcp", "service": "http", "version": "Hikvision Embedded Web Server 1.0"},
                {"port": "554/tcp", "service": "rtsp", "version": "Hikvision RTSP Server 1.0"},
            ],
            "evidence": (
                "IoT camera 10.0.0.50 uses Hikvision firmware with undocumented backdoor command (CVE-2017-7921). "
                "Default credentials (admin:12345) are active. RTSP stream accessible without authentication."
            ),
            "severity_reason": "Backdoor and default creds allow full device compromise and video feed access.",
            "remediation": (
                "Update firmware to latest Hikvision release. Change all default passwords. "
                "Segment IoT devices on an isolated VLAN. Disable unused cloud/P2P features."
            ),
            "services_researched": ["Hikvision Embedded Web Server 1.0"],
            "host": "10.0.0.50",
            "cves_found": ["CVE-2017-7921"],
            "active_checks": [],
        },
    ]
