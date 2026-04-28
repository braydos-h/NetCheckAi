# Host 192.168.1.130

**Risk Level:** LOW

**Title:** Windows host with RPC and exposed AnyDesk remote access on port 7070

## Open Ports

- 135/tcp: msrpc Microsoft Windows RPC
- 7070/tcp: ssl/anydesk AnyDesk Client

## Evidence
Nmap basic and service scans identified Microsoft Windows RPC on port 135/tcp. On port 7070/tcp, Nmap reported ssl/realserver? but the aggressive scan extracted an SSL certificate with Subject commonName=AnyDesk Client (self-signed, valid 2026-01-12 to 2075-12-31). The Nmap vuln scan did not identify any script-detectable vulnerabilities on either port.

## Severity Reason
Only two services are exposed. Port 135/tcp is standard Windows RPC and is normal for a Windows host. Port 7070/tcp is running AnyDesk remote desktop software, which increases remote attack surface, but no known vulnerabilities, misconfigurations, or outdated versions were detected during scanning. Without additional indicators such as weak credentials, unauthorized software, or known CVEs applicable to the discovered versions, the overall risk remains low.

## Remediation
1) Verify whether AnyDesk is authorized on this host; if unauthorized, remove it immediately. 2) If AnyDesk is required, restrict inbound access to port 7070/tcp via host firewall or network ACLs to authorized administrator IPs only. 3) Ensure AnyDesk is updated to the latest stable version and configure strong unattended-access passwords with two-factor authentication. 4) Continue standard Windows patching and monitor RPC-related exposure per organizational hardening baselines.

## Services Researched
- Microsoft Windows RPC
- AnyDesk Client
