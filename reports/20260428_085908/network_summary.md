# Network Summary

```markdown
# Network Vulnerability Assessment Summary

**Assessment Date:** 2026-04-28  
**Assessor:** Defensive Security Team  
**Scope:** Unauthenticated network discovery and service triage

---

## Approved Subnets and Scan Scope

- **Approved Subnet:** `192.168.1.0/24`
- **Scan Type:** Unauthenticated ping sweep, TCP triage (top 100 ports), and targeted service/version detection (top 1000 ports) on selected hosts.
- **Tooling:** Nmap 7.98
- **Exclusions:** No exploit validation, brute-force testing, or authenticated host inspection was performed.

---

## Hosts Assessed

| IP Address | MAC / Vendor | Scan Coverage | Identification / Role |
|------------|--------------|---------------|-----------------------|
| 192.168.1.1 | 74:24:9F:55:BC:0E (Tibro) | Triage + Top-1000 Basic | Starlink / Gateway Router |
| 192.168.1.21 | D0:65:78:95:1B:A4 (Intel Corporate) | Triage only | Likely workstation |
| 192.168.1.68 | CC:E8:AC:BE:90:A5 (Soyea Technology) | Triage only | Unknown / embedded device |
| 192.168.1.130 | — | Triage + Top-1000 Basic | Windows host with AnyDesk |
| 192.168.1.208 | 14:EB:B6:44:E7:79 (TP-Link) | Triage only | Network appliance (Windows discovery endpoint) |

*Note: Hosts 192.168.1.21 and 192.168.1.68 had no open TCP ports during triage and were not selected for deeper scanning.*

---

## Key Risks by Severity

### Medium

#### 192.168.1.1 — Starlink Gateway: Outdated OpenSSH and Broad Management Surface
- **Evidence:**  
  - `22/tcp` — OpenSSH 8.4 (protocol 2.0)  
  - `80/tcp` — Golang `net/http` server serving a Starlink administrative web interface  
  - `9000/tcp` and `9003/tcp` — gRPC endpoints  
  - `9001/tcp` — Golang `net/http` server returning HTTP 500 errors for standard requests, suggesting insufficient error handling or input validation  
  - `9002/tcp` — TLS-encrypted service (`ssl/dynamid?`) presenting a 20-year self-signed certificate (CN=`Router-010000000000000001C5BC0E`, valid 2025-10-29 to 2045-10-29)
- **Likely Severity:** **Medium**  
  The host exposes multiple remote management protocols simultaneously. OpenSSH 8.4 is outdated and associated with publicly disclosed vulnerabilities. The presence of several HTTP/gRPC services expands the attack surface beyond what is typical for a residential gateway. A 20-year self-signed certificate indicates poor cryptographic lifecycle governance. The cumulative exposure, combined with deprecated software and weak certificate management, presents a moderate risk of unauthorized access or control if additional weaknesses are identified.
- **Remediation (Summary):**  
  Patch or upgrade OpenSSH; restrict SSH to management networks with key-based MFA; harden/restrict HTTP and gRPC services; replace the long-lived certificate with a properly managed, shorter-lived certificate; enforce host-level firewall rules limiting inbound access to management services.

### Low

#### 192.168.1.130 — Windows Host: Exposed AnyDesk Remote Access
- **Evidence:**  
  - `135/tcp` — Microsoft Windows RPC (standard)  
  - `7070/tcp` — AnyDesk remote desktop client (TLS certificate with CN=`AnyDesk Client`, self-signed, valid 2026-01-12 to 2075-12-31)
- **Likely Severity:** **Low**  
  Only two services are exposed. MSRPC is expected on a Windows host. While AnyDesk increases remote access attack surface, no known CVEs applicable to the discovered version were identified, and no misconfiguration (e.g., blank password, outdated banner) was detected. The primary risk is unauthorized or unaudited remote access tooling operating on the network.
- **Remediation (Summary):**  
  Verify business authorization for AnyDesk; remove if unauthorized; restrict `7070/tcp` to authorized administrator source IPs; enforce strong unattended-access passwords and MFA; maintain current patching.

#### 192.168.1.208 — TP-Link / Windows Device: Network Discovery Endpoint
- **Evidence:**  
  - `5357/tcp` — Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) returning HTTP `503 Service Unavailable`
- **Likely Severity:** **Low**  
  Port 5357 is used by Windows Function Discovery / WS-Discovery. The endpoint returned no active application content, and no CVEs for Microsoft HTTPAPI 2.0 were identified during this assessment. The risk of direct compromise is minimal, though the port confirms a Windows operating system and a discoverable network presence.
- **Remediation (Summary):**  
  If network discovery is not required, disable the `fdPHost` and `fdResPub` services or block inbound `5357/tcp` at the host/network firewall. If required, restrict to trusted local subnets.

---

## Final Prioritized Remediation List

### 1. Harden the Starlink Gateway (192.168.1.1) — Priority: High
1. **Upgrade OpenSSH:** Update the router’s SSH service to the latest vendor-supported or upstream stable release to address known deficiencies in OpenSSH 8.4.
2. **Restrict Remote Login:** Limit `22/tcp` to dedicated management network segments only. Disable password authentication; enforce key-based authentication with multi-factor authentication (MFA) where supported.
3. **Reduce Web / gRPC Exposure:** Review the necessity of services on ports `80`, `9000`, `9001`, and `9003`. Disable any non-essential management interfaces. If required, implement strict ingress filtering, proper input validation, and robust error handling (especially for the HTTP 500 behavior observed on `9001/tcp`).
4. **Replace Long-Lived Certificate:** Investigate the service on `9002/tcp`. Replace the 20-year self-signed certificate with a properly managed PKI certificate (e.g., via an internal CA or vendor-issued cert) with a standard validity period. Enforce strong TLS versions and cipher suites.
5. **Enable Host / Edge Firewalling:** Ensure the device’s built-in firewall denies unauthorized inbound connections to all management services from untrusted subnets.

### 2. Audit Remote Access on Windows Host (192.168.1.130) — Priority: Medium
1. **Authorize or Remove AnyDesk:** Confirm whether AnyDesk is approved for business use. If unauthorized, uninstall it immediately.
2. **Network Segregation:** Restrict inbound access to `7070/tcp` via host firewall or network ACLs to authorized administrator IP ranges only.
3. **Harden AnyDesk Configuration:** Update to the latest stable version; disable unattended access if not required; if required, configure complex access passwords and enable two-factor authentication.
4. **Continue OS Hardening:** Apply standard Windows patching and maintain RPC baseline hardening per organizational policy.

### 3. Reduce Discovery Footprint on 192.168.1.208 — Priority: Low
1. **Disable Unnecessary Services:** Turn off Windows Function Discovery services (`fdPHost`, `fdResPub`) if not required for domain or local network functionality.
2. **Apply Firewall Restrictions:** Block or restrict inbound `5357/tcp` to trusted local subnets.

### 4. Improve Visibility and Coverage — Priority: Ongoing
1. **Full-Port Scanning:** Conduct full-port (`-p-`) scans on all live hosts during a maintenance window to identify services running outside the top 1000 ports.
2. **Authenticated Auditing:** Perform authenticated patch and configuration audits on Windows endpoints (e.g., `192.168.1.130`, `192.168.1.208`) to detect missing OS updates, insecure local policies, and unauthorized software.
3. **Inventory Silent Hosts:** Review `192.168.1.21` and `192.168.1.68` via host-based inventory or authenticated assessment, as they exposed no TCP services during network triage but may still present risk via UDP, passive protocols, or outbound behavior.

---

## Notes on Limitations

- **Scan Depth:** Triage was limited to the top 100 TCP ports. Deeper inspection was performed only on two selected hosts and was limited to the top 1000 TCP ports. Services on high/ephemeral ports, UDP ports, and ICMP-responsive devices may have been missed.
- **Host Selection:** `192.168.1.21` and `192.168.1.68` were not selected for deeper scanning because no open TCP ports were observed during triage. This does not guarantee they are free of vulnerability.
- **Unauthenticated Only:** This assessment was conducted entirely from the network without credentials. Patch levels, local security policy, malware presence, and account hygiene were not evaluated.
- **Vulnerability Script Coverage:** The Nmap vulnerability script scan against `192.168.1.1` timed out and did not complete, leaving potential script-detectable misconfigurations unverified.
- **Service Fingerprinting:** Several services returned ambiguous fingerprints (e.g., `ssl/dynamid?` on `9002/tcp`, `ssl/realserver?` on `7070/tcp`). Version detection was based on banner and certificate data; exact build numbers were not obtained, limiting precise CVE correlation.
- **No Exploit Validation:** Risk ratings are derived from exposure analysis, service behavior, and version intelligence. No exploitation or proof-of-concept testing was performed to confirm exploitability.
```
