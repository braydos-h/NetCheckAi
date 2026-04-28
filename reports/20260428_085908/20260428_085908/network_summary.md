# Network Assessment Report

**Run ID:** 20260428_085908
**Scope:** 192.168.1.0/24
**Generated:** 2026-04-28T09:12:21.908442Z

## Findings Summary
- **Total:** 26

## Detailed Findings

### ssh on 22/tcp
- **Severity:** LOW
- **Host:** 192.168.1.1
- **Port:** 22/tcp
- **Service:** ssh
- **Confidence:** confirmed
- **Evidence:** Port 22/tcp is open; Service: ssh; Product: OpenSSH; Version: 8.4; Extra: protocol 2.0; Risk indicator: remote login surface
- **CPE:** cpe:/a:openbsd:openssh:8.4
- **Remediation:** Use key-based auth; disable root login; keep OpenSSH updated.
- **Next Scan Recommended:** Consider ssh-audit or version-specific CVE lookup.

### ssh on 22/tcp
- **Severity:** LOW
- **Host:** 192.168.1.1
- **Port:** 22/tcp
- **Service:** ssh
- **Confidence:** confirmed
- **Evidence:** Port 22/tcp is open; Service: ssh; Product: OpenSSH; Version: 8.4; Extra: protocol 2.0; Risk indicator: remote login surface
- **CPE:** cpe:/a:openbsd:openssh:8.4
- **Remediation:** Use key-based auth; disable root login; keep OpenSSH updated.
- **Next Scan Recommended:** Consider ssh-audit or version-specific CVE lookup.

### http on 80/tcp
- **Severity:** LOW
- **Host:** 192.168.1.1
- **Port:** 80/tcp
- **Service:** http
- **Confidence:** likely
- **Evidence:** Port 80/tcp is open; Service: http; Product: Golang net/http server; Risk indicator: web surface
- **CPE:** cpe:/a:golang:go
- **Remediation:** Keep software updated; remove default credentials; audit exposed paths.
- **Next Scan Recommended:** Consider --script http-enum,http-vuln-* or manual app scan.

### http on 80/tcp
- **Severity:** LOW
- **Host:** 192.168.1.1
- **Port:** 80/tcp
- **Service:** http
- **Confidence:** likely
- **Evidence:** Port 80/tcp is open; Service: http; Product: Golang net/http server; Risk indicator: web surface
- **CPE:** cpe:/a:golang:go
- **Remediation:** Keep software updated; remove default credentials; audit exposed paths.
- **Next Scan Recommended:** Consider --script http-enum,http-vuln-* or manual app scan.

### http on 9001/tcp
- **Severity:** LOW
- **Host:** 192.168.1.1
- **Port:** 9001/tcp
- **Service:** http
- **Confidence:** likely
- **Evidence:** Port 9001/tcp is open; Service: http; Product: Golang net/http server; Risk indicator: web surface
- **CPE:** cpe:/a:golang:go
- **Remediation:** Keep software updated; remove default credentials; audit exposed paths.
- **Next Scan Recommended:** Consider --script http-enum,http-vuln-* or manual app scan.

### http on 5357/tcp
- **Severity:** LOW
- **Host:** 192.168.1.208
- **Port:** 5357/tcp
- **Service:** http
- **Confidence:** confirmed
- **Evidence:** Port 5357/tcp is open; Service: http; Product: Microsoft HTTPAPI httpd; Version: 2.0; Extra: SSDP/UPnP; Risk indicator: web surface
- **CPE:** cpe:/o:microsoft:windows
- **Remediation:** Keep software updated; remove default credentials; audit exposed paths.
- **Next Scan Recommended:** Consider --script http-enum,http-vuln-* or manual app scan.

### http on 5357/tcp
- **Severity:** LOW
- **Host:** 192.168.1.208
- **Port:** 5357/tcp
- **Service:** http
- **Confidence:** confirmed
- **Evidence:** Port 5357/tcp is open; Service: http; Product: Microsoft HTTPAPI httpd; Version: 2.0; Extra: SSDP/UPnP; Risk indicator: web surface
- **CPE:** cpe:/o:microsoft:windows
- **Remediation:** Keep software updated; remove default credentials; audit exposed paths.
- **Next Scan Recommended:** Consider --script http-enum,http-vuln-* or manual app scan.

### http on 5357/tcp
- **Severity:** LOW
- **Host:** 192.168.1.208
- **Port:** 5357/tcp
- **Service:** http
- **Confidence:** confirmed
- **Evidence:** Port 5357/tcp is open; Service: http; Product: Microsoft HTTPAPI httpd; Version: 2.0; Extra: SSDP/UPnP; Risk indicator: web surface
- **CPE:** cpe:/o:microsoft:windows
- **Remediation:** Keep software updated; remove default credentials; audit exposed paths.
- **Next Scan Recommended:** Consider --script http-enum,http-vuln-* or manual app scan.

### grpc on 9000/tcp
- **Severity:** INFO
- **Host:** 192.168.1.1
- **Port:** 9000/tcp
- **Service:** grpc
- **Confidence:** likely
- **Evidence:** Port 9000/tcp is open; Service: grpc; Risk indicator: open port
- **Remediation:** Review necessity; restrict by firewall; apply vendor patches.

### dynamid on 9002/tcp
- **Severity:** INFO
- **Host:** 192.168.1.1
- **Port:** 9002/tcp
- **Service:** dynamid
- **Confidence:** likely
- **Evidence:** Port 9002/tcp is open; Service: dynamid; Risk indicator: open port
- **Remediation:** Review necessity; restrict by firewall; apply vendor patches.

### grpc on 9003/tcp
- **Severity:** INFO
- **Host:** 192.168.1.1
- **Port:** 9003/tcp
- **Service:** grpc
- **Confidence:** likely
- **Evidence:** Port 9003/tcp is open; Service: grpc; Risk indicator: open port
- **Remediation:** Review necessity; restrict by firewall; apply vendor patches.

### msrpc on 135/tcp
- **Severity:** INFO
- **Host:** 192.168.1.130
- **Port:** 135/tcp
- **Service:** msrpc
- **Confidence:** likely
- **Evidence:** Port 135/tcp is open; Service: msrpc; Product: Microsoft Windows RPC; Risk indicator: open port
- **CPE:** cpe:/o:microsoft:windows
- **Remediation:** Review necessity; restrict by firewall; apply vendor patches.

### msrpc on 135/tcp
- **Severity:** INFO
- **Host:** 192.168.1.130
- **Port:** 135/tcp
- **Service:** msrpc
- **Confidence:** likely
- **Evidence:** Port 135/tcp is open; Service: msrpc; Product: Microsoft Windows RPC; Risk indicator: open port
- **CPE:** cpe:/o:microsoft:windows
- **Remediation:** Review necessity; restrict by firewall; apply vendor patches.

### msrpc on 135/tcp
- **Severity:** INFO
- **Host:** 192.168.1.130
- **Port:** 135/tcp
- **Service:** msrpc
- **Confidence:** likely
- **Evidence:** Port 135/tcp is open; Service: msrpc; Product: Microsoft Windows RPC; Risk indicator: open port
- **CPE:** cpe:/o:microsoft:windows
- **Remediation:** Review necessity; restrict by firewall; apply vendor patches.

### realserver on 7070/tcp
- **Severity:** INFO
- **Host:** 192.168.1.130
- **Port:** 7070/tcp
- **Service:** realserver
- **Confidence:** likely
- **Evidence:** Port 7070/tcp is open; Service: realserver; Risk indicator: open port
- **Remediation:** Review necessity; restrict by firewall; apply vendor patches.

### realserver on 7070/tcp
- **Severity:** INFO
- **Host:** 192.168.1.130
- **Port:** 7070/tcp
- **Service:** realserver
- **Confidence:** likely
- **Evidence:** Port 7070/tcp is open; Service: realserver; Risk indicator: open port
- **Remediation:** Review necessity; restrict by firewall; apply vendor patches.

### realserver on 7070/tcp
- **Severity:** INFO
- **Host:** 192.168.1.130
- **Port:** 7070/tcp
- **Service:** realserver
- **Confidence:** likely
- **Evidence:** Port 7070/tcp is open; Service: realserver; Risk indicator: open port
- **Remediation:** Review necessity; restrict by firewall; apply vendor patches.

### Starlink Router with Multiple Exposed Services and Outdated OpenSSH
- **Severity:** MEDIUM
- **Host:** 192.168.1.1
- **Port:** 22/tcp
- **Service:** ssh
- **Confidence:** likely
- **Evidence:** Nmap service scan found OpenSSH 8.4 on 22/tcp, a Golang net/http server on 80/tcp serving a Starlink web interface (title: Starlink), grpc on 9000/tcp and 9003/tcp, another Golang HTTP server on 9001/tcp returning HTTP 500 errors for most requests, and an ssl/dynamid service on 9002/tcp presenting a TLS certificate for a SpaceX router (CN=Router-010000000000000001C5BC0E) valid from 2025-10-29 to 2045-10-29. OS fingerprinting suggests Linux. The Nmap vulnerability script scan timed out and did not complete.
- **Remediation:** 1) Upgrade OpenSSH to the latest stable/vendor-patched release. 2) Restrict SSH to management networks and enforce key-based authentication with MFA. 3) Harden Golang HTTP services on ports 80 and 9001; implement proper error handling, input validation, and access controls. 4) Restrict gRPC on 9000/9003 to authorized clients and enable TLS with strong authentication. 5) Investigate the ssl/dynamid service on 9002; disable if unnecessary, otherwise replace the long-lived certificate with a properly managed PKI cert and enforce strong cipher suites. 6) Apply regular vulnerability scanning and patch management. 7) Use host-based firewall rules to limit exposure of management services.

### Starlink Router with Multiple Exposed Services and Outdated OpenSSH
- **Severity:** MEDIUM
- **Host:** 192.168.1.1
- **Port:** 80/tcp
- **Service:** http
- **Confidence:** likely
- **Evidence:** Nmap service scan found OpenSSH 8.4 on 22/tcp, a Golang net/http server on 80/tcp serving a Starlink web interface (title: Starlink), grpc on 9000/tcp and 9003/tcp, another Golang HTTP server on 9001/tcp returning HTTP 500 errors for most requests, and an ssl/dynamid service on 9002/tcp presenting a TLS certificate for a SpaceX router (CN=Router-010000000000000001C5BC0E) valid from 2025-10-29 to 2045-10-29. OS fingerprinting suggests Linux. The Nmap vulnerability script scan timed out and did not complete.
- **Remediation:** 1) Upgrade OpenSSH to the latest stable/vendor-patched release. 2) Restrict SSH to management networks and enforce key-based authentication with MFA. 3) Harden Golang HTTP services on ports 80 and 9001; implement proper error handling, input validation, and access controls. 4) Restrict gRPC on 9000/9003 to authorized clients and enable TLS with strong authentication. 5) Investigate the ssl/dynamid service on 9002; disable if unnecessary, otherwise replace the long-lived certificate with a properly managed PKI cert and enforce strong cipher suites. 6) Apply regular vulnerability scanning and patch management. 7) Use host-based firewall rules to limit exposure of management services.

### Starlink Router with Multiple Exposed Services and Outdated OpenSSH
- **Severity:** MEDIUM
- **Host:** 192.168.1.1
- **Port:** 9000/tcp
- **Service:** grpc
- **Confidence:** likely
- **Evidence:** Nmap service scan found OpenSSH 8.4 on 22/tcp, a Golang net/http server on 80/tcp serving a Starlink web interface (title: Starlink), grpc on 9000/tcp and 9003/tcp, another Golang HTTP server on 9001/tcp returning HTTP 500 errors for most requests, and an ssl/dynamid service on 9002/tcp presenting a TLS certificate for a SpaceX router (CN=Router-010000000000000001C5BC0E) valid from 2025-10-29 to 2045-10-29. OS fingerprinting suggests Linux. The Nmap vulnerability script scan timed out and did not complete.
- **Remediation:** 1) Upgrade OpenSSH to the latest stable/vendor-patched release. 2) Restrict SSH to management networks and enforce key-based authentication with MFA. 3) Harden Golang HTTP services on ports 80 and 9001; implement proper error handling, input validation, and access controls. 4) Restrict gRPC on 9000/9003 to authorized clients and enable TLS with strong authentication. 5) Investigate the ssl/dynamid service on 9002; disable if unnecessary, otherwise replace the long-lived certificate with a properly managed PKI cert and enforce strong cipher suites. 6) Apply regular vulnerability scanning and patch management. 7) Use host-based firewall rules to limit exposure of management services.

### Starlink Router with Multiple Exposed Services and Outdated OpenSSH
- **Severity:** MEDIUM
- **Host:** 192.168.1.1
- **Port:** 9001/tcp
- **Service:** http
- **Confidence:** likely
- **Evidence:** Nmap service scan found OpenSSH 8.4 on 22/tcp, a Golang net/http server on 80/tcp serving a Starlink web interface (title: Starlink), grpc on 9000/tcp and 9003/tcp, another Golang HTTP server on 9001/tcp returning HTTP 500 errors for most requests, and an ssl/dynamid service on 9002/tcp presenting a TLS certificate for a SpaceX router (CN=Router-010000000000000001C5BC0E) valid from 2025-10-29 to 2045-10-29. OS fingerprinting suggests Linux. The Nmap vulnerability script scan timed out and did not complete.
- **Remediation:** 1) Upgrade OpenSSH to the latest stable/vendor-patched release. 2) Restrict SSH to management networks and enforce key-based authentication with MFA. 3) Harden Golang HTTP services on ports 80 and 9001; implement proper error handling, input validation, and access controls. 4) Restrict gRPC on 9000/9003 to authorized clients and enable TLS with strong authentication. 5) Investigate the ssl/dynamid service on 9002; disable if unnecessary, otherwise replace the long-lived certificate with a properly managed PKI cert and enforce strong cipher suites. 6) Apply regular vulnerability scanning and patch management. 7) Use host-based firewall rules to limit exposure of management services.

### Starlink Router with Multiple Exposed Services and Outdated OpenSSH
- **Severity:** MEDIUM
- **Host:** 192.168.1.1
- **Port:** 9002/tcp
- **Service:** ssl/dynamid?
- **Confidence:** likely
- **Evidence:** Nmap service scan found OpenSSH 8.4 on 22/tcp, a Golang net/http server on 80/tcp serving a Starlink web interface (title: Starlink), grpc on 9000/tcp and 9003/tcp, another Golang HTTP server on 9001/tcp returning HTTP 500 errors for most requests, and an ssl/dynamid service on 9002/tcp presenting a TLS certificate for a SpaceX router (CN=Router-010000000000000001C5BC0E) valid from 2025-10-29 to 2045-10-29. OS fingerprinting suggests Linux. The Nmap vulnerability script scan timed out and did not complete.
- **Remediation:** 1) Upgrade OpenSSH to the latest stable/vendor-patched release. 2) Restrict SSH to management networks and enforce key-based authentication with MFA. 3) Harden Golang HTTP services on ports 80 and 9001; implement proper error handling, input validation, and access controls. 4) Restrict gRPC on 9000/9003 to authorized clients and enable TLS with strong authentication. 5) Investigate the ssl/dynamid service on 9002; disable if unnecessary, otherwise replace the long-lived certificate with a properly managed PKI cert and enforce strong cipher suites. 6) Apply regular vulnerability scanning and patch management. 7) Use host-based firewall rules to limit exposure of management services.

### Starlink Router with Multiple Exposed Services and Outdated OpenSSH
- **Severity:** MEDIUM
- **Host:** 192.168.1.1
- **Port:** 9003/tcp
- **Service:** grpc
- **Confidence:** likely
- **Evidence:** Nmap service scan found OpenSSH 8.4 on 22/tcp, a Golang net/http server on 80/tcp serving a Starlink web interface (title: Starlink), grpc on 9000/tcp and 9003/tcp, another Golang HTTP server on 9001/tcp returning HTTP 500 errors for most requests, and an ssl/dynamid service on 9002/tcp presenting a TLS certificate for a SpaceX router (CN=Router-010000000000000001C5BC0E) valid from 2025-10-29 to 2045-10-29. OS fingerprinting suggests Linux. The Nmap vulnerability script scan timed out and did not complete.
- **Remediation:** 1) Upgrade OpenSSH to the latest stable/vendor-patched release. 2) Restrict SSH to management networks and enforce key-based authentication with MFA. 3) Harden Golang HTTP services on ports 80 and 9001; implement proper error handling, input validation, and access controls. 4) Restrict gRPC on 9000/9003 to authorized clients and enable TLS with strong authentication. 5) Investigate the ssl/dynamid service on 9002; disable if unnecessary, otherwise replace the long-lived certificate with a properly managed PKI cert and enforce strong cipher suites. 6) Apply regular vulnerability scanning and patch management. 7) Use host-based firewall rules to limit exposure of management services.

### Exposed Windows Network Discovery HTTP Service (HTTPAPI/2.0) on TCP 5357
- **Severity:** LOW
- **Host:** 192.168.1.208
- **Port:** 5357/tcp
- **Service:** http
- **Confidence:** likely
- **Evidence:** Nmap basic, service, and vulnerability scans identified a single open port 5357/tcp running Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP). The service returns HTTP title 'Service Unavailable' and server header 'Microsoft-HTTPAPI/2.0'. OS fingerprinting suggests a modern Windows OS (10/11/Server 2019). Nmap vulnerability scripts (http-csrf, http-dombased-xss, http-stored-xss) found no web vulnerabilities. No CVEs were found in NVD for 'Microsoft HTTPAPI 2.0'. All other ports are filtered.
- **Remediation:** If network discovery is not required, disable the 'Function Discovery Provider Host' (fdPHost) and 'Function Discovery Resource Publication' (fdResPub) services, or block inbound TCP 5357 via the host/network firewall. If network discovery is required, restrict access to trusted local subnets and ensure the system is fully patched. Verify that no additional services register with HTTPAPI on this port.

### Windows host with RPC and exposed AnyDesk remote access on port 7070
- **Severity:** LOW
- **Host:** 192.168.1.130
- **Port:** 135/tcp
- **Service:** msrpc
- **Confidence:** likely
- **Evidence:** Nmap basic and service scans identified Microsoft Windows RPC on port 135/tcp. On port 7070/tcp, Nmap reported ssl/realserver? but the aggressive scan extracted an SSL certificate with Subject commonName=AnyDesk Client (self-signed, valid 2026-01-12 to 2075-12-31). The Nmap vuln scan did not identify any script-detectable vulnerabilities on either port.
- **Remediation:** 1) Verify whether AnyDesk is authorized on this host; if unauthorized, remove it immediately. 2) If AnyDesk is required, restrict inbound access to port 7070/tcp via host firewall or network ACLs to authorized administrator IPs only. 3) Ensure AnyDesk is updated to the latest stable version and configure strong unattended-access passwords with two-factor authentication. 4) Continue standard Windows patching and monitor RPC-related exposure per organizational hardening baselines.

### Windows host with RPC and exposed AnyDesk remote access on port 7070
- **Severity:** LOW
- **Host:** 192.168.1.130
- **Port:** 7070/tcp
- **Service:** ssl/anydesk
- **Confidence:** likely
- **Evidence:** Nmap basic and service scans identified Microsoft Windows RPC on port 135/tcp. On port 7070/tcp, Nmap reported ssl/realserver? but the aggressive scan extracted an SSL certificate with Subject commonName=AnyDesk Client (self-signed, valid 2026-01-12 to 2075-12-31). The Nmap vuln scan did not identify any script-detectable vulnerabilities on either port.
- **Remediation:** 1) Verify whether AnyDesk is authorized on this host; if unauthorized, remove it immediately. 2) If AnyDesk is required, restrict inbound access to port 7070/tcp via host firewall or network ACLs to authorized administrator IPs only. 3) Ensure AnyDesk is updated to the latest stable version and configure strong unattended-access passwords with two-factor authentication. 4) Continue standard Windows patching and monitor RPC-related exposure per organizational hardening baselines.
