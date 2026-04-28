# Host 192.168.1.1

**Risk Level:** MEDIUM

**Title:** Starlink Router with Multiple Exposed Services and Outdated OpenSSH

## Open Ports

- 22/tcp: ssh OpenSSH 8.4 (protocol 2.0)
- 80/tcp: http Golang net/http server (Starlink)
- 9000/tcp: grpc unknown
- 9001/tcp: http Golang net/http server
- 9002/tcp: ssl/dynamid? unknown (SpaceX router TLS cert)
- 9003/tcp: grpc unknown

## Evidence
Nmap service scan found OpenSSH 8.4 on 22/tcp, a Golang net/http server on 80/tcp serving a Starlink web interface (title: Starlink), grpc on 9000/tcp and 9003/tcp, another Golang HTTP server on 9001/tcp returning HTTP 500 errors for most requests, and an ssl/dynamid service on 9002/tcp presenting a TLS certificate for a SpaceX router (CN=Router-010000000000000001C5BC0E) valid from 2025-10-29 to 2045-10-29. OS fingerprinting suggests Linux. The Nmap vulnerability script scan timed out and did not complete.

## Severity Reason
The host exposes a broader remote attack surface than initially triaged, including an outdated OpenSSH 8.4 remote login service, multiple HTTP/Golang services (one generating internal server errors), and exposed gRPC endpoints. OpenSSH 8.4 is known to have published vulnerabilities (e.g., privilege escalation, scp command injection). A 20-year self-signed certificate on port 9002 indicates weak cryptographic lifecycle management. While no critical remote code execution was confirmed, the cumulative exposure and outdated components justify a medium risk.

## Remediation
1) Upgrade OpenSSH to the latest stable/vendor-patched release. 2) Restrict SSH to management networks and enforce key-based authentication with MFA. 3) Harden Golang HTTP services on ports 80 and 9001; implement proper error handling, input validation, and access controls. 4) Restrict gRPC on 9000/9003 to authorized clients and enable TLS with strong authentication. 5) Investigate the ssl/dynamid service on 9002; disable if unnecessary, otherwise replace the long-lived certificate with a properly managed PKI cert and enforce strong cipher suites. 6) Apply regular vulnerability scanning and patch management. 7) Use host-based firewall rules to limit exposure of management services.

## Services Researched
- OpenSSH 8.4
- Golang net/http server
- grpc
- ssl/dynamid
