# Network Assessment Report

**Run ID:** 20260428_084600
**Scope:** 192.168.1.0/24
**Generated:** 2026-04-28T08:49:16.608914Z

## Findings Summary
- **Total:** 13

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
