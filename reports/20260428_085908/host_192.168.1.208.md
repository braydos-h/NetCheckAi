# Host 192.168.1.208

**Risk Level:** LOW

**Title:** Exposed Windows Network Discovery HTTP Service (HTTPAPI/2.0) on TCP 5357

## Open Ports

- 5357/tcp: http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

## Evidence
Nmap basic, service, and vulnerability scans identified a single open port 5357/tcp running Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP). The service returns HTTP title 'Service Unavailable' and server header 'Microsoft-HTTPAPI/2.0'. OS fingerprinting suggests a modern Windows OS (10/11/Server 2019). Nmap vulnerability scripts (http-csrf, http-dombased-xss, http-stored-xss) found no web vulnerabilities. No CVEs were found in NVD for 'Microsoft HTTPAPI 2.0'. All other ports are filtered.

## Severity Reason
TCP 5357 is used by Windows Function Discovery/WS-Discovery (WSDAPI), a standard network discovery component. While it exposes a minimal HTTP surface, it currently returns 'Service Unavailable', indicating no active web application is listening. No associated CVEs or script-detectable web vulnerabilities were identified. The risk of compromise via this port is low, though it confirms the host is Windows and exposes a network discovery endpoint.

## Remediation
If network discovery is not required, disable the 'Function Discovery Provider Host' (fdPHost) and 'Function Discovery Resource Publication' (fdResPub) services, or block inbound TCP 5357 via the host/network firewall. If network discovery is required, restrict access to trusted local subnets and ensure the system is fully patched. Verify that no additional services register with HTTPAPI on this port.

## Services Researched
- Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
