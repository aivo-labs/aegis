---
title: Ingress PEP Gateway (WAF & Scanners)
description: In-line web attack interception, OWASP Top 10 mitigation, and automated scanner blocking.
---

The **Aegis Gate PEP (Policy Enforcement Point)** gateway serves as the frontline perimeter shield of Aegis (`apps/gate-proxy`). Deployed in-line on port `8000`, it scrutinizes every inbound packet before it reaches your backend application runtimes.

## 🛡️ In-Line Interception Engine (< 1.5 ms)

Aegis Gate inspects each HTTP/HTTPS request against hardened deterministic filters:

### 1. Vulnerability Scanners & Reconnaissance Tools
Automated probing tools are immediately caught via behavioral User-Agent fingerprints and signature patterns:
* **Blocked tools** : `Nikto`, `SQLmap`, `Nuclei`, `Gobuster`, `Dirbuster`, `Nmap`, `Masscan`, `WPScan`, `Acunetix`, `Nessus`, `Hydra`.
* **Action** : Immediate `HTTP 403 Forbidden` response without forwarding to application runtimes.

### 2. SQL Injections (SQLi)
* Detection of database exfiltration payloads: `UNION SELECT`, `' OR 1=1`, `benchmark()`, `sleep()`, table recon on `information_schema`.
* **Severity** : `CRITICAL` (Risk Score: 98/100).

### 3. Path Traversal & Local File Inclusion (LFI)
* Detection of unauthorized filesystem traversal: `../../../../etc/passwd`, `/etc/shadow`, `.env`, `.git/HEAD`.
* **Severity** : `HIGH` (Risk Score: 90/100).

### 4. Remote Code Execution (RCE)
* Detection of unauthenticated command injection strings: `; cat`, `| id`, `$(whoami)`, `curl http`, `/bin/sh`.
* **Severity** : `CRITICAL` (Risk Score: 99/100).

### 5. Cross-Site Scripting (XSS)
* Detection of unauthorized script execution vectors and event handlers: `<script>`, `javascript:`, `onerror=`, `onload=`, `alert()`.
* **Severity** : `MEDIUM` (Risk Score: 75/100).

---

## 📡 Ingress Audit Telemetry

As soon as an offensive request is intercepted or healthy traffic is verified, Aegis Gate posts a structured JSON payload to the Go backend (`/api/v1/gate/telemetry/ingress`):

```json
{
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "client_ip": "185.220.101.5",
  "user_agent": "Mozilla/5.00 (Nikto/2.1.6)",
  "http_method": "GET",
  "request_uri": "/admin/setup.php",
  "decision": "BLOCK",
  "http_status_returned": 403,
  "latency_ms": 1.2,
  "metadata": {
    "threat_type": "PENTEST_SCANNER_DETECTED",
    "severity": "HIGH",
    "risk_score": 92,
    "engine": "Aegis Gate PEP (OWASP CRS)"
  }
}
```

The incident is visualized in real-time within the corresponding column of the **Triage Kanban** in the Cockpit.
