---
title: Ingress PEP Gateway (WAF, Pure BFF & Virtual Patching)
description: Zero-Trust network-interception architecture, OWASP Top 10 filtering, RFC 413 overflow defense, Shannon entropy detection, and Pure BFF session management.
---

The **Aegis Gate PEP (Policy Enforcement Point)** gateway is the frontline sovereign shield of the Aegis ecosystem (`apps/gate-proxy`). Deployed in-line or integrated as an external authorization subrequest (`ForwardAuth`), it scrutinizes every inbound packet before it reaches the internal application network, delivering a deterministic security verdict in **under 1.5 milliseconds**.

---

## 🏛️ Ingress PEP Architecture Diagram

```
                           [ Inbound HTTP/HTTPS Request ]
                                          │
                                          ▼
                ┌──────────────────────────────────────────────────┐
                │   Edge Reverse Proxy / Load Balancer             │
                │   (Traefik v3 Dokploy / Nginx / Caddy / Envoy)   │
                └─────────────────────────┬────────────────────────┘
                                          │
                        ForwardAuth Mode  │  Transparent Reverse
                   (Subrequest /_aegis/verify)     Proxy Mode (:8000)
                                          │
                                          ▼
    ┌────────────────────────────────────────────────────────────────────────┐
    │                 AEGIS GATE PEP — INSPECTION PIPELINE                   │
    │                                                                        │
    │  1. Pure BFF Token Handler (/api/auth/*)                               │
    │     ↳ OIDC PKCE Resolution + AES-256-GCM Sealed Session Cookies        │
    │                                                                        │
    │  2. Recursive Canonicalization & Normalization Engine                  │
    │     ↳ Multi-layer URL/Hex/Unicode decoding, null-byte stripping        │
    │                                                                        │
    │  3. RFC 413 Volumetric Body Cap                                        │
    │     ↳ Immediate truncation at 32 KB (Anti-DDoS & Buffer Overflow)      │
    │                                                                        │
    │  4. Shannon Information Entropy Engine (H)                             │
    │     ↳ Mathematical detection of shellcodes, binaries & high-H tokens   │
    │                                                                        │
    │  5. Hardened WAF Rule Registry (OWASP CRS)                             │
    │     ↳ Scanners (Nikto, Nuclei), SQLi, XSS, RCE, LFI, SSRF, CMS Probes  │
    │                                                                        │
    │  6. Dynamic Zero-Day Virtual Patching                                  │
    │     ↳ Upstream CVE neutralization (e.g., PHP2Shell, JNDI Injections)   │
    └───────────────────────────────────┬────────────────────────────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                 [ VERDICT : BLOCK ]           [ VERDICT : ALLOW ]
                 • Immediate HTTP 403 / 413     • HTTP 200 Forwarded
                 • Real-time JSON telemetry     • Verified X-Aegis Headers
                 • Streamed to TimescaleDB      • Relayed to Upstream Apps
```

---

## 🛡️ The 6 Pillars of the Inspection Pipeline

### 1. Pure BFF Architecture (Backend-for-Frontend)
Aegis completely eliminates token-theft vulnerabilities resulting from malicious script execution (XSS):
* No access token (`access_token`, `id_token`, or `refresh_token`) is ever stored in the browser (neither in `localStorage`, `sessionStorage`, nor in JavaScript memory).
* The `apps/gate-proxy/src/bff` module intercepts `/api/auth/*` routes, negotiates standardized OIDC with **PKCE (RFC 7636)** verification, and issues an encrypted **AES-256-GCM**, `HttpOnly`, `SameSite=Strict`, `Secure` session cookie to the browser.
* Upstream of internal microservices, Aegis Gate decrypts the session and injects certified identity headers (`X-Aegis-User-Id`, `X-Aegis-User-Role`, `X-Aegis-Tenant-Id`).

### 2. Multi-Encoding Canonicalization & Anti-Obfuscation (Lock #2)
Attackers frequently use nested obfuscation to evade pattern-matching filters (multi-encoding `%252e%252e%252f`, null bytes `%00`, mixed UTF-8 sequences, HTML entities, and Base64 wrappers).
* **Recursive 3-Pass Decoding**: The engine recursively canonicalizes all URI paths, query strings, headers, and bodies until reaching a stable, raw representation.
* **Entity & Escape Normalization**: Strips null bytes, decodes named, decimal, and hex HTML entities (`&quot;`, `&#x27;`), and resolves Hex/Unicode escapes (`\x..`, `\u....`, `%u....`).
* **Path Sanitization**: Strictly normalizes path separators (`/./`, `//`, Windows `\`) prior to directory traversal inspection.
* **Automatic Base64 Ingestion**: Suspect base64 segments (`>= 16` alphanumeric characters with valid padding) are decoded on the fly and inspected as primary payloads.

### 3. Volumetric Rate-Limiting & Automated Auto-Jail (Lock #3)
Aegis Gate protects upstreams against brute-force attacks and high-speed fuzzing:
* **Sliding-Window Volumetric Limiter**: Enforces a strict budget of **60 requests per 10 seconds** per client IP, returning `HTTP 429 Too Many Requests` with a compliant `Retry-After: 10` header.
* **15-Minute Automated Auto-Jail**: Any unauthenticated IP accumulating **3 critical offenses** (`risk_score >= 90`) within **5 minutes** is automatically quarantined in the persistent blacklist for 15 minutes (`AUTO_JAIL_TEMPORARY_QUARANTINE`), synced to the Go Control Plane and visible in the Cockpit.

### 4. HTTP Protocol Hardening & RFC 413 / 431 Defense (Lock #4)
* **Header Budgets (`HTTP 431`)**: Requests exceeding `8 KB` total header size, `4 KB` for an individual header, or containing over `64` headers are blocked with `HTTP 431 Request Header Fields Too Large`.
* **Volumetric Body Cap (`HTTP 413`)**: Enforces a strict cut-off on the incoming request body size (configurable via `AEGIS_MAX_PAYLOAD_BYTES`, defaulting to `32 KB`), halts transfer immediately with `HTTP 413 Payload Too Large`, and defends against compression bombs.
* **Multipart RFC Validation**: Validates `multipart/form-data` boundary formatting, bounds nested boundary recursion depth (`<= 3`), and blocks executable upload extensions (`.php`, `.phtml`, `.phar`, `.sh`).

### 5. Shannon Entropy Engine
* Computing Shannon entropy $H(X) = -\sum P(x) \log_2 P(x)$ quantifies information density across URI segments and request bodies.
* Any string exhibiting an entropy value greater than **3.85** over a significant character length instantly indicates an injected compiled binary, base64-obfuscated shellcode, or cryptographic key exfiltration attempt.

### 5. Hardened WAF Filtering & Pentest Tool Interception
Aegis blocks destructive cyberattack vectors at the root:
* **Offensive scanners**: Automated reconnaissance tools blocked on the very first packet (`Nikto`, `SQLmap`, `Nuclei`, `Gobuster`, `Dirbuster`, `Nmap`, `Acunetix`, `WPScan`, `Hydra`, etc.).
* **SQL Injections (SQLi)** : Detection of time-based blind SQLi (`benchmark()`, `pg_sleep()`), `UNION SELECT`, and schema enumeration (`information_schema`).
* **Path Traversal & LFI**: Neutralization of sensitive file reads (`/etc/passwd`, `/etc/shadow`, `.env`, `.git/config`, `wp-config.php`).
* **Remote Code Execution (RCE)** : Interception of command injection attempts (`; cat`, `| id`, `$(whoami)`, `/bin/sh`).
* **Cross-Site Scripting (XSS)** : Strict filtering of executable HTML elements and DOM event triggers (`<script>`, `onerror=`, `onload=`, `javascript:`).

### 6. Dynamic Zero-Day Virtual Patching
When a critical vulnerability emerges in an underlying framework or runtime (such as the PHP2Shell CVE-2026-33044 flaw or Log4j JNDI injection), Aegis Gate instantly applies a proxy-level virtual patch. Target services are shielded on the spot, without requiring system downtime or urgent source code rollouts.

---

## ⚙️ Operational Modes

Aegis Gate integrates seamlessly with any modern cloud architecture:

### Mode A: External Authorizer (ForwardAuth)
The primary edge proxy (e.g., **Traefik v3** in Dokploy or **Nginx**) maintains TLS termination with Let's Encrypt and calls Aegis on its `/_aegis/verify` endpoint:
* The subrequest forwards client metadata headers (`X-Forwarded-Uri`, `X-Forwarded-Method`, `X-Forwarded-For`).
* Aegis assesses the request in **0.4 ms**. If safe, it returns `HTTP 200 OK` with validation headers, and Traefik forwards the request to the upstream container.
* If a threat is detected, Aegis immediately returns `HTTP 403 Forbidden` or `HTTP 413`, aborting the request before it can touch the protected workload.

### Mode B: Transparent Reverse Proxy (Edge Gateway)
Aegis Gate listens directly on port `8000` (or behind an L4 cloud load balancer). It performs in-line inspection and proxies clean traffic to configured upstreams (`BACKEND_URL`, `WEB_URL`, or `AEGIS_UPSTREAM_ROUTING`).

---

## 📡 Audit Telemetry & Real-Time Correlation

Every security inspection generates structured JSON telemetry dispatched to the Go/TimescaleDB backend:

```json
{
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "client_ip": "185.220.101.5",
  "user_agent": "Mozilla/5.0 (Nikto/2.1.6)",
  "http_method": "GET",
  "request_uri": "/admin/wp-config.php.bak",
  "decision": "BLOCK",
  "http_status_returned": 403,
  "latency_ms": 0.8,
  "threat_type": "PENTEST_SCANNER_DETECTED",
  "severity": "CRITICAL",
  "risk_score": 96,
  "entropy": 4.12,
  "metadata": {
    "engine": "Aegis Gate PEP (OWASP CRS)",
    "rule_triggered": "ScannerSignatureRule",
    "virtual_patch_active": true
  }
}
```

The incident is visualized instantaneously in the SOC **Triage Kanban** for impact triage and automated IP quarantine.

---

## 📚 In-Depth Articles & Technical References

To learn more about the theoretical foundations and production learnings behind Aegis Gate PEP, explore our research articles on AIVO:

* 📖 [**Pure BFF Architecture Guide: Uncompromised OIDC Security**](https://aivo.fr/en/blog/guide-architecture-pure-bff-securite-oidc) — In-depth breakdown of the Token Handler pattern, total elimination of XSS token leaks, and AES-GCM session cryptography.
* 📖 [**Shannon Entropy & Zero-Trust Decisions: Frugal AI Powering the WAF**](https://aivo.fr/en/blog/entropie-shannon-decision-zero-trust-ia-frugale) — Mathematical formulation of entropy scoring for near-zero-energy instant threat classification.
* 📖 [**Anatomy of a VPS Under Continuous Attack: Scanners, Energy, and Active Responses**](https://aivo.fr/en/blog/anatomie-vps-sous-assaut-continu-scanners-energie) — Empirical analysis of automated scanner traffic and real hardware power consumption under attack.
* 🔬 [**Aegis Sovereign Gate Case Study on AIVO.fr**](https://aivo.fr/en/realisations/aegis-sovereign-gate) — Executive project overview, sovereign compliance milestones, and upcoming CTI / AI agent harness roadmap.
