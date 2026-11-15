---
title: Passive Scanner, Legal Mandate & Post-Quantum Probe (ML-KEM)
description: Architecture of the 2-tier scanner (100% passive RGESN/DNS/Headers/CVE/PQC audit vs Tier-2 deep probes under cryptographic legal mandate) and NIST FIPS 203 X25519MLKEM768 detection.
---

The diagnostic engine in **Aegis (`apps/backend/internal/scanner`)** is built from the ground up around **Legal-by-Design Ethics**. Unlike traditional offensive scanners that fire intrusive requests against third-party hosts without authorization, Aegis strictly separates its analysis into **two execution tiers**:

1. **Tier 1 — 100% Passive Diagnostic (No Prior Mandate Required)**: Inspects only public metadata returned during standard browsing (public HTML, HTTP headers, public DNS records, and a standard Post-Quantum TLS 1.3 handshake).
2. **Tier 2 — Deep Audit under Cryptographic Legal Mandate (Criminal Law Compliance)**: Unlocked **exclusively** after mathematical proof of domain ownership (via DNS `TXT` record or `/.well-known/aegis-verify.txt`) and a signed audit mandate sealed with a `SHA-256` hash.

---

## 🏛️ 2-Tier Scanner Architecture Diagram

```
                        [ Audit Request: Target Domain ]
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│            TIER 1: 100% PASSIVE PROBE (NO PRIOR MANDATE REQUIRED)            │
│                      POST /api/v1/audit/passive-scan                         │
│                                                                              │
│  ┌──────────────────────────────┐    ┌────────────────────────────────────┐  │
│  │ 1. Light Crawl & EcoIndex    │    │ 2. Hierarchical DNS Inspection     │  │
│  │ • Up to 4 public pages       │    │ • A / AAAA Resolution              │  │
│  │ • DOM / Req / KB Quantiles   │    │ • Direct & Wildcard SPF (RFC 7208) │  │
│  │ • 0-100 Score (A-G), gCO2e,  │    │ • Direct & Parent DMARC (RFC 7489) │  │
│  │   and Water footprint (cL)   │    └────────────────────────────────────┘  │
│  └──────────────────────────────┘                                            │
│  ┌──────────────────────────────┐    ┌────────────────────────────────────┐  │
│  │ 3. HTTP Headers & CVE Matrix │    │ 4. Post-Quantum Readiness (PQC)    │  │
│  │ • HSTS, CSP, XFO, XCTO...    │    │ • TLS 1.3 Handshake (Go 1.25)      │  │
│  │ • Passive Fingerprinting     │    │ • Hybrid group X25519MLKEM768      │  │
│  │ • Virtual Patching Coverage  │    │ • HNDL Risk & Config Snippets      │  │
│  └──────────────────────────────┘    └────────────────────────────────────┘  │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                  Domain owner wishing │ to unlock deep exposure probes
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│          LEGAL SAFEGUARD: OWNERSHIP PROOF & SHA-256 SIGNED MANDATE           │
│     POST /api/v1/audit/request-verification -> /api/v1/audit/verify-ownership│
│                                                                              │
│  1. Unique token: aegis-site-verification=aegis_verify_<24_hex_chars>        │
│  2. DNS TXT check (@ or _aegis-challenge + 1.1.1.1 / 8.8.8.8 UDP fallback)   │
│     or HTTPS file https://<domain>/.well-known/aegis-verify.txt              │
│  3. SHA-256 Seal: Hash(domain | email | signer_ip | timestamp | contract)    │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼ (If and only if verified)
┌──────────────────────────────────────────────────────────────────────────────┐
│            TIER 2: AUTHORIZED DEEP EXPOSURE PROBES (LEVEL 2)                 │
│                                                                              │
│  • Secret exposure checks: /.env, /.git/config, /phpinfo.php                 │
│  • CMS attack surface checks: /wp-login.php, /xmlrpc.php                     │
│  • Verdict: PROTECTED (Filtered) / BLOCKED AT EDGE (HTTP 403) / EXPOSED (200)│
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔍 Deep Dive into the 4 Passive Scanner Modules (Tier 1)

When `POST /api/v1/audit/passive-scan` is called, the Go orchestrator (`RunRealPassiveAudit` in `apps/backend/internal/scanner/engine.go`) runs four non-intrusive modules in parallel:

### 1. RGESN Eco-Design Audit & EcoIndex Calculation (`eco.go`)
The scanner inspects the home page and up to 3 public internal pages (`<a href>` on the same domain) with a strict `3.5-second` timeout:
- **Extracted Metrics**: Transfer weight in KB (`weight_kb`), HTML tree complexity (`dom_elements` via tag count), and external sub-requests triggered (`http_requests`: scripts, stylesheets, images, iframes).
- **Official EcoIndex Formula (GreenIT Collective)**: Linear interpolation across the 20 official quantile tables (`quantilesDOM`, `quantilesReq`, `quantilesSize`):
  $$\text{EcoScore} = 100 - \frac{5 \times (3 \cdot Q_{\text{DOM}} + 2 \cdot Q_{\text{Req}} + Q_{\text{Size}})}{6}$$
- **Physical Footprint per Visit**:
  - **Greenhouse Gas Emissions ($\text{gCO}_2\text{e}$)**: $2 + \frac{2 \times (50 - \text{EcoScore})}{100}$
  - **Water Consumption ($\text{cL}$)**: $3 + \frac{3 \times (50 - \text{EcoScore})}{100}$

### 2. Passive DNS Inspection & Hierarchical Traversal (`dns.go`)
`InspectDomainDNS` resolves IPv4/IPv6 addresses (`A` / `AAAA`) and checks email anti-spoofing records with full subdomain inheritance support:
- **SPF (RFC 7208)**: Looks up a direct `v=spf1` record on the target domain, then falls back to wildcard records (`*.parent`) across parent domains via `getParentDomains`.
- **DMARC (RFC 7489 Section 6.6.3)**: Looks up `_dmarc.<domain>`. If a subdomain has no explicit DMARC record, the scanner traverses up to the organizational parent domain (`_dmarc.<parent>`) and validates inheritance provided subdomain policy is not explicitly disabled (`sp=none`).

### 3. Security Headers, Tech Fingerprinting & CVE Coverage Matrix (`headers.go` & `fingerprint.go`)
- **Security Headers (`AnalyzeSecurityHeaders`)**: Audits the presence and policy strength of `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Passive Fingerprinting & CVE Matrix (`DetectTechAndCVEs`)**: Identifies technologies disclosed in HTTP headers (`Server`, `X-Powered-By`) and HTML markup, mapping each relevant CVE to:
  - a **hot-mitigation coverage status** (`COVERED_VIRTUAL_PATCH` via Aegis Ingress PEP or `HOST_PATCH_REQUIRED`),
  - a step-by-step **root fix procedure (`root_fix_procedure`)**,
  - and a **verification command (`verification_probe`)**.

---

## 🔐 Focus: Post-Quantum Readiness Passive Probe (`pqc.go`)

### Why Audit Post-Quantum Readiness Today?
Even though fault-tolerant cryptanalytic quantum computers (capable of running Shor's algorithm to break RSA and classical elliptic curves like `X25519` / `P-256`) are projected for the 2030+ timeframe, the **HNDL (*Harvest Now, Decrypt Later*)** threat is active right now: adversaries are recording encrypted TLS traffic today so they can decrypt sensitive payloads retroactively once quantum hardware matures.

To neutralize this threat, NIST standardized **FIPS 203 (`ML-KEM`, derived from CRYSTALS-Kyber)** in August 2024. In TLS 1.3, it is deployed via the hybrid key exchange group **`X25519MLKEM768` (`0x11ec`)**, natively supported in **Go 1.25+**, **Cloudflare**, **OpenSSL 3.5+**, **BoringSSL**, and modern browsers.

### How the `InspectDomainPQC` Passive Handshake Works

```
 Aegis Passive Scanner (Go 1.25)                        Target Server (:443)
 ───────────────────────────────                        ────────────────────
               │                                                  │
               │ 1. TLS 1.3 ClientHello (3s Timeout)              │
               │    Supported Groups (CurvePreferences):          │
               │      [1] X25519MLKEM768 (0x11ec - NIST FIPS 203) │
               │      [2] X25519Kyber768Draft00 (0x6399 - Draft)  │
               │      [3] X25519 (0x001d - Classical)             │
               │      [4] P-256 (0x0017) / P-384 (0x0018)         │
               ├─────────────────────────────────────────────────►│
               │                                                  │
               │ 2. TLS 1.3 ServerHello                           │
               │    KeyShare selected by the remote server        │
               │◄─────────────────────────────────────────────────┤
               │                                                  │
               │ 3. Inspect conn.ConnectionState().CurveID        │
               │    • If 0x11ec -> PostQuantumReady = true        │
               │    • Otherwise -> Emit PQC-HNDL-EXPOSURE warning │
               │                   + Traefik/Nginx/Caddy snippets │
               │                                                  │
               │ 4. Immediate clean closure of the TLS socket     │
               ├─────────────────────────────────────────────────►│
```

1. **Preferential Group Negotiation**: `InspectDomainPQC` dials port `443` over TLS with `tls.X25519MLKEM768` (`0x11ec`) placed first in `CurvePreferences`.
2. **Cryptographic State Inspection (`EvaluateTLSConnectionState`)**:
   - **Case 1 — FIPS 203 Capable Server (`0x11ec`)**:
     - `post_quantum_ready: true`
     - `standard: "NIST FIPS 203 (X25519MLKEM768)"`
     - `hndl_risk: "LOW"`
     - Automatically appends `Cryptographie TLS Post-Quantique (NIST FIPS 203)` to the domain's `tech_stack`.
   - **Case 2 — Pre-Standard IETF Draft Server (`0x6399`)**:
     - `post_quantum_ready: true`
     - `standard: "IETF Draft (X25519Kyber768Draft00 — Migration FIPS 203 recommandée)"`
     - `hndl_risk: "MODERATE"` with migration snippets to `X25519MLKEM768`.
   - **Case 3 — Classical Elliptic Curve Fallback (`X25519`, `P-256`, `P-384`)**:
     - `post_quantum_ready: false`
     - `standard: "Classical ECDHE (Non-PQC)"`
     - `hndl_risk: "HIGH"`
     - Emits the **`PQC-HNDL-EXPOSURE`** warning along with copy-paste remediation snippets (`remediation_snippets`).

### Copy-Paste Post-Quantum Remediation Snippets Provided by Aegis

When `post_quantum_ready` is `false`, the API returns ready-to-use configuration snippets to enable `X25519MLKEM768`:

#### Traefik (v3.3+ / Dokploy)
```yaml
tls:
  options:
    default:
      minVersion: VersionTLS13
      curvePreferences:
        - X25519MLKEM768
        - X25519
        - CurveP256
```

#### Nginx (with OpenSSL 3.5+)
```nginx
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;
```

#### Caddy
```txt
tls {
    protocols tls1.3
    curves x25519mlkem768 x25519 secp256r1
}
```

#### Native Go Server (Go 1.25+)
```go
tlsConfig := &tls.Config{
    MinVersion:       tls.VersionTLS13,
    CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
}
```

---

## 🧪 How to Test the Passive Scanner & PQC Probe

### 1. Run Unit Tests & Live Local TLS 1.3 Post-Quantum Handshake
`apps/backend/internal/scanner/pqc_test.go` includes an end-to-end test (`TestLiveTLS13Handshake_NegotiatesX25519MLKEM768`) that spins up a local TLS 1.3 server and verifies real negotiation of hybrid group `0x11ec`:

```bash
cd apps/backend
go test -v ./internal/scanner -run "TestEvaluateTLSConnectionState|TestLiveTLS13Handshake"
```

### 2. Query the Passive Scanner API (`/api/v1/audit/passive-scan`)
When the Go Control Plane is running:

```bash
curl -s -X POST http://localhost:8080/api/v1/audit/passive-scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "cloudflare.com"}' | jq '.post_quantum'
```

Example JSON output on a domain supporting `X25519MLKEM768`:
```json
{
  "post_quantum_ready": true,
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "negotiated_curve": "X25519MLKEM768 (0x11ec)",
  "standard": "NIST FIPS 203 (X25519MLKEM768)",
  "hndl_risk": "LOW — Protégé contre les attaques Harvest Now, Decrypt Later (HNDL) via encapsulation hybride X25519 + ML-KEM-768."
}
```

### 3. Manual Verification with OpenSSL 3.5+
```bash
openssl s_client -connect cloudflare.com:443 -groups X25519MLKEM768
```

---

## ⚖️ Tier 2: Cryptographic Legal Mandate & Ownership Proof (`ownership.go`)

In strict compliance with **Article 323-1 of the French Penal Code** (and international equivalents such as the CFAA), any probe that checks for unlinked sensitive files (`/.env`, `/.git/config`, `/phpinfo.php`, `/wp-login.php`, `/xmlrpc.php`) requires explicit authorization from the verified domain owner:

1. **Challenge Request (`POST /api/v1/audit/request-verification`)**:
   Generates a cryptographic 96-bit random token (`aegis-site-verification=aegis_verify_<24_hex>`).
2. **Zero-Negative-Cache Multi-Channel Verification (`POST /api/v1/audit/verify-ownership`)**:
   - Checks for the DNS `TXT` record on `@` or `_aegis-challenge.<domain>` using the system resolver, then directly queries **Cloudflare (`1.1.1.1:53`)** and **Google (`8.8.8.8:53`)** over UDP to bypass negative DNS caching delays.
   - Alternatively, checks for the token inside `https://<domain>/.well-known/aegis-verify.txt`.
3. **Tamper-Evident Audit Proof (`contract_text_hash`)**:
   The signed mandate, signer IP address, UTC RFC 3339 timestamp, and legal contract text are hashed with `SHA-256` and stored in the `domain_ownership_contracts` PostgreSQL table before executing `runLevel2DeepChecks`.

---

## 📚 Further Reading

- **[Ingress PEP Gateway (WAF, Pure BFF & Virtual Patching)](/docs/security/ingress-pep/)**: How vulnerabilities detected by the passive scanner are hot-patched at the edge in under 1.5 ms.
- **[Attack Simulation & Live Testbench](/docs/pentest/banc-essai/)**: Replay controlled attack scenarios against your staging environment.
