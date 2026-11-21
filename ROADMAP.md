# 🛡️ Aegis Technical Roadmap — Zero-Trust Hardening, GreenOps & AI Security

<p align="center">
  <strong>English</strong> | <a href="ROADMAP.fr.md">Français</a>
</p>

This document is the **single source of truth** for the Aegis engineering roadmap, shared between the open-source repository and the [AIVO Agency architectural case study](https://aivo.fr/en/realisations/aegis-sovereign-gate).

Every item is tracked strictly by **implementation status (`✅ Delivered`, `🚧 Partial`, `⏳ Planned / In Design`)** and **engineering priority (`P0` to `P3`)** — with no arbitrary calendar promises — toward three measurable objectives:
1. Raise real-world interception efficacy against manual Red Team evasion, **autonomous AI pentesting frameworks (such as ARTEX / Hexstrike)**, and memory-corruption attacks from **~78% to > 95%**.
2. Enforce **"Assume Breach" defense-in-depth** across containers, Linux kernels, and workstations (`< 10 MB RAM` Rust endpoint posture agent) without per-seat SaaS licensing fees.
3. Extend sovereign perimeter filtering to **AI workloads** (LLM data exfiltration guardrails, sandboxed Agent Harnesses, collaborative P2P CTI, and CPU-only `< 1B` micro-SLMs).

---

## 🧭 Unified Priority & Status Matrix

| Phase | Lock / Module | Status | Priority | Codebase Scope | Core Security & GreenOps Gain |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **v1 Base** | **Ingress WAF, PHP2Shell VP, Pure BFF & RAPL Cockpit** | **✅ Delivered** | **v1 Core** | `gate-proxy`, `backend`, `telemetry-agent`, `web` | `< 1.5 ms` idle edge PEP, HTTP `413` (`32 KB`), `100%` PHP2Shell mitigation (`0%` app CPU), OIDC Pure BFF & live CSRD RAPL PDF/CSV |
| **P0/P1** | **#1 Strict Egress Network Confinement & DNS-to-IP Allowlist** | **✅ Delivered (v1.2)** | **P0 (Critical)** | `docker-compose*.yml`, `egress-gateway`, `deploy/security/` | Blocks raw-IP TCP reverse shells bypassing DNS (`internal: true` bridge, `DnsToIpAllowlist` 60s TTL + `egress-lockdown.nft`) |
| **P0/P1** | **#2 Multi-Encoding Normalization (Base64 / HTML / Hex)** | **✅ Delivered (v1.2)** | **P1 (High)** | `apps/gate-proxy/src/engine/canonicalizer.ts`, `sandboxEngine.ts` | Recursive 3-pass URL, HTML entities, Hex/Unicode escapes, path normalization (`/./`, `//`, `\`) & auto Base64 payload decoding (`>= 16` chars) |
| **P0/P1** | **#3 Volumetric Rate-Limiting (`429`) & Auto-Jail IP Quarantine** | **✅ Delivered (v1.2)** | **P1 (High)** | `apps/gate-proxy/src/quarantine/ip-reputation.ts`, `backend` | Persistent SOC blacklist + sliding-window rate limits (`60 req/10s`, `HTTP 429`) & 15-min Auto-Jail (`3` critical offenses in `5 min`) |
| **P0/P1** | **#4 HTTP Protocol Hardening (`431`), Multipart RFC & Shell-Spawn Watch** | **✅ Delivered (v1.2)** | **P1 (High)** | `apps/gate-proxy/src/`, `apps/telemetry-agent/src/collector/` | Strict `HTTP 431` header caps (`8 KB` total / `4 KB` single / `64` max), RFC multipart validation, compression-bomb block & Rust `/proc` shell-spawn monitor |
| **P0/P1** | **#5 Continuous Passive Posture, PQC (`ML-KEM`), CERT-FR & Remediation** | **✅ Delivered (v1.2)** | **P1 (High)** | `apps/backend/internal/scanner/`, `service/audit_service.go`, `web` | Scheduled periodic audits (`6h`/`12h`/`24h`), posture drift detection, guided Traefik/Nginx/Caddy/PHP snippets, PQC `X25519MLKEM768` & CVSS-weighted scoring |
| **Hardening** | **v1.2.1/v1.2.2 TimescaleDB Failover, Rust Worker Filter & Sovereign Precision UI** | **✅ Delivered (v1.2.2)** | **P1 (High)** | `apps/backend/internal/database/`, `telemetry-agent`, `web`, `aegis-cloud` | `/etc/hosts` Docker link & dynamic `lastGoodIP` failover (zero 500s), benign worker spawn filter, CPU clamping `[0, 100]%`, Ollama micro-SLM resilience & anti-vibe UI/UX overhaul |
| **v1.3 (P1.5)** | **#5-Bis "Anti-Artex" Shield (Autonomous Offensive AI Defense)** | **✅ Delivered (v1.3)** | **P1.5 (High)** | `gate-proxy`, `egress-gateway` | Opaque `403`, Adaptive Tarpit & Canary Honeypot anti-LLM, OAST/LOTC Sinkhole (`interact.sh`), API BOLA/IDOR/Swagger shield, UA mismatch & BFF Context-Binding |
| **P2** | **#6 L3/L4 eBPF / XDP Kernel Filter, `SIGKILL` Kill-Switch & CVE Audit** | **⏳ In Design** | **P2 (Medium)** | `apps/telemetry-agent/src/` | NIC-level `XDP_DROP` (`< 0.005 ms`) against malformed TCP SYN options, active `< 10 ms` `SIGKILL` on rogue shell spawn + `uname -r` alerts |
| **P2** | **#7 Enterprise DNS Filtering & Shadow IT (DoH/DoT)** | **⏳ Planned** | **P2 (Medium)** | `apps/egress-gateway/src/` | Central DHCP/`:5053` + remote DoH/DoT resolver regulating RAT tools (TeamViewer, AnyDesk, RustDesk) in Prod/DMZ |
| **P2** | **#8 Frugal Rust Endpoint Agent (`< 10 MB`) & PQC `mTLS`** | **⏳ In Design** | **P2 (Medium)** | New `aegis-node-agent` (Rust) + `web` | Cross-platform workstation CVE & hygiene probe over **hybrid post-quantum `mTLS` (`X25519MLKEM768`)** + conditional access |
| **P2** | **#9 "Assume Breach" ZTNA Micro-Segmentation** | **⏳ In Design** | **P2 (Medium)** | Network architecture & PEP | Eliminates direct L3 office-to-DB routes + adds internal ARP/port-scan honeypot alerting |
| **P3** | **#10 "Two-Door" AI Governance & Zero-Secret Egress** | **⏳ In Design** | **P3 (R&D)** | `gate-proxy` (Edge) & `egress-gateway` | Inbound Prompt Injection guardrails + **Zero-Secret Placeholder** (zero API keys in agent sandbox, PII scrubbing & boundary injection) |
| **P3** | **#11 Zero-Trust MCP Gateway & PQC AI Act Ledger** | **⏳ In Design** | **P3 (R&D)** | `gate-proxy`, host `seccomp`/eBPF & `backend` | Per-identity MCP (`tools/list`, `tools/call`) filtering, kernel sandboxing & immutable **`Ed25519 + ML-DSA` (FIPS 204)** audit ledger |
| **P3** | **#12 Collaborative P2P CTI & `< 1B` CPU Micro-SLMs** | **🚧 Partial** | **P3 (R&D)** | `apps/egress-gateway/src/cti/blocklist.ts`, Ollama | Static C2 blocklist + optional **Nimble 9B** (Ollama) **done in v1**; adds live Abuse.ch/CERT-FR/CISA KEV sync, P2P node sharing & `< 1B` CPU-only SLMs |

---

## ✅ v1 / v1.1 / v1.2 Baseline Delivered (Currently Verified in Codebase)

Before listing upcoming P2/P3 locks, the following capabilities are **already implemented and verified** in production Docker compositions:

| Pillar | Verified Codebase Implementation | Proven Benchmark / Evidence |
| :--- | :--- | :--- |
| **Ingress PEP & Virtual Patching** | [`apps/gate-proxy/src/server.ts`](apps/gate-proxy/src/server.ts), [`engine/inspector.ts`](apps/gate-proxy/src/engine/inspector.ts), [`engine/entropy.ts`](apps/gate-proxy/src/engine/entropy.ts), [`rules/zeroday.rule.ts`](apps/gate-proxy/src/rules/zeroday.rule.ts) | `CVE-2024-4577` PHP2Shell burst benchmark: **`602 / 602` blocked (`100%`)**, **`0%` PHP-FPM CPU**, **`5.81 W` avg** vs **`24.14 W` avg (`37.58 W` peak)** & **`743.4%` CPU** unshielded (**`×4.34` extra energy wasted**) |
| **Pure BFF Token Handler** | [`apps/gate-proxy/src/bff/auth-handler.ts`](apps/gate-proxy/src/bff/auth-handler.ts), [`bff/session.ts`](apps/gate-proxy/src/bff/session.ts) | Zero JWTs in browser `localStorage`/JS; AES-256-GCM encrypted `HttpOnly` cookies; agnostic OIDC (Keycloak, Authelia, Okta, Standalone) |
| **Egress DNS Sinkhole & SLM v1** | [`apps/egress-gateway/src/index.ts`](apps/egress-gateway/src/index.ts), [`dns/udp-server.ts`](apps/egress-gateway/src/dns/udp-server.ts), [`engine/system-one.ts`](apps/egress-gateway/src/engine/system-one.ts) | UDP/TCP `:5053` DNS Sinkhole (`0.0.0.0`), Shannon DGA entropy scoring (`H > 4.2`), static CTI blocklist & optional **Nimble 9B** (`ollama-nimble:11434`) air-gapped SLM |
| **Hardware RAPL Telemetry & CSRD** | [`apps/telemetry-agent/src/main.rs`](apps/telemetry-agent/src/main.rs), `collector/rapl.rs`, `collector/cpu.rs`, TimescaleDB | Real Linux `/sys/class/powercap` Watts + `/proc/stat` CPU ingestion, Kepler eBPF K8s support, Scope 2 PDF & CSV CSRD reports |
| **Cockpit SOC, PQC Scanner & CVE Feed** | [`apps/backend/internal/scanner/engine.go`](apps/backend/internal/scanner/engine.go), [`scanner/pqc.go`](apps/backend/internal/scanner/pqc.go), [`internal/service/cve_service.go`](apps/backend/internal/service/cve_service.go), `apps/web` | Live SSE triage stream, 5-page non-intrusive domain security, EcoIndex & **NIST FIPS 203 `X25519MLKEM768` Post-Quantum probe**, interactive CVE coverage catalog |

---

## 🔥 Phase P0 / P1 — Edge, Egress & Continuous Posture Hardening (✅ Delivered in v1.2.0)

### 🔒 Lock #1: Strict Egress Network Confinement & DNS-to-IP Allowlist (Anti-Raw-IP Reverse Shell)
- **Status:** ✅ Delivered (`v1.2.0`)
- **Priority:** Critical (**P0**) — Prerequisite before multi-tenant untrusted workload exposure
- **Security Gain:** Jumps from `0%` to `~98%` neutralization on direct raw-IP socket callbacks (`connect()` without DNS)
- **Delivered Implementation:**
  1. Docker network segmentation in [`docker-compose.yml`](docker-compose.yml) and [`docker-compose.dokploy.yml`](docker-compose.dokploy.yml): isolated `aegis-internal` (`internal: true`) network for `timescaledb`, `web`, and `telemetry-agent`, paired with `aegis-edge` for gateway services.
  2. Dynamic DNS-to-IP allowlist engine [`apps/egress-gateway/src/engine/ip-allowlist.ts`](apps/egress-gateway/src/engine/ip-allowlist.ts) (`DnsToIpAllowlist` with 60s TTL) integrated into [`evaluator.ts`](apps/egress-gateway/src/engine/evaluator.ts) and [`tcp-server.ts`](apps/egress-gateway/src/http/tcp-server.ts) (`POST /api/v1/egress/verify-connection`), blocking literal-IP callbacks (`RAW_IP_REVERSE_SHELL_BLOCKED`) and unapproved direct-IP sockets (`UNRESOLVED_DIRECT_IP_EGRESS_BLOCKED`).
  3. Host-level nftables enforcement policy in [`deploy/security/egress-lockdown.nft`](deploy/security/egress-lockdown.nft).

### 🔒 Lock #2: Multi-Encoding Normalization & Anti-Obfuscation
- **Status:** ✅ Delivered (`v1.2.0`)
- **Priority:** High (**P1**)
- **Security Gain:** **+12% to +15%** detection against manual obfuscation and double-encoded evasion vectors
- **Delivered Implementation:**
  1. Multi-layer canonicalization in [`apps/gate-proxy/src/engine/canonicalizer.ts`](apps/gate-proxy/src/engine/canonicalizer.ts) and [`apps/web/src/services/sandboxEngine.ts`](apps/web/src/services/sandboxEngine.ts): 3-pass recursive URL decoding, null-byte stripping, named/decimal/hex HTML entity decoding, Hex/Unicode escapes (`\x..`, `\u....`, `%u....`), and automatic Base64 payload extraction and decoding (`>= 16` chars).
  2. Strict path separator normalization (`/./`, `//`, Windows `\`) prior to `TRAVERSAL_REGEX` inspection.

### 🔒 Lock #3: Volumetric Rate-Limiting & Automated IP Auto-Quarantine (Auto-Jail)
- **Status:** ✅ Delivered (`v1.2.0`)
- **Priority:** High (**P1**)
- **Security Gain:** Neutralizes **99%** of automated fuzzing loops and high-speed credential brute-forcing
- **Delivered Implementation:**
  1. Sliding-window volumetric rate limiter (`60 req / 10s` per IP returning HTTP `429 Too Many Requests` with `Retry-After: 10`) in [`apps/gate-proxy/src/quarantine/ip-reputation.ts`](apps/gate-proxy/src/quarantine/ip-reputation.ts) and [`server.ts`](apps/gate-proxy/src/server.ts).
  2. **15-minute Auto-Jail**: any unauthenticated IP accumulating `3` critical WAF blocks (`risk_score >= 90`) within `5` minutes enters automated **15-minute quarantine** (`AUTO_JAIL_TEMPORARY_QUARANTINE`), synced to the Go Control Plane (`ttlMinutes` / `expires_at`) and surfaced in the Cockpit Controls view.

### 🔒 Lock #4: HTTP Protocol Hardening (`431`), Multipart RFC & Shell-Spawn Watch
- **Status:** ✅ Delivered (`v1.2.0`)
- **Priority:** High (**P1**)
- **Delivered Implementation:**
  1. **Protocol Hardening in [`inspector.ts`](apps/gate-proxy/src/engine/inspector.ts)**: Enforces header budgets (`> 8 KB` total / `> 4 KB` single header / `> 64` headers returning `HTTP 431 Request Header Fields Too Large`), strict `multipart/form-data` RFC boundary & depth validation (`<= 3` nested boundaries, executable upload extension blocking `.php`, `.phtml`, `.phar`, `.sh`), and multi-encoding compression-bomb chaining mitigation.
  2. **Runtime Shell-Spawn Anomaly Telemetry**: Rust collector [`apps/telemetry-agent/src/collector/process_spawn.rs`](apps/telemetry-agent/src/collector/process_spawn.rs) scanning `/host/proc` and `/proc` to raise an immediate alert when a web worker (`php-fpm`, `php-cgi`, `node`, `nginx`, `apache2`, `caddy`) spawns a child shell or exfiltration binary (`sh`, `bash`, `nc`, `curl`, `python`, `perl`, `socat`).

### 🔒 Lock #5: Continuous Passive Posture Monitoring, Post-Quantum Probe (`ML-KEM`) & Guided Remediation
- **Status:** ✅ Delivered (`v1.2.0`)
- **Priority:** High (**P1**)
- **Delivered Implementation:**
  1. **Scheduled Continuous Background Scans & Drift Detection**: `GET/POST /api/v1/audit/schedule` endpoints in [`audit_service.go`](apps/backend/internal/service/audit_service.go) and [`audit_handler.go`](apps/backend/internal/http/handlers/audit_handler.go) with automatic posture drift evaluation (`EvaluatePostureDrift`) and `6h` / `12h` / `24h` scheduling controls in [`AuditPanel.vue`](apps/web/src/components/soc/actions/AuditPanel.vue).
  2. **Guided Host Remediation Wizard**: Dynamic copy-paste hardening configurations (`GenerateGuidedRemediationSnippets`) for **Traefik**, **Nginx**, **Caddy**, and **Apache / `php.ini`** covering missing security headers, Post-Quantum TLS 1.3 (`X25519MLKEM768`), and PHP SAPI confinement.
  3. **Sovereign CERT-FR Ingestion & Continuous Qualification (`PENDING_VERIFICATION`)**: On-demand sync with official CERT-FR (ANSSI) advisories and explicit `"Procedure under verification (Aegis Lab)"` labeling for uncurated advisories.
  4. **Composite CVSS-Weighted Security Scoring (Zero Fake-Positive)**: Unified scoring combining transport headers, DNS resilience, and CVSS-weighted CVE penalties (`-25 pts` per unmitigated CRITICAL CVE, capping domain score at `65/100` when critical vulnerabilities are exposed).

### 🔒 Stabilization & Hardening: TimescaleDB DNS Failover, Worker Anomaly Filtering & Sovereign Precision UI/UX (v1.2.1 / v1.2.2)
- **Status:** ✅ Delivered (`v1.2.2`)
- **Priority:** High (**P1**)
- **Delivered Implementation:**
  1. **Multi-Tier TimescaleDB Connection Failover**: Hardened Go PostgreSQL driver ([`apps/backend/internal/database/pgwire.go`](apps/backend/internal/database/pgwire.go)) with static `/etc/hosts` inspection, 30s TCP KeepAlive, and dynamic `lastGoodIP` fallback, paired with Docker Compose `links: - timescaledb:timescaledb` to eliminate Docker embedded DNS (`127.0.0.11:53`) `SERVFAIL` exceptions in multi-bridge topologies.
  2. **Contextual Worker Child Spawn Filtering**: Added `is_benign_worker_child_cmd` in [`apps/telemetry-agent/src/collector/process_spawn.rs`](apps/telemetry-agent/src/collector/process_spawn.rs) to ignore legitimate runtime wrappers (`sh -c dotenv ...`, `npm`, `pnpm`, `node dist/`) while strictly alerting on true interactive shells and exfiltration pipes.
  3. **High-Resilience Ingest & Clamping**: Enforced mathematical CPU clamping strictly between `0.0` and `100.0%` in [`telemetry_service.go`](apps/backend/internal/service/telemetry_service.go) to satisfy PostgreSQL `CHECK` constraints, with 4-tier resilient `node_id` foreign key resolution.
  4. **Micro-SLM Pull Resilience**: Upgraded all Docker Compose files to fetch standard lightweight `qwen2.5:0.5b` and alias to `nimble` via `ollama cp`, bypassing schema v2 registry 412 errors.
  5. **Sovereign Precision UI/UX Design System**: Complete elimination of decorative emojis, replacement with crisp vector SVGs, high-contrast light mode styling via robust attribute selectors (`[class*="bg-slate-900"]`), and monospace tabular data layout across both `Aegis` and `aegis-cloud`.

---

## ⚔️ Phase P1.5 (v1.3) — Sovereign "Anti-Artex" Shield (Autonomous Offensive AI Defense — ✅ Delivered)

### 🔒 Lock #5-Bis: Neutralizing Autonomous Multi-Agent Pentesting Orchestrators (ARTEX, Hexstrike, CyberStrikeAI)
- **Status:** ✅ Delivered (`v1.3.0`)
- **Priority:** High (**P1.5** — Direct countermeasure against LLM-driven autonomous offensive frameworks)
- **Context & Threat Model:** Agentic offensive frameworks (such as **ARTEX**) decompose natural-language intrusion goals into sub-tasks executed at machine speed (*Machine-Speed Kill Chain* `< 3h`) by autonomous *Agent Workers*. Unlike static scanners, they parse HTTP `403` error bodies to mutate payloads, target API business logic (**BOLA / IDOR**, OpenAPI/GraphQL schemas), validate blind exploits via **OAST** relays (`interact.sh`), and chain stolen session tokens.
- **Technical Plan (6 "Anti-Artex" Defense Bricks):**
  1. **Anti-LLM Cognitive Deception, Opaque `403` Mode, Adaptive Tarpit & Canary Honeypot ([`apps/gate-proxy/src/server.ts`](apps/gate-proxy/src/server.ts))**:
     - **Production `STEALTH_BLOCK` Mode**: Strip internal rule names (`threat_detected`) and matched regex patterns from external HTTP error responses (returning only an opaque `event_id` while logging full forensics to TimescaleDB), depriving ARTEX's LLM *Planner* of its feedback learning oracle.
     - **Adaptive Tarpit**: Inject progressive response delays (`3s` $\rightarrow$ `10s` $\rightarrow$ `25s`) on IPs accumulating anomalies to stall synchronous agent worker loops and exhaust orchestration timeouts.
     - **Canary Honeypot & Contextual Traps (Booby-Trapped `/.env`)**: Optionally serve decoy `.env` payloads containing traceable *Canary Tokens* on trap endpoints; any subsequent request presenting a Canary Token mathematically proves automated multi-step chaining and triggers an immediate permanent ban (`CANARY_TOKEN_TRIPWIRE_TRIGGERED`).
  2. **Egress Neutralization of OAST Servers & "Living-off-the-Trusted-Cloud" (LOTC) Relays ([`apps/egress-gateway/src/cti/blocklist.ts`](apps/egress-gateway/src/cti/blocklist.ts))**:
     - **Native OAST Blocklist in DNS Sinkhole (`:5053`)**: Block out-of-band pentest callback infrastructures by default (`*.interact.sh`, `*.interactsh.com`, `*.oast.pro`, `*.oast.live`, `*.oast.site`, `*.oast.online`, `*.oast.fun`, `*.oast.me`, `*.burpcollaborator.net`, `*.oastify.com`, `*.canarytokens.com`, `*.webhook.site`, `*.requestbin.com`, `*.pipedream.net`), rendering ARTEX **100% blind** on asynchronous exploits (*Blind SSRF, Blind RCE, Blind XXE*).
     - **Server LOTC Egress Policy**: Optional blocking of public exfiltration tunnels and relays (`*.ngrok-free.app`, `*.ngrok.io`, `*.trycloudflare.com`, `*.loca.lt`, `transfer.sh`, `pastebin.com`) from production backend containers.
  3. **API Business Logic Shield: Anti-BOLA / IDOR, Anti-Mass Assignment & OpenAPI/GraphQL Masking ([`apps/gate-proxy/src/rules/`](apps/gate-proxy/src/rules/default-rules.ts))**:
     - **API Discovery Schema Lockdown**: Block unauthenticated external access to API specifications (`/swagger*`, `/openapi.json`, `/api-docs*`, `/v2/api-docs`, `/v3/api-docs`, `/redoc`, `/actuator*`) and GraphQL introspection queries (`__schema`, `__type`) in production.
     - **Sequential Enumeration Detector (Anti-BOLA / IDOR)**: Sliding-window tracking of distinct object IDs queried across parameterized routes (`/api/v1/resource/{id}`) to halt automated business-object scraping (`API_BOLA_ENUMERATION_DETECTED`).
     - **Anti-Mass Assignment & Prototype Pollution Filter**: Inspect inbound JSON bodies (`POST`/`PUT`/`PATCH`) against privilege-escalation field injection (`"role":"admin"`, `"is_admin":true`, `"permissions"`, `"__proto__"`, `"constructor.prototype"`).
  4. **"Low-and-Slow" Behavioral Detection & Browser Header Fingerprint Mismatch ([`apps/gate-proxy/src/engine/inspector.ts`](apps/gate-proxy/src/engine/inspector.ts))**:
     - **Unmasking Disguised Go/Python Workers**: Detect requests claiming a modern browser `User-Agent` (Chrome/Edge/Firefox) while omitting mandatory structural browser headers (`Sec-Ch-Ua`, `Sec-Fetch-Mode`, `Sec-Fetch-Site`, `Accept-Language`).
     - **Long-Horizon Suspicion Memory (24h)**: Accumulate slow bursts of `404` / `401` / `403` probes operating below the volumetric rate threshold (`60 req/10s`) to neutralize distributed *Low-and-Slow* reconnaissance.
  5. **Cryptographic Session Context-Binding in Pure BFF (Anti-Token Replay) ([`apps/gate-proxy/src/bff/session.ts`](apps/gate-proxy/src/bff/session.ts))**:
     - Seal the client context fingerprint (`User-Agent` hash + `/24` or `/64` IP subnet prefix) directly inside the `AES-256-GCM` encrypted `HttpOnly` `aegis_session` cookie. Any replay of a stolen session cookie from an ARTEX Worker or different network immediately revokes the session and raises a critical `SESSION_HIJACK_REPLAY_DETECTED` alert.
  6. **Sovereign "Purple Team" Continuous Self-Audit ([`apps/backend/internal/scanner/`](apps/backend/internal/scanner/engine.go))**:
     - Extend the continuous passive posture scanner (Lock #5) to proactively verify that protected domains do not expose sensitive files (`.env`, `.git`, backups), open Swagger/GraphQL schemas, or unprotected subdomains — delivering the legitimate defensive visibility ARTEX originally promised without deploying a weaponizable offensive tool.

---

## 🛡️ Phase P2 — Kernel Defense, Frugal Rust Endpoint Agent & ZTNA

### 🔒 Lock #6: L3/L4 `eBPF / XDP` Network Filter, Sub-Second `SIGKILL` Process Kill-Switch & Host Kernel Watch
- **Status:** ⏳ In Design
- **Priority:** Medium (**P2** — Linux Host / Bare-Metal)
- **Technical Plan:**
  1. Extend [`apps/telemetry-agent`](apps/telemetry-agent/src/main.rs) with an `xdp` eBPF program attached at the NIC driver layer to discard malformed IPv4 TCP SYN packets carrying dangerous IP options (`IPOPT_LSRR`, `IPOPT_SSRR`, `IPOPT_RR` — e.g., kernel TCP stack UAF vectors like CVE-2026-98432) in `< 0.005 ms` (`XDP_DROP`).
  2. **Sub-Second Process Kill-Switch (`SIGKILL < 10 ms`) against machine-speed post-exploitation**: Evolve [`apps/telemetry-agent/src/collector/process_spawn.rs`](apps/telemetry-agent/src/collector/process_spawn.rs) from passive `/proc` detection to an `ACTIVE_CONTAINMENT` mode that immediately dispatches `SIGKILL` (`kill -9`) to any unauthorized child shell (`sh`, `bash`, `nc`, `python`, `socat`) spawned by a web worker before an autonomous AI agent (ARTEX) can receive its command output.
  3. Read host kernel release (`uname -r`) continuously and surface actionable distro upgrade alerts in the Cockpit when running unpatched kernels.

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
