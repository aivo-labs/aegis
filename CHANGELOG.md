# 📋 Changelog — Aegis Sovereign Gate

<p align="center">
  <strong>English</strong> | <a href="CHANGELOG.fr.md">Français</a> •
  <a href="README.md">README</a> •
  <a href="ROADMAP.md">Roadmap</a> •
  <a href="CONTRIBUTING.md">Contributing (Gitflow)</a>
</p>

All notable changes to **Aegis Sovereign Gate** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres strictly to [Semantic Versioning (SemVer 2.0.0)](https://semver.org/spec/v2.0.0.html) and the [Gitflow](https://nvie.com/posts/a-successful-git-branching-model/) release lifecycle:
- **`MAJOR` (`vX.0.0`)**: Breaking architectural or API changes.
- **`MINOR` (`v1.X.0`)**: New security locks, passive scanner probes, telemetry capabilities, or backward-compatible features merged via `release/v1.X.0` into `main`.
- **`PATCH` (`v1.0.X`)**: Critical security fixes or bug fixes merged via `hotfix/v1.0.X` or `release/v1.0.X` into `main`.

---

## [Unreleased]

---

## [1.3.0-beta] — 2026-11-21 (Tag `v1.3.0-beta` on `main`)

### Added
- **Lock #5-Bis (P1.5 High) — Sovereign "Anti-Artex" Shield (Autonomous Offensive AI Defense)**:
  - **Egress OAST & LOTC Sinkhole (`apps/egress-gateway`)**: Sub-`0.5 ms` interception of 19 out-of-band blind exploit callback domains (*Blind SSRF/RCE/XXE*: `*.interact.sh`, `*.oast.*`, `*.burpcollaborator.net`, `*.oastify.com`, `*.webhook.site`, `*.canarytokens.com`) and exfiltration tunnels (`*.ngrok-free.app`, `*.trycloudflare.com`, `transfer.sh`).
  - **API Business Logic & Anti-BOLA/IDOR Shield (`apps/gate-proxy/src/rules/anti-artex.rule.ts`, `ip-reputation.ts`)**: Production lockdown of `/swagger*`, `/openapi.json`, `/api-docs*`, `/actuator*`, and GraphQL introspection (`__schema`); sliding-window sequential object ID enumeration detection (`API_BOLA_IDOR_ENUMERATION`); *Mass Assignment* & prototype pollution blocking (`is_admin`, `user_role`, `__proto__`).
  - **Disguised AI Worker Detection (`scanner.rule.ts`)**: Signatures for autonomous AI pentesting agents (`artex`, `hexstrike`, `cyberstrike`, `pentestgpt`, `xbow`, `cairn`) and browser header fingerprint mismatch detection (`AI_AGENT_SPOOFED_BROWSER_FINGERPRINT` on fake Chrome/Edge `User-Agent` headers lacking `Sec-Ch-Ua` / `Sec-Fetch-Mode`).
  - **Anti-LLM Cognitive Deception (`server.ts`)**: `STEALTH_BLOCK` opaque `403` mode (depriving LLM *Planners* of error-feedback oracles), **Adaptive Tarpit** (`3s` $\rightarrow$ `10s` $\rightarrow$ `25s`), and **Canary Honeypot (`/.env.canary`)** with immediate ban on token replay (`CANARY_TOKEN_TRIPWIRE_TRIGGERED`).
  - **Pure BFF Cryptographic Context-Binding (`bff/session.ts`)**: Seals client context fingerprint (`User-Agent` + `/24` or `/64` IP subnet) inside the `AES-256-GCM` session cookie to prevent stolen session replay.

### Fixed
- **Traefik ForwardAuth (`/_aegis/verify`) Full Parity & Docker Bridge Gateway Auto-Jail Safety**:
  - Decoupled Auto-Jail exemption (SOC admin IPs and Docker internal bridge gateways `172.16.0.0/12` ending in `.1`) from WAF threat inspection so pentest probes consistently trigger `HTTP 403` blocks without collateral auto-banning.
  - Full ForwardAuth telemetry parity (`BLOCK`, `BYPASS`, `ALLOW` with `X-Aegis-Verified` deduplication) and TimescaleDB Auto-Jail persistence.
  - Extended static `/etc/hosts` `links` across all internal services in all `docker-compose*.yml` manifests.

---

## [1.2.2-beta] — 2026-11-21 (Tag `v1.2.2-beta` on `main`)

### Fixed
- **TimescaleDB Ingestion DNS Failover & `/etc/hosts` Resolution**:
  - Resolved intermittent Docker embedded DNS (`127.0.0.11:53`) SERVFAIL errors in the Go backend (`apps/backend/internal/database/pgwire.go`) via direct `/etc/hosts` parsing, 30s TCP KeepAlive, and runtime failover to the last-known-good IP address.
  - Added `links: - timescaledb:timescaledb` in `docker-compose.yml`, `docker-compose.dokploy.yml`, and `deploy/docker-compose/docker-compose.yml`.
- **Zero-Metrics Fallback & Conditional Cache Locking**:
  - Resolved blank overview cockpit metrics by adding global fallback queries in `DashboardService` (`dashboard_service.go`) when tenant-scoped queries return empty sets, preventing persistent 0-metric cache states.
- **Telemetry Agent Process Spawn Filtering & CPU Clamping**:
  - Implemented `is_benign_worker_child_cmd` in `apps/telemetry-agent` to eliminate false-positive P1 host shell spawn alerts on legitimate development/runtime wrappers (`node`, `npm`, `dotenv`), while retaining real-time interception for hostile shells (`nc`, `bash -i`).
  - Clamped CPU utilization mathematically to `[0.0, 100.0]%` to ensure rock-solid energy Joules calculations.
- **Ollama Micro-SLM Resilience**:
  - Added fallback alias to `qwen2.5:0.5b` for `nimble`, resolving HTTP 412 model manifest pull failures across older and newer Ollama engine builds.
- **Light Theme Contrast & Sovereign Precision Polish**:
  - Fixed low-contrast elements (grey-on-grey card text, CVE feed cards) in Cockpit and harmonized the vector SVG design system across all pages.

---

### Added
- **Lock #1 (P0 Critical) — Strict Egress Network Confinement & Anti-Reverse Shell DNS-to-IP Allowlist**:
  - Added [`apps/egress-gateway/src/engine/ip-allowlist.ts`](apps/egress-gateway/src/engine/ip-allowlist.ts) (`DnsToIpAllowlist` with 60s TTL) and `POST /api/v1/egress/verify-connection` in [`tcp-server.ts`](apps/egress-gateway/src/http/tcp-server.ts), blocking direct raw-IP callbacks (`RAW_IP_REVERSE_SHELL_BLOCKED`) and unapproved outbound IP sockets (`UNRESOLVED_DIRECT_IP_EGRESS_BLOCKED`).
  - Segmented Docker networks in [`docker-compose.yml`](docker-compose.yml) and [`docker-compose.dokploy.yml`](docker-compose.dokploy.yml) (`aegis-internal` with `internal: true` + `aegis-edge`) and added host nftables policy [`deploy/security/egress-lockdown.nft`](deploy/security/egress-lockdown.nft).
- **Lock #2 (P1 High) — Multi-Encoding Anti-Obfuscation Canonicalization (Base64 / HTML / Hex / Path)**:
  - Upgraded [`apps/gate-proxy/src/engine/canonicalizer.ts`](apps/gate-proxy/src/engine/canonicalizer.ts) and [`apps/web/src/services/sandboxEngine.ts`](apps/web/src/services/sandboxEngine.ts) with HTML entity decoding (named, decimal, hex), Hex/Unicode escapes (`\x..`, `\u....`, `%u....`), path separator normalization (`/./`, `//`, `\`), and automatic Base64 payload extraction and decoding (`>= 16` chars).
- **Lock #3 (P1 High) — Volumetric Rate-Limiting (`HTTP 429`) & Automated 15-Minute IP Auto-Jail**:
  - Added sliding-window rate limiting (`60 req / 10s` per IP with `Retry-After: 10`) and automated **15-minute Auto-Jail** (`AUTO_JAIL_TEMPORARY_QUARANTINE`) after `3` critical WAF blocks (`risk_score >= 90`) within `5` minutes in [`apps/gate-proxy/src/quarantine/ip-reputation.ts`](apps/gate-proxy/src/quarantine/ip-reputation.ts), synced with the Go Control Plane (`ttlMinutes` / `expires_at`).
- **Lock #4 (P1 High) — HTTP Protocol Hardening (`HTTP 431`), Multipart RFC & Rust Anti-Spawn Shell Probe**:
  - Enforced HTTP header limits (`> 8 KB` total, `> 4 KB` single header, or `> 64` headers returning `HTTP 431`), `multipart/form-data` RFC boundary & nesting validation (`<= 3` depth, blocking executable upload extensions `.php`, `.phtml`, `.phar`, `.sh`), and multi-encoding compression-bomb chaining detection in [`apps/gate-proxy/src/engine/inspector.ts`](apps/gate-proxy/src/engine/inspector.ts).
  - Added Rust procfs collector [`apps/telemetry-agent/src/collector/process_spawn.rs`](apps/telemetry-agent/src/collector/process_spawn.rs) scanning `/host/proc` and `/proc` to detect child shells (`sh`, `bash`, `nc`, `curl`, `python`, `socat`) spawned by web workers (`php-fpm`, `node`, `nginx`, `caddy`).
- **Lock #5 (P1 High) — Continuous Scheduled Posture Audits, Drift Detection & Guided Remediation Wizard**:
  - Added `GET/POST /api/v1/audit/schedule`, automated posture drift detection (`EvaluatePostureDrift`), and ready-to-deploy hardening snippets (`GenerateGuidedRemediationSnippets` for Traefik, Nginx, Caddy, and Apache/`php.ini`) in [`audit_service.go`](apps/backend/internal/service/audit_service.go) and [`AuditPanel.vue`](apps/web/src/components/soc/actions/AuditPanel.vue).

### Changed
- **"Aegis Sovereign Precision" UI/UX Redesign (Eliminating the AI-Generated Aesthetic)**:
  - Created monochrome vector SVG icon component [`AegisIcon.vue`](apps/web/src/components/soc/AegisIcon.vue) (`stroke-width: 1.75px`) replacing raw Unicode emojis across the SOC Cockpit and Landing Page.
  - Enforced strict `90/5/5` chromatic restraint (`slate-950`/`slate-900` surfaces, `1px` `slate-800` hairlines, unified `emerald-400` brand accent, semantic alert colors reserved strictly for active telemetry), tightened border radii (`rounded-lg` = `8px`), applied dual typography (`font-sans` for UI labels and prose; `font-mono tabular-nums` for metrics, IPs, CVEs, and Watts), and removed promotional slogans from the operational Cockpit.

---

## [1.1.0] — 2026-11-15 (Tag `v1.1.0` on `main`)

### Added
- **Post-Quantum Cryptography Readiness Probe (`X25519MLKEM768` — NIST FIPS 203)**:
  - Added [`apps/backend/internal/scanner/pqc.go`](apps/backend/internal/scanner/pqc.go) and [`pqc_test.go`](apps/backend/internal/scanner/pqc_test.go) to perform a passive TLS 1.3 handshake (`InspectDomainPQC`) proposing hybrid group `X25519MLKEM768` (`0x11ec`) and pre-standard `X25519Kyber768Draft00` (`0x6399`).
  - Added `PQCAnalysis` (`post_quantum`) to `PassiveAuditResult` in [`apps/backend/internal/domain/audit.go`](apps/backend/internal/domain/audit.go) with *Harvest Now, Decrypt Later (HNDL)* risk scoring and copy-paste remediation snippets for **Traefik**, **Nginx**, **Caddy**, and **Go TLS**.
  - Added automatic `Cryptographie TLS Post-Quantique (NIST FIPS 203)` fingerprint badge when `0x11ec` is negotiated, or a `PQC-HNDL-EXPOSURE` warning with step-by-step remediation when classical ECDHE (`X25519` / `P-256`) is negotiated.
- **Official Passive Scanner & Post-Quantum Documentation (FR/EN)**:
  - Added bilingual documentation pages [`apps/docs/src/content/docs/security/passive-scanner.md`](apps/docs/src/content/docs/security/passive-scanner.md) and [`apps/docs/src/content/docs/fr/security/passive-scanner.md`](apps/docs/src/content/docs/fr/security/passive-scanner.md) covering the 2-tier Legal-by-Design scanner architecture (Tier 1 passive EcoIndex/DNS/Headers/CVE/PQC vs Tier 2 cryptographic ownership mandate under Article 323-1 CP).
- **Changelog & Gitflow Versioning Documentation**:
  - Added bilingual [`CHANGELOG.md`](CHANGELOG.md) and [`CHANGELOG.fr.md`](CHANGELOG.fr.md) along with step-by-step Gitflow release tagging procedures (`release/vX.Y.Z` & `hotfix/vX.Y.Z` -> `git tag -a vX.Y.Z`) in [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CONTRIBUTING.fr.md`](CONTRIBUTING.fr.md).

### Changed
- **Go 1.25 Toolchain Upgrade**:
  - Upgraded `apps/backend/go.mod`, `apps/backend/Dockerfile`, and `.github/workflows/ci.yml` from Go `1.22` to **Go `1.25`** to leverage native `crypto/tls` support for `tls.X25519MLKEM768` and `tls.ConnectionState.CurveID`.
- **Technical Roadmap Alignment (Locks #5, #8, #10, and #11)**:
  - Synchronized [`ROADMAP.md`](ROADMAP.md), [`ROADMAP.fr.md`](ROADMAP.fr.md), [`README.md`](README.md), and [`README.fr.md`](README.fr.md) with the delivered **NIST FIPS 203 `X25519MLKEM768`** passive probe (Lock #5), **Post-Quantum hybrid `mTLS`** endpoint telemetry channel (Lock #8), **"Two-Door & Zero-Secret Placeholder"** AI egress DLP pattern (Lock #10), and **Zero-Trust MCP Gateway (`tools/list`, `tools/call`) + `Ed25519 + ML-DSA` (FIPS 204)** EU AI Act audit ledger (Lock #11).

---

## [1.0.0] — 2026-11-14 (Tag `v1.0.0` on `main`)

### Added
- **Initial Public Release of Aegis Sovereign Gate (AGPLv3)**:
  - **Ingress PEP Gateway (`apps/gate-proxy`)**: Zero-Trust edge Policy Enforcement Point operating in both Reverse-Proxy and Traefik/Nginx `ForwardAuth` (`/_aegis/verify`) modes, featuring recursive URL/Hex/Unicode canonicalization, RFC 413 payload truncation (32 KB cap), mathematical Shannon Entropy ($H$) shellcode detection, OWASP Top 10 / scanner signature filtering, and hot Virtual Patching (`CVE-2024-4577` PHP2Shell, Log4Shell, path traversal) in `< 1.5 ms`.
  - **Pure BFF OIDC Authentication**: Token Handler pattern with OAuth2/OIDC PKCE (Keycloak, Okta, Authelia, Authentik) and `HttpOnly; Secure; SameSite=Strict` cookies sealed with **AES-256-GCM** (`zero tokens in browser storage`).
  - **Egress Gateway & Sovereign Local AI (`apps/egress-gateway` + `infra/coredns`)**: Dual-layer outbound filtering combining CoreDNS RPZ sinkholing (~15 MB RAM) with asynchronous behavioral and DGA inspection powered by a local quantized **Qwen 3.5 9B (`Q4_K_M`)** SLM via Ollama (`zero cloud data exfiltration`).
  - **Go Control Plane & 2-Tier Passive Scanner (`apps/backend`)**:
    - Tier 1 passive domain scanner (RGESN EcoIndex quantile engine, hierarchical RFC 7489 DMARC & RFC 7208 SPF DNS resolver, security headers scorer, passive tech fingerprinting, and CVE/CISA KEV virtual patching coverage matrix).
    - Tier 2 deep exposure probes (`/.env`, `/.git/config`, `/phpinfo.php`, `/wp-login.php`, `/xmlrpc.php`) unlocked strictly after DNS `TXT` or `/.well-known/aegis-verify.txt` ownership verification and `SHA-256` legal mandate sealing.
  - **Hardware RAPL & GreenOps Telemetry (`agents/energy-agent` & TimescaleDB)**: Native Rust daemon reading physical Intel/AMD **RAPL** silicon counters (`/sys/class/powercap/intel-rapl:0`), `/proc/stat`, and Kubernetes **Kepler eBPF** metrics, paired with deterministic **CSRD / EFRAG VSME** PDF certificate generation.
  - **Unified SOC & GreenOps Cockpit (`apps/web`) & Starlight Documentation (`apps/docs`)**: Bilingual (FR/EN) Astro 5 + Vue 3 islands operational cockpit, interactive sandbox replay, and comprehensive deployment guides (Dokploy/Traefik, VPS Docker Compose, Bare-Metal RAPL, Kubernetes Helm, Standalone Agent).
  - **Open-Source Governance**: Added [`VISION.md`](VISION.md) / [`VISION.fr.md`](VISION.fr.md), [`ROADMAP.md`](ROADMAP.md) / [`ROADMAP.fr.md`](ROADMAP.fr.md), [`CONTRIBUTING.md`](CONTRIBUTING.md) / [`CONTRIBUTING.fr.md`](CONTRIBUTING.fr.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), [`SECURITY.md`](SECURITY.md), [`LICENSE`](LICENSE) (GNU AGPLv3), and Architecture Decision Records ([`docs/adr/ADR-0001`](docs/adr/ADR-0001-pure-bff-token-handler.md) through [`ADR-0007`](docs/adr/ADR-0007-keycloak-sso-iam-theming.md)).
