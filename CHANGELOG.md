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

## [Unreleased] — Target `v1.1.0` (`develop`)

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
