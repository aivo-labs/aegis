# 🤝 Contributing to Aegis Sovereign Gate

<p align="center">
  <strong>English</strong> | <a href="CONTRIBUTING.fr.md">Français</a>
</p>

Thank you for your interest in contributing to **Aegis Sovereign Gate**! Before submitting a pull request, please read our [Vision & Engineering Principles](VISION.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## 1. Gitflow Branching Model (Mandatory)

Aegis strictly follows Vincent Driessen's **Gitflow** branching workflow ([*A successful Git branching model*](https://nvie.com/posts/a-successful-git-branching-model/)).

```
main       ────●─────────────────────────────●───────────●──── (Production Tags: v1.0.0, v1.1.0, v1.1.1)
                \                           /           /
hotfix/*         \                         /           ●────── (Critical production fixes from main)
                  \                       /           /
release/*          \                 ●───●           /
                    \               /     \         /
develop    ──────────●──────●──────●───────●───────●────────── (Integration branch)
                      \    /        \     /
feature/*              ●──●          ●───●                     (Topic branches from develop)
```

### Permanent Branches
* **`main`**: Production-ready state **only**. Direct commits to `main` are forbidden. Every merge into `main` produces a tagged release (`vX.Y.Z`).
* **`develop`**: Primary integration branch containing the latest delivered development changes for the next release.

### Supporting Branches
1. **`feature/<scope>-<short-description>`** (e.g. `feature/pqc-readiness`, `feature/waf-base64-decoder`)
   * **Branched from**: `develop`
   * **Merged back into**: `develop` (via Pull Request / `--no-ff`)
   * **Commands**:
     ```bash
     git checkout develop
     git pull origin develop
     git checkout -b feature/scanner-pqc-readiness develop
     ```
2. **`release/vX.Y.Z`** (e.g. `release/v1.1.0`)
   * **Branched from**: `develop` when features for the upcoming release are complete.
   * **Purpose**: Semantic Versioning (`SemVer 2.0.0`) bump, moving `[Unreleased]` entries into `[X.Y.Z] — YYYY-MM-DD` in [`CHANGELOG.md`](CHANGELOG.md) and [`CHANGELOG.fr.md`](CHANGELOG.fr.md), and release stabilization (no new features).
   * **Merged back into**: `main` (with an **annotated Git tag `vX.Y.Z`**) **and** back-merged into `develop`:
     ```bash
     # 1. Cut release branch from develop & update CHANGELOG.md / CHANGELOG.fr.md
     git checkout -b release/v1.1.0 develop
     git commit -am "chore(release): prepare v1.1.0 changelog and version metadata"

     # 2. Merge into main & create annotated SemVer tag
     git checkout main
     git merge --no-ff release/v1.1.0 -m "Merge branch 'release/v1.1.0' into main"
     git tag -a v1.1.0 -m "Release v1.1.0"

     # 3. Back-merge into develop & remove temporary release branch
     git checkout develop
     git merge --no-ff release/v1.1.0 -m "Merge branch 'release/v1.1.0' into develop"
     git branch -d release/v1.1.0
     ```
3. **`hotfix/vX.Y.Z`** (e.g. `hotfix/v1.0.1`)
   * **Branched from**: `main` to resolve a critical security or production bug immediately.
   * **Merged back into**: `main` (tagged `vX.Y.Z` via `git tag -a vX.Y.Z`) **and** `develop`, with a corresponding entry in [`CHANGELOG.md`](CHANGELOG.md) and [`CHANGELOG.fr.md`](CHANGELOG.fr.md).

---

## 2. Commit Message Convention (Conventional Commits)

All commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```text
<type>(<optional-scope>): <concise imperative summary in English>
```

* **`feat`**: A new security lock, probe capability, or cockpit feature (`feat(scanner): add NIST FIPS 203 X25519MLKEM768 PQC readiness probe`).
* **`fix`**: A bug fix (`fix(rse): resolve blank page when printing CSRD PDF certificate`).
* **`security`**: A security hardening change or vulnerability mitigation.
* **`perf`**: A latency, memory, or energy optimization (`perf(gate-proxy): reduce Shannon entropy buffer allocations`).
* **`docs`**: Documentation, ADR, or roadmap updates (`docs(roadmap): align Locks #5, #8, #10 and #11 with PQC and MCP governance`).
* **`test`**: Adding or updating unit/integration/pentest suites.
* **`chore` / `ci`**: Build scripts, Dockerfiles, or GitHub Actions workflows.

---

## 3. Local Development & Verification Suite

Before opening a Pull Request against `develop`, ensure all relevant checks pass locally:

### A. Go Control Plane & Passive Scanner (`apps/backend`)
```bash
cd apps/backend
go test -v ./...
```

### B. TypeScript Gateways & Web Cockpit (`apps/gate-proxy`, `apps/egress-gateway`, `apps/web`, `apps/docs`)
```bash
pnpm install
pnpm --filter @aivo/aegis-gate-proxy build
pnpm --filter @aivo/aegis-egress-gateway build
pnpm test
pnpm --filter @aivo/aegis-web build
pnpm --filter @aivo/aegis-docs build
```

### C. Rust Hardware Telemetry Probe (`apps/telemetry-agent`)
```bash
cd apps/telemetry-agent
cargo check
cargo test
```

### D. End-to-End Docker & Pentest Battery
```bash
docker compose up -d --build timescaledb backend gate-proxy web egress-gateway
./scripts/run-pentest-demo.sh
docker compose down -v
```

---

## 4. Engineering & Documentation Standards

1. **Zero Bloat & Frugality First**: Avoid adding external libraries when standard library primitives (`crypto/tls`, `net/http`, Node `node:crypto`, `node:http`) suffice.
2. **Bilingual Parity (EN & FR)**: Any change to `README.md`, `ROADMAP.md`, `VISION.md`, or Starlight documentation (`apps/docs/src/content/docs/`) must be mirrored in its French counterpart (`README.fr.md`, `ROADMAP.fr.md`, `VISION.fr.md`, `apps/docs/src/content/docs/fr/`).
3. **Architecture Decision Records (`docs/adr/`)**: Significant architectural changes must be documented in a new or updated ADR.
4. **Never Commit Secrets**: Never commit `.env` files, private TLS keys, or raw customer telemetry dumps.
