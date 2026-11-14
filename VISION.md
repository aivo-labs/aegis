# 🧭 Aegis Sovereign Gate — Vision & Engineering Principles

<p align="center">
  <strong>English</strong> | <a href="VISION.fr.md">Français</a>
</p>

## 1. Why Aegis Exists: Our Mission

Modern cybersecurity and AI governance suffer from a structural paradox:
1. **Prohibitive complexity and pricing**: Enterprise security suites (hyperscaler WAFs, managed SOCs, GPU-backed AI guardrails, heavy EDRs) are engineered and priced for Fortune 500 corporations with dedicated SecOps teams. Small and medium-sized businesses (SMBs), mid-market enterprises (ETIs), independent SaaS builders, and public institutions are left with an impossible choice: pay a punitive per-seat "SaaS tax" or leave their infrastructure exposed.
2. **Digital dependency and opacity**: Relying exclusively on non-sovereign cloud proxies to inspect traffic, store identity tokens, or filter AI prompts means surrendering confidentiality and cryptographic control to third parties.
3. **Computational and environmental waste**: Nearly 40% of internet traffic consists of automated vulnerability scanners, credential stuffers, and exploit bursts. Letting this parasitic traffic reach application runtimes (PHP-FPM, Node.js, Python, JVM) or GPU inference pools wastes massive amounts of electricity—while traditional carbon calculators hide this reality behind fictional spend-based monetary ratios.

**Aegis Sovereign Gate** was created by **AIVO** to break this deadlock:
> **Our mission is to make Zero-Trust cybersecurity, digital sovereignty, verifiable GreenOps, and AI governance accessible to every organization—deployable in 5 minutes on a single VPS or Kubernetes cluster, auditable in open source, and operating under 15 Watts.**

---

## 2. The 6 Core Engineering Principles

Every architectural decision (`ADR`), pull request, and roadmap lock in Aegis is governed by six non-negotiable principles:

### Principle #1 — Mathematics & Determinism Before AI
AI should never be the first line of defense when a deterministic mathematical function can solve 95% of the problem in microseconds.
* Aegis screens inbound and outbound payloads using **Shannon information entropy ($20\ \mu\text{s}$)**, canonicalization, and deterministic virtual patching (`gate-proxy`) before invoking any language model.
* **Result**: During a sustained `CVE-2024-4577` (`PHP2Shell`) exploit burst, Aegis blocks 100% of attacks at the edge while keeping the target application container at **`0%` CPU** and **`5.81 W` average power** (versus `743.4%` peak CPU and `24.14 W` without protection). A blocked request never burns an application CPU cycle or a single LLM token.

### Principle #2 — Silicon Physics Over Financial Greenwashing
You cannot optimize what you estimate from cloud invoices.
* Aegis rejects spend-based carbon estimation (`€ spent × generic factor`).
* Our Rust probe (`telemetry-agent`) reads real physical energy counters directly from **Intel/AMD RAPL** hardware registers (`/sys/class/powercap`) and Linux kernel **eBPF (`Kepler`)** telemetry, producing tamper-evident **CSRD / EFRAG Scope 2** certificates in Joules, Watts, and $\text{gCO}_2\text{eq}$.

### Principle #3 — Two-Door Boundary & Zero-Secret Architecture
*"Governance inside every application is governance nowhere."* Security and AI rules must not rely on each application or autonomous agent policing itself; they must be enforced at the network boundaries every request crosses:
```
[ Caller / User / Webhook ]
           │
           ▼
╔══════════════════════════════════════════════════════════╗
║ DOOR 1 — Ingress PEP (gate-proxy)                        ║
║ • Pure BFF OIDC (Zero JWT in browser JS / AES-256-GCM)   ║
║ • Deterministic WAF, Shannon Entropy & Prompt Guardrails ║
╚══════════════════════════════════════════════════════════╝
           │
           ▼
┌──────────────────────────────────────────────────────────┐
│ Confined Workload / AI Agent Sandbox (internal: true)    │
│ • Holds ZERO raw API keys (only Placeholder tokens)      │
│ • Ephemeral Linux kernel confinement (seccomp / eBPF)    │
└──────────────────────────────────────────────────────────┘
           │
           ▼
╔══════════════════════════════════════════════════════════╗
║ DOOR 2 — Egress Gate (egress-gateway)                    ║
║ • DNS Sinkhole (:5053), Anti-DGA & C2 Blocklist          ║
║ • MCP Tool Filtering by Agent Identity & PII Masking     ║
║ • Just-in-Time Vault Secret Injection & AI Act Ledger    ║
╚══════════════════════════════════════════════════════════╝
```
* **In the Browser (Pure BFF)**: Client JavaScript never sees `access_token` or `refresh_token`.
* **In the Agent Sandbox (Zero-Secret Placeholders)**: Autonomous agents never hold real third-party API keys; `egress-gateway` substitutes placeholders on the way out only when the destination, identity, and policy match.

### Principle #4 — Radical Agnosticism & Sovereign Open-Core
Security infrastructure must adapt to the user's stack, never lock them in:
* **Reverse Proxy Agnostic**: Runs natively behind **Traefik** (`ForwardAuth`), **Nginx** (`auth_request`), **Caddy**, or standalone.
* **Identity Provider Agnostic**: Supports **Keycloak**, **Authelia**, **Okta**, **Microsoft Entra ID**, or Aegis built-in standalone mode.
* **Inference Agnostic & Air-Gapped Ready**: Operates 100% offline without external API keys, with optional local **Ollama** SLMs (`Nimble 9B` in v1, evolving toward sub-1B CPU-only micro-SLMs).

### Principle #5 — Post-Quantum Resilience by Design
Adversaries are already executing **"Harvest Now, Decrypt Later" (HNDL)** campaigns—recording encrypted TLS sessions and mTLS telemetry today to decrypt them once cryptographically relevant quantum computers (CRQCs) mature.
* Aegis embraces **NIST FIPS 203 (`X25519MLKEM768`)** hybrid post-quantum key exchange across its Go Control Plane and Rust probes, pairs it with quantum-resistant **`AES-256-GCM`** session encryption, and audits external domains for Post-Quantum TLS readiness.

### Principle #6 — Actionable Clarity Over Alert Fatigue
An alert that requires a senior security architect to decipher is a failed alert for an SMB.
* Every finding in the Aegis SOC Cockpit—whether a missing HTTP security header, an aging TLS configuration, an exposed software version, or a non-PQC cipher suite—is accompanied by a clear risk explanation and **ready-to-copy remediation snippets** (Nginx, Traefik, PHP, Docker).

---

## 3. Explicit Non-Goals (What Is Out of Scope)

To preserve our `< 200 MB RAM` footprint, 5-minute deployment time, and code auditability, Aegis deliberately **excludes**:
1. **Heavy GPU Cluster Orchestration & Hardware Slicing**: Aegis governs traffic and agent tool calls; it is not a distributed GPU scheduler (like NVIDIA MIG managers, SUSE AI Factory compute pools, or distributed vLLM orchestrators).
2. **Virtual Machine Hypervisors & Custom Linux Distributions**: Unlike KubeVirt/OpenShift Virtualization or immutable OS distributions (`bootc`), Aegis remains completely OS-agnostic and runs on any standard Linux kernel via Docker Compose or Kubernetes.
3. **Internal Developer Portals (IDP / Backstage)**: The Aegis Web Cockpit (`apps/web`) is a unified **SOC, Posture & GreenOps Control Center**, not a software scaffolding catalog.
4. **GPU-Heavy Guardrail Microservices**: Running multi-gigabyte GPU microservices solely to filter prompts contradicts Green IT principles. Aegis prioritizes microsecond deterministic math (`20 µs`) and frugal CPU-only micro-models (`< 1B`).
