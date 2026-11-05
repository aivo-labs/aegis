# 🛡️ Aegis by AIVO — Sovereign Zero-Trust Suite & ESG Cockpit (AGPLv3)

<p align="center">
  <strong>English</strong> | <a href="README.fr.md">Français</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-AGPLv3-emerald?style=flat-square" alt="AGPLv3 License" />
  <img src="https://img.shields.io/badge/Architecture-Zero--Trust-blue?style=flat-square" alt="Zero Trust" />
  <img src="https://img.shields.io/badge/Go-1.22-00ADD8?style=flat-square&logo=go" alt="Go 1.22" />
  <img src="https://img.shields.io/badge/Rust-RAPL-orange?style=flat-square&logo=rust" alt="Rust RAPL" />
  <img src="https://img.shields.io/badge/Astro-5.x-purple?style=flat-square&logo=astro" alt="Astro 5" />
  <img src="https://img.shields.io/badge/NIS%202-Ready-success?style=flat-square" alt="NIS 2 Compliance" />
  <img src="https://img.shields.io/badge/RGESN%20%2F%20EFRAG-Compliant-brightgreen?style=flat-square" alt="Green IT Sobriety" />
</p>

**Operational Control Center (SOC), In-Line Protection (Ingress/Egress) & Verifiable Hardware Energy Governance (RGESN / ANSSI / EFRAG)**

Aegis is a unified software suite built to protect SMB and mid-market information systems while auditing and reducing their environmental footprint under the **Ethical Open-Core (AGPLv3)** model. Engineered in **native Go and Rust**, Aegis runs as an ultra-frugal, transparent overlay (< 200 MB RAM excluding local LLM weights) with zero per-seat SaaS tax.

---

## 🏛️ Architecture & Service Topology

```
                         [ INBOUND TRAFFIC (Ingress Web & API) ]
                                           │
                                           ▼
        ┌─────────────────────────────────────────────────────────────────┐
        │      Aegis Gate PEP / WAF (apps/gate-proxy : Port 8000)         │
        │      In-Line OWASP & Automated Scanner Filter (Nikto, SQLi, RCE)│
        └────────────────────────────────┬────────────────────────────────┘
                      ┌──────────────────┴──────────────────┐
               (Blocked Traffic 403)                 (Legitimate Traffic 200)
                      │                                     │
                      ▼                                     ▼
        ┌───────────────────────────┐         ┌───────────────────────────┐
        │    Aegis Backend (Go)     │         │     Aegis Web Cockpit     │
        │    (apps/backend : 8080)  │ ◀────── │     (apps/web : 4321)     │
        │    • Triage Feed / API    │         │     • Astro 5 + Vue 3     │
        │    • Real Passive Scanner │         │     • Reverse-proxy /docs │
        └─────────────┬─────────────┘         └─────────────┬─────────────┘
                      │                                     │
                      ▼                                     ▼
        ┌───────────────────────────┐         ┌───────────────────────────┐
        │   TimescaleDB (Port 5432) │ ◀────── │   Aegis Docs (Starlight)  │
        │   (Telemetry Hypertables) │         │   (apps/docs : profile)   │
        └───────────────────────────┘         └───────────────────────────┘
                      ▲                                     ▲
                      │ (Hardware Energy Telemetry)         │ (DNS Sinkhole & AI)
        ┌───────────────────────────┐         ┌───────────────────────────┐
        │   Aegis Telemetry Agent   │         │  Aegis Egress (Port 5053) │
        │   (apps/telemetry-agent)  │         │  Hardened CoreDNS + SLM   │
        │   Rust RAPL Sensor (/sys) │         │  Nimble 9B (Ollama :11434)│
        └───────────────────────────┘         └───────────────────────────┘
```

### Port Mapping

| Service | Public Port | Technology | Operational Role |
| :--- | :--- | :--- | :--- |
| **`web`** | **`4321`** (-> 80) | Astro 5, Vue 3, Nginx | **Unified SOC & ESG Cockpit**, Kanban Triage, `/docs/` Gateway. |
| **`gate-proxy`** | **`8000`** | Go / Node.js Reverse-Proxy | **Ingress PEP / WAF Gateway** (latency < 1.5 ms, RAM < 25 MB). |
| **`backend`** | **`8080`** | Native Go (Zero-Mock) | **Go Control Plane API** (Triage feed, passive scanner, metrics). |
| **`egress-gateway`** | **`5053` (UDP/TCP)** | CoreDNS & SLM Inference | **Egress DNS Gateway** (CTI cache + Local Nimble 9B AI). |
| **`telemetry-agent`**| *Host network* | Native Compiled Rust | **Hardware Sensor** (Linux RAPL real Watts via `/sys/class/powercap`). |
| **`timescaledb`** | **`5432`** | PostgreSQL 16 + TimescaleDB| **Sovereign Secure Datastore** (Immutable logs & time-series metrics). |
| **`ollama-nimble`** | **`11434`** | Air-Gapped Ollama | **Local Nimble 9B AI** (0 tokens leaked to 3rd-party US clouds). |
| **`docs`** | *Internal* (`/docs/`) | Astro Starlight | **Official Documentation** (Docker profile `--profile docs`). |

---

## 🎛️ Architecture & Services

Aegis is architected as an autonomous, sovereign Zero-Trust stack with zero dependencies on US Big Tech clouds:

### 1. Ingress PEP & Pure BFF Token Handler (`gate-proxy:8000`)
- **Ultra-low latency (< 1.5 ms)** OWASP Top 10 WAF, Virtual Patching, and Shannon Entropy analyzer.
- **Pure BFF Token Handler**: Authenticates sessions via AES-256-GCM encrypted HttpOnly cookies (OIDC Keycloak or Standalone Sovereign Demo). Tokens never leak to browser JavaScript.

### 2. Unified SOC & ESG Cockpit (`web:4321`)
- Real-time cyber threat map, live streaming attack logs, instant WAF controls, and hardware energy metrics.
- Accessible directly or behind the Ingress PEP at `/app/`.

### 3. Community Portal (`/`)
- Minimalist, sovereign community landing page at `/` (EN) and `/fr/` (FR) providing instant 1-click access to the SOC Cockpit, live documentation, and GitHub repository.

---

## 📋 Prerequisites

* **Operating System**: Linux (Ubuntu 22.04/24.04, Debian 12, Rocky Linux 9, etc.) or macOS.
* **Docker Engine**: version 24.0+ (`docker --version`).
* **Docker Compose**: version v2.20+ (`docker compose version`).
* **Hardware Sizing**:
  * *Standard (without heavy local LLM)*: 2 vCPUs, 2 GB RAM, 20 GB SSD.
  * *Full Stack (with Nimble 9B local inference)*: 4 vCPUs, 8 GB RAM (or compatible GPU).

---

## 🚀 Quickstart

### 1. Clone the repository
```bash
git clone https://github.com/aivo-labs/aegis.git
cd aegis
```

### 2. Start the full suite
```bash
# Start all containers in sovereign mode
docker compose up -d

# (Optional) Start the official documentation container
docker compose --profile docs up -d
```

### 3. Access endpoints
- **Primary Ingress PEP & WAF Entrypoint**: `http://localhost:8000/`
- **Unified SOC & ESG Cockpit**: `http://localhost:8000/app/` (or `http://localhost:4321/app/`)
- **Sovereign Authentication (Pure BFF)**: `http://localhost:8000/login/` (EN) | `http://localhost:8000/fr/login/` (FR)
- **Technical Documentation (Starlight)**: `http://localhost:8000/docs/` (or port 4322)
- **Bilingual Support (i18n)**: English default at root URLs, French under `/fr/`, with language toggle on all headers.

---

## 🌐 VPS & PaaS Deployment (Dokploy, Coolify, Traefik)

The Aegis Nginx architecture is engineered for hassle-free deployment on VPS and container PaaS platforms:
- **Dedicated Dokploy Compose**: Use `docker-compose.dokploy.yml` on Dokploy, automatically attaching `gate-proxy` and `egress-gateway` to `dokploy-network`.
- **Zero Third-Party Port Exposure**: The Go API (`/api/`) and documentation (`/docs/`) are served transparently via Docker internal bridge networking.
- **Port-Preserved Relative Redirects**: Configured with `absolute_redirect off;` and `port_in_redirect off;`, ensuring Traefik, Caddy, or Nginx SSL proxies handle traffic without losing custom ports or SSL schemes.

---

## 🧪 Pentest Suite & Automated Benchmark

An automated security test suite is included to simulate real-world attack vectors against the in-line filters and verify live detection in the Cockpit:

```bash
./scripts/run-pentest-demo.sh
```

### Simulated & Neutralized Attack Vectors:
1. **Automated Web Scanners**: Neutralizes User-Agent `Nikto/2.1.6` (**403 Forbidden**).
2. **SQL Injections (SQLi)**: Catches `' UNION SELECT username,password FROM users--` (**403 Forbidden**).
3. **Local File Inclusion (LFI)**: Blocks `../../../../etc/passwd` traversals (**403 Forbidden**).
4. **Remote Code Execution (RCE)**: Intercepts `; cat /etc/shadow` commands (**403 Forbidden**).
5. **Cross-Site Scripting (XSS)**: Sanitizes `<script>` tag injections (**403 Forbidden**).
6. **DNS Exfiltration & C2**: Intercepts queries to suspicious domains on port `5053` (**Sinkhole 0.0.0.0**).
7. **DGA Algorithms**: Shannon entropy detection and algorithmic quarantine via the **Nimble 9B** SLM.
8. **Compliant Traffic**: Authenticated requests forwarded with sub-1.5 ms latency (**200 OK**).

---

## ⎈ Kubernetes & Helm Deployment

Aegis natively supports enterprise Kubernetes deployments with granular per-namespace power attribution via **Kepler eBPF**:

* **One-Command Helm Installation**:
  ```bash
  helm upgrade --install aegis ./deploy/kubernetes/helm/aegis \
    --namespace aegis-system \
    --create-namespace
  ```
* **Pure Manifests (GitOps / ArgoCD)**:
  ```bash
  kubectl apply -f deploy/kubernetes/manifests/
  ```

---

## 📁 Repository Structure

```
aegis/
├── apps/
│   ├── backend/            # Sovereign native Go engine (REST API, Passive scanner, Honeypot)
│   ├── docs/               # Official Astro Starlight documentation (Bilingual EN/FR)
│   ├── egress-gateway/     # Outbound DNS gateway with hardened CoreDNS & C2 Sinkhole
│   ├── gate-proxy/         # Ultra-lightweight Ingress PEP / WAF gateway (< 25 MB RAM)
│   ├── telemetry-agent/    # Native Rust hardware sensor (Real Linux RAPL Watts)
│   └── web/                # Unified frontend: Vue 3 SOC Cockpit, Kanban, Astro 5 Landing
├── deploy/
│   ├── docker-compose/     # Docker compose variations (bare-metal, enterprise)
│   └── kubernetes/         # Helm chart and native Kubernetes manifests
├── docs/                   # Whitepapers, technical benchmarks, and architecture guides
├── scripts/                # Setup scripts and automated pentest test benches
└── docker-compose.yml      # Official production Docker Compose definition
```

---

## ⚖️ License & Commitments

* **Open-Source License**: Distributed under the **AGPLv3** (*GNU Affero General Public License v3*). Fully auditable and modifiable source code.
* **Sovereign Design**: Developed in France by **AIVO Labs** — Immune to the extraterritorial US Cloud Act.
* **Regulatory Compliance**: Built for **NIS 2**, **DORA**, **RGESN 2024**, and the European **VS Standard (EFRAG 2026)**.

---

## 🧭 Development Priority Matrix

For detailed technical specifications and lock remediation plans, please refer to the full [Technical Roadmap](ROADMAP.md).  
To interconnect external servers, gateways, and third-party probes to the Control Plane, refer to the [Control Center API Integration Guide](docs/API_INTEGRATION_GUIDE.md).

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

