---
title: Quickstart (2 min)
description: Spin up the complete Aegis sovereign testbench locally or on a server using our 1-click script or Docker Compose.
---

This guide gets you up and running immediately with the **Aegis** sovereign cybersecurity & ESG suite on your local workstation, a VPS, or a staging server.

## 📋 Prerequisites

* A Linux distribution (Debian, Ubuntu, AlmaLinux, Fedora) or macOS with Docker.
* **Docker Engine** (v24.0+) and **Docker Compose** (v2.20+).
* Available network ports:
  * `4321` : Operational SOC & ESG Cockpit
  * `8000` : Ingress PEP Gateway (WAF)
  * `5053` : Egress Gateway (DNS UDP)
  * `8080` : Backend Control Plane API (Go / TimescaleDB)
  * `5432` : TimescaleDB Database
  * `11434` : Sovereign Local AI Engine (Nimble Micro-SLM / Ollama)

---

## ⚡ Method 1: 1-Click Installation Script (Recommended)

On any server or test virtual machine, run the official installation script:

```bash
# Automated hardened deployment (VPS / Single-Server profile)
curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- --profile vps
```

The script automatically provisions required dependencies, sets up `/opt/aegis`, and starts all containerized services within a frugal footprint (< 200 MB RAM).

> [!TIP]
> If deploying on a **physical dedicated server**, use the Bare-Metal profile to enable direct Intel/AMD RAPL hardware energy register sampling:
> ```bash
> curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- --profile baremetal
> ```

---

## 🛠️ Method 2: Git Clone & Manual Testbench

If you prefer to audit the source code before running:

```bash
# 1. Clone the official monorepo
git clone https://github.com/aivo-labs/aegis.git
cd aegis

# 2. Launch the full stack with Docker Compose
docker compose up -d --build
```

> [!NOTE]
> As of **v1.2.2**, the Docker composition automatically injects an `/etc/hosts` link and multi-tier dynamic reconnection (`lastGoodIP`) between the Go backend and TimescaleDB, ensuring absolute resilience against Docker embedded DNS timeouts.

---

## 🧭 Live Web Interfaces

As soon as the containers are running (`docker compose ps`):

* 📊 **Operational SOC & ESG Cockpit**: [`http://localhost:4321/app`](http://localhost:4321/app) (Sovereign Precision UI with high-contrast light/dark toggle)
* 🗂️ **Real-Time Traffic Triage (Kanban)**: [`http://localhost:4321/app/triage`](http://localhost:4321/app/triage)
* 🛡️ **Cybersecurity Action Center**: [`http://localhost:4321/app/actions/security`](http://localhost:4321/app/actions/security)
* 🌿 **Energy Management & Frugal Mode**: [`http://localhost:4321/app/actions/green`](http://localhost:4321/app/actions/green)
* 📜 **EFRAG / ANSSI Compliance Dashboard**: [`http://localhost:4321/app/actions/compliance`](http://localhost:4321/app/actions/compliance)

---

## 🧪 Validate the Testbench with the Automated Pentest Suite

Aegis includes a built-in automated attack testbench to immediately simulate real-world exploits against the Ingress and Egress gateways:

```bash
# Run the complete 8-attack simulation suite
./scripts/run-pentest-demo.sh
```

This script triggers:
1. **Nikto Scanner** (User-Agent signature detection) ➔ `HTTP 403 Forbidden`
2. **SQL Injection** (`UNION SELECT` on user tables) ➔ `HTTP 403 Forbidden`
3. **Path Traversal / LFI** (attempted `/etc/passwd` read) ➔ `HTTP 403 Forbidden`
4. **Remote Code Execution (RCE)** (shell command injection) ➔ `HTTP 403 Forbidden`
5. **Cross-Site Scripting (XSS)** (script payload injection) ➔ `HTTP 403 Forbidden`
6. **Compliant Legitimate Traffic** (healthy API request) ➔ `HTTP 200 OK`
7. **CrowdSec C2 Exfiltration** (outbound DNS query to known malicious domain) ➔ Sinkholed to `0.0.0.0`
8. **High-Entropy DGA Exfiltration** (algorithmic detection by local Nimble 9B AI) ➔ Blocked / Quarantined

Open the **Triage Kanban** ([`http://localhost:4321/app/triage`](http://localhost:4321/app/triage)) side-by-side: you will see each attack appear in real time, categorized by severity with geolocation and forensic metadata.
