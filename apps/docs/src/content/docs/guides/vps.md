---
title: Single-Server & VPS Deployment
description: Deploy Aegis on a Linux virtual machine (Debian, Ubuntu) using our 1-click script, Docker Compose, or Dokploy.
---

This guide is intended for system administrators, CTOs, and DevOps engineers looking to deploy the Aegis sovereign suite onto a **Cloud VPS** (Scaleway, OVHcloud, Hetzner Cloud, AWS EC2, DigitalOcean).

## 🏗️ VPS Deployment Architecture

On a VPS, Aegis runs as an orchestrated set of contiguous, highly-optimized micro-services:

* **Aegis Gate PEP (:8000)** : Zero-Trust Ingress gateway inline-blocking web attacks (&lt; 1.5 ms).
* **Aegis Egress Gateway (:5053/udp)** : DNS resolver mitigating data exfiltration and C2 beaconing.
* **Aegis Web (:4321)** : Admin cockpit, Real-time Kanban triage, ESG radar, and GeoIP threat map.
* **Aegis Backend (:8080)** : High-performance Go control plane paired with TimescaleDB.
* **Energy Daemon** : Continuous `/proc/stat` workload sampling and thermodynamic wattage modeling adjusted for virtualized CPU topology.

---

## ⚡ Method 1: 1-Click Script Deployment (Recommended)

On your pristine VPS (Debian 12, Ubuntu 22.04 / 24.04), execute the following command:

```bash
curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- --profile vps
```

### What the script handles automatically:
1. Verifies and installs Docker Engine and Docker Compose if missing.
2. Clones the production release to `/opt/aegis`.
3. Brings up all containers via Docker Compose.
4. Activates monitoring daemons and isolates internal docker networks.

---

## 🛠️ Method 2: Manual Deployment with Git & Docker Compose

If you prefer orchestrating the deployment manually:

```bash
# 1. Clone the repository into /opt/aegis
sudo git clone https://github.com/aivo-labs/aegis.git /opt/aegis
cd /opt/aegis

# 2. Start the full stack
sudo docker compose up -d --build
```

Verify service status:
```bash
sudo docker compose ps
```

---

## 🌐 Reverse Proxy & TLS (HTTPS) Configuration

To expose your services under your corporate domain names with automated Let's Encrypt certificates:

### Example with Caddy Server
```nginx
# Operational SOC & ESG Cockpit
soc.your-company.com {
    reverse_proxy localhost:4321
}

# Ingress PEP Gateway (protecting your backend APIs)
waf.your-company.com {
    reverse_proxy localhost:8000
}
```

### Example with Nginx
```nginx
server {
    server_name soc.your-company.com;
    listen 80;

    location / {
        proxy_pass http://127.0.0.1:4321;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## ⚙️ Deployment via Dokploy / Coolify

If you manage your VPS fleets using open-source PaaS managers like **Dokploy** or **Coolify**:

1. Create a new application project: *"Aegis Production"*.
2. Add a service using the **Docker Compose** provider.
3. Configure the Git repository: `https://github.com/aivo-labs/aegis.git` (branch `main`).
4. Set the Compose file path: `docker-compose.yml`.
5. Map public ingress domains to port `4321` (Cockpit) and `8000` (WAF Ingress).

---

## 🧪 Validate the Installation with the Automated Testbench

Once installed, confirm that the WAF and Triage Kanban react immediately:

```bash
cd /opt/aegis
./scripts/run-pentest-demo.sh
```

Navigate to [`http://your-server-ip:4321/app/triage`](http://your-server-ip:4321/app/triage) to observe real-time mitigation of test payloads.
