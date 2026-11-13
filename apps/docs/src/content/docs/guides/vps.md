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

## 🌐 Reverse Proxy & Infrastructure Agnosticism

Aegis is engineered from the ground up to be **100% agnostic** to your hosting infrastructure and TLS termination proxies. Whether you run **Nginx**, **Traefik**, **Caddy**, **HAProxy**, or **Envoy**, two integration patterns are supported:

### Option A: Nginx with `auth_request` (Equivalent to ForwardAuth)
In this pattern, Nginx directly serves your upstream workload (WordPress, Symfony, Python, Node.js), but queries Aegis Gate on `/_aegis/verify` before granting access:

```nginx
# Nginx Configuration (/etc/nginx/sites-available/my-application.conf)
server {
    listen 443 ssl http2;
    server_name my-app.your-company.com;

    ssl_certificate /etc/letsencrypt/live/my-app.your-company.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/my-app.your-company.com/privkey.pem;

    # 1. Protect application via Aegis WAF subrequest
    location / {
        # Fast in-line WAF query (< 0.5 ms)
        auth_request /_aegis/verify;

        # Forward certified headers
        auth_request_set $aegis_verified $upstream_http_x_aegis_verified;
        auth_request_set $aegis_client_ip $upstream_http_x_aegis_client_ip;

        # Forward to local upstream application
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Aegis-Verified $aegis_verified;
    }

    # 2. Internal WAF check endpoint
    location = /_aegis/verify {
        internal;
        proxy_pass http://127.0.0.1:8000/_aegis/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        
        # Forward original request metadata
        proxy_set_header X-Forwarded-Method $request_method;
        proxy_set_header X-Forwarded-Uri $request_uri;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Host $host;
    }

    # 3. Custom error response when Aegis blocks an attacker
    error_page 403 = @aegis_blocked;
    location @aegis_blocked {
        default_type application/json;
        return 403 '{"status":403,"verdict":"BLOCKED","error":"Access Denied by Aegis Gate PEP"}';
    }
}
```

### Option B: Nginx as Transparent Reverse Proxy
If you want Aegis Gate to handle internal routing and Pure BFF token handling directly:

```nginx
server {
    listen 443 ssl http2;
    server_name soc.your-company.com;

    ssl_certificate /etc/letsencrypt/live/soc.your-company.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.your-company.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

---

## 🔑 Total Identity Provider (IdP / IAM) Agnosticism

Aegis **Pure BFF** adheres strictly to open standards: **OpenID Connect (OIDC)** and **OAuth 2.0 PKCE (RFC 7636)**. You are never locked into Keycloak; Aegis connects seamlessly with any compliant IdP:

| Identity Provider | `OIDC_ISSUER_URL` Example | Endpoints & Specifics |
| :--- | :--- | :--- |
| **Keycloak (Default)** | `https://auth.your-domain.com/realms/aegis` | Standard `/protocol/openid-connect/*` endpoints resolved automatically. |
| **Okta** | `https://dev-xxxx.okta.com/oauth2/default` | Automatic resolution of `/v1/authorize` and `/v1/logout`. |
| **Authelia** | `https://auth.your-domain.com` | Lightweight sovereign IdP. Endpoints `/api/oidc/authorization`. |
| **Authentik** | `https://authentik.your-domain.com/application/o/aegis/` | Modern open-source provider. Standard endpoints auto-derived. |
| **Auth0 / Okta CIC** | `https://my-tenant.eu.auth0.com` | Configure standard `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`. |
| **Microsoft Entra ID** | `https://login.microsoftonline.com/{tenant-id}/v2.0` | Enterprise Azure OIDC PKCE flow fully supported. |

### Manual Endpoint Overrides (Optional)
If your corporate authentication server uses non-standard routes, configure endpoints explicitly via environment variables:
```bash
OIDC_AUTHORIZATION_ENDPOINT="https://auth.your-company.com/oauth/custom/authorize"
OIDC_TOKEN_ENDPOINT="https://auth.your-company.com/oauth/custom/token"
OIDC_END_SESSION_ENDPOINT="https://auth.your-company.com/oauth/custom/logout"
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
