---
title: Production Dokploy & Traefik (ForwardAuth)
description: Step-by-step tutorial to deploy the Aegis sovereign suite to production on Dokploy with Traefik v3 ForwardAuth network interception.
---

This guide details how to deploy Aegis in production on a VPS or bare-metal host managed by **Dokploy** (the sovereign open-source alternative to Vercel and Coolify), leveraging **Traefik v3** as the edge reverse proxy and load balancer configured with **ForwardAuth** middleware.

---

## 🏗️ Production Architecture Topology

```
                                [ Inbound Public HTTPS Traffic ]
                                               │
                                               ▼
                     ┌───────────────────────────────────────────────────┐
                     │          TRAEFIK v3 (Dokploy Edge Proxy)          │
                     │    • Automatic Let's Encrypt TLS termination      │
                     │    • SNI Domain routing                           │
                     │    • Active ForwardAuth middleware                │
                     └─────────────────────────┬─────────────────────────┘
                                               │
                            1. Subrequest      │  3. Authorized traffic (HTTP 200)
                            /_aegis/verify     │     with certified headers
                                               │
                                               ▼
        ┌──────────────────────────────────────┴───────────────────────────────────────┐
        │                                                                              │
        ▼                                                                              ▼
┌───────────────────────────────┐                             ┌─────────────────────────────────┐
│     AEGIS GATE PROXY (:8000)  │                             │   UPSTREAM PROTECTED SERVICES   │
│                               │                             │                                 │
│ • In-line inspection < 1.5 ms │                             │ • Aegis Cockpit (:4321 / web)   │
│ • OWASP CRS & Scanner Defense │       2. WAF Verdict        │ • Protected Customer APIs & CMS │
│ • RFC 413 Overflow Defense    ├────────────────────────────►│ • Internal Microservices        │
│ • Shannon Entropy Scoring     │   (403 Block if threat /    │                                 │
│ • Telemetry to TimescaleDB    │    200 OK if clean)         │                                 │
└───────────────────────────────┘                             └─────────────────────────────────┘
```

In this production design:
1. **Traefik** handles edge TLS termination and public domain routing.
2. For every incoming HTTP request, Traefik queries Aegis on its internal endpoint `http://gate-proxy:8000/_aegis/verify`.
3. If clean, Aegis replies with `HTTP 200 OK` in **0.4 ms**, and Traefik forwards the request to the upstream container.
4. If a threat is detected (SQL injection, automated scanner, shellcode, volumetric overflow), Aegis immediately returns `HTTP 403 Forbidden` or `HTTP 413` with the audit payload, cutting the connection before it can ever touch your application.

---

## 📋 Prerequisites

* A virtual or dedicated server running **Debian 12** or **Ubuntu 22.04 / 24.04**.
* A working **Dokploy** installation (accessible via port `3000`).
* The external Docker network `dokploy-network` initialized.
* Two DNS records pointing to your server's public IP:
  * `aegis.your-domain.com` (SOC administration Cockpit)
  * `app.your-domain.com` (The application or API you want to protect)

---

## 🚀 Step 1: Create the Project in Dokploy

1. Open your Dokploy dashboard (`https://dokploy.your-server.com`).
2. Navigate to **Projects** > **Create Project** and name it `Aegis Production`.
3. Inside the project, click **Create Service** and select **Compose**.
4. Name the service `aegis-stack`.

---

## 📦 Step 2: Deploy `docker-compose.dokploy.yml`

Paste the following production composition into Dokploy's Compose editor:

```yaml
version: '3.8'

services:
  # 1. TIMESCALEDB TIME-SERIES HYPERTABLES
  timescaledb:
    image: timescale/timescaledb:latest-pg16
    container_name: aegis_timescaledb
    restart: always
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-aegis_db}
      POSTGRES_USER: ${POSTGRES_USER:-aegis_user}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    networks:
      - aegis-internal
    volumes:
      - aegis_pgdata:/var/lib/postgresql/data
      - ./apps/backend/migrations/schema-database-postgresql-aegis.sql:/docker-entrypoint-initdb.d/01-schema.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-aegis_user} -d ${POSTGRES_DB:-aegis_db}"]
      interval: 5s
      timeout: 5s
      retries: 5

  # 2. GO BACKEND CONTROL PLANE & EVALUATION ENGINE
  backend:
    build:
      context: ./apps/backend
      dockerfile: Dockerfile
    container_name: aegis_backend
    restart: always
    environment:
      DATABASE_URL: "postgresql://${POSTGRES_USER:-aegis_user}:${POSTGRES_PASSWORD}@timescaledb:5432/${POSTGRES_DB:-aegis_db}?serverVersion=16&charset=utf8"
      APP_ENV: prod
      APP_SECRET: ${APP_SECRET}
    networks:
      - aegis-internal
    depends_on:
      timescaledb:
        condition: service_healthy

  # 3. AEGIS EGRESS GATEWAY (DNS NIMBLE FILTER)
  egress-gateway:
    build:
      context: ./apps/egress-gateway
      dockerfile: Dockerfile
    container_name: aegis_egress_gateway
    restart: always
    environment:
      AEGIS_TENANT_ID: "${AEGIS_TENANT_ID}"
      AEGIS_GATE_API_URL: "http://backend:80/api/v1/gate/telemetry/egress"
      SYSTEMONE_API_URL: "http://ollama-nimble:11434/v1/systemone"
      SYSTEMONE_MODEL_NAME: "nimble"
      EGRESS_LISTEN_PORT: 5053
    ports:
      - "5053:5053/udp"
      - "5053:5053/tcp"
    networks:
      - aegis-internal
      - dokploy-network
    depends_on:
      - backend

  # 4. RUST ENERGY TELEMETRY AGENT
  telemetry-agent:
    build:
      context: ./apps/telemetry-agent
      dockerfile: Dockerfile
    container_name: aegis_telemetry_agent
    restart: always
    pid: "host"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
    environment:
      AEGIS_TENANT_ID: "${AEGIS_TENANT_ID}"
      AEGIS_SERVER_ID: "aegis-dokploy-node"
      AEGIS_GATE_API_URL: "http://backend:80/api/v1/gate/telemetry/energy"
      POLL_INTERVAL_SECS: "5"
    networks:
      - aegis-internal
    depends_on:
      - backend

  # 5. SOVEREIGN SYSTEM ONE AI MODEL (LOCAL OLLAMA NIMBLE)
  ollama-nimble:
    image: ollama/ollama:latest
    container_name: aegis_ollama_nimble
    restart: always
    networks:
      - aegis-internal
    volumes:
      - aegis_ollama_data:/root/.ollama
    entrypoint: ["/bin/sh", "-c", "ollama serve & sleep 5 && (ollama pull nimble || true) && wait"]

  # 6. WEB COCKPIT & SOC DASHBOARD (ASTRO / VUE 3)
  web:
    build:
      context: ./apps/web
      dockerfile: Dockerfile
    container_name: aegis_web
    restart: always
    networks:
      - aegis-internal
    depends_on:
      - backend

  # 7. INGRESS PEP & WAF GATEWAY (PURE BFF & VIRTUAL PATCHING)
  gate-proxy:
    build:
      context: ./apps/gate-proxy
      dockerfile: Dockerfile
    container_name: aegis_gate_proxy
    restart: always
    environment:
      GATE_PORT: 8000
      BACKEND_URL: "http://backend:80"
      WEB_URL: "http://web:80"
      AEGIS_GATE_API_URL: "http://backend:80/api/v1/gate/telemetry/ingress"
      AEGIS_TENANT_ID: "${AEGIS_TENANT_ID}"
      BFF_SESSION_SECRET: "${BFF_SESSION_SECRET}"
      OIDC_ISSUER_URL: "${OIDC_ISSUER_URL:-}"
      OIDC_CLIENT_ID: "${OIDC_CLIENT_ID:-aegis-cockpit}"
      OIDC_CLIENT_SECRET: "${OIDC_CLIENT_SECRET:-}"
      OIDC_REDIRECT_URI: "${OIDC_REDIRECT_URI:-}"
    ports:
      - "8000:8000"
    networks:
      - aegis-internal
      - dokploy-network
    depends_on:
      - backend
      - web

  # 8. OFFICIAL DOCUMENTATION PORTAL
  docs:
    build:
      context: ./apps/docs
      dockerfile: Dockerfile
    container_name: aegis_docs
    restart: always
    networks:
      - aegis-internal
      - dokploy-network

volumes:
  aegis_pgdata:
  aegis_ollama_data:

networks:
  aegis-internal:
    driver: bridge
  dokploy-network:
    external: true
```

---

## 🔑 Step 3: Configure Environment Variables

Under the **Environment Variables** tab of your Dokploy service, provide your production values:

| Variable | Description | Recommended Value |
| :--- | :--- | :--- |
| `AEGIS_TENANT_ID` | Your organization's Tenant UUID | `00000000-0000-0000-0000-000000000001` |
| `POSTGRES_DB` | TimescaleDB database name | `aegis_db` |
| `POSTGRES_USER` | Database username | `aegis_admin` |
| `POSTGRES_PASSWORD` | Strong database password | *(Generate 32 random characters)* |
| `APP_SECRET` | Backend signing secret key | *(Generate 32 random bytes)* |
| `BFF_SESSION_SECRET` | AES-256 session cookie encryption key | *(Min. 32 character secret)* |
| `OIDC_ISSUER_URL` | OpenID Connect Identity Provider URL | `https://auth.your-domain.com/realms/aegis` *(Optional)* |
| `OIDC_CLIENT_ID` | Registered OIDC client ID | `aegis-cockpit` *(Optional)* |

---

## 🛡️ Step 4: Define Traefik ForwardAuth Middleware

To allow Traefik to filter requests on any workload:

1. In Dokploy, go to global **Traefik** configuration (or add a file to `/etc/dokploy/traefik/dynamic/aegis-middleware.yml`).
2. Add the `aegis-auth` middleware definition:

```yaml
http:
  middlewares:
    aegis-auth:
      forwardAuth:
        address: "http://aegis_gate_proxy:8000/_aegis/verify"
        trustForwardHeader: true
        authResponseHeaders:
          - "X-Aegis-Verified"
          - "X-Aegis-Engine"
          - "X-Aegis-Client-IP"
```

### Protecting Upstream Apps
Attach the middleware to any target application container using Docker labels:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.myapp.rule=Host(`myapp.your-domain.com`)"
  - "traefik.http.routers.myapp.entrypoints=websecure"
  - "traefik.http.routers.myapp.tls.certresolver=letsencrypt"
  - "traefik.http.routers.myapp.middlewares=aegis-auth@file"
```

Traefik will now verify **every single request** with Aegis Gate PEP before passing it to `myapp`!

---

## 🧪 Step 5: Verification & Attack Simulation

Once deployment completes:

### 1. Verify Clean Traffic
```bash
curl -I https://myapp.your-domain.com
```
👉 Returns `HTTP 200 OK` with certified response headers:
```http
X-Aegis-Verified: true
X-Aegis-Engine: Aegis Gate PEP
```

### 2. Test Automated Scanner Interception
```bash
curl -I -A "Mozilla/5.0 (Nikto/2.1.6)" https://myapp.your-domain.com/admin.php
```
👉 Returns immediate `HTTP 403 Forbidden` in **0.4 ms**:
```http
HTTP/2 403 Forbidden
content-type: application/json
x-aegis-decision: BLOCK
x-aegis-threat: PENTEST_SCANNER_DETECTED
```

### 3. Check SOC Triage Kanban
Open `https://aegis.your-domain.com/app/triage` to see the intercepted threat in real time.
