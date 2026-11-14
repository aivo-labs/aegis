---
title: Production Dokploy & Traefik (ForwardAuth)
description: Guide pas-à-pas pour déployer la suite souveraine Aegis en production sur Dokploy avec Traefik v3 en coupure réseau ForwardAuth.
---

Ce tutoriel détaille la mise en production d'Aegis sur un serveur VPS ou dédié géré via **Dokploy** (l'alternative souveraine et open-source à Vercel et Coolify), en utilisant **Traefik v3** comme passerelle d'entrée (*Ingress Load Balancer*) avec le middleware **ForwardAuth**.

---

## 🏗️ Topologie de l'Architecture en Production

```
                                [ Trafic Public HTTPS ]
                                           │
                                           ▼
                     ┌───────────────────────────────────────────┐
                     │    TRAEFIK v3 (Dokploy Edge Proxy)        │
                     │    • Terminaison SSL Let's Encrypt auto   │
                     │    • Routage de domaine SNI               │
                     │    • Middleware ForwardAuth actif         │
                     └─────────────────────┬─────────────────────┘
                                           │
                           1. Subrequest   │  3. Flux autorisé (HTTP 200)
                           /_aegis/verify  │     avec headers certifiés
                                           │
                                           ▼
        ┌──────────────────────────────────┴───────────────────────────────────┐
        │                                                                      │
        ▼                                                                      ▼
┌───────────────────────────────┐                             ┌─────────────────────────────────┐
│     AEGIS GATE PROXY (:8000)  │                             │  APPLICATIONS & SERVICES CIBLES │
│                               │                             │                                 │
│ • Inspection In-Line < 1,5 ms │                             │ • Aegis Cockpit (:4321 / web)   │
│ • WAF OWASP CRS & Scanners    │       2. Verdict WAF        │ • Vos APIs métier & CMS client  │
│ • Protection Overflow 413     ├────────────────────────────►│ • Microservices protégés        │
│ • Entropie de Shannon         │   (403 Block si menace /    │                                 │
│ • Télémétrie vers TimescaleDB │    200 OK si flux sain)     │                                 │
└───────────────────────────────┘                             └─────────────────────────────────┘
```

Dans cette configuration :
1. **Traefik** gère les certificats SSL publics et route les noms de domaine.
2. Pour chaque requête reçue, Traefik interroge instantanément Aegis sur son endpoint `http://gate-proxy:8000/_aegis/verify`.
3. Si la requête est saine, Aegis répond `HTTP 200 OK` en **0,4 ms**, et Traefik transmet la requête à l'application cible.
4. Si une attaque est détectée (injection SQL, scanner de vulnérabilité, shellcode, débordement de taille), Aegis répond immédiatement `HTTP 403 Forbidden` ou `HTTP 413` avec la charge JSON d'audit, bloquant l'attaquant avant même qu'il n'atteigne votre application.

---

## 📋 Prérequis

* Un serveur VPS ou dédié sous **Debian 12** ou **Ubuntu 22.04 / 24.04**.
* Une instance **Dokploy** installée et fonctionnelle (accessible via le port `3000`).
* Le réseau Docker `dokploy-network` actif (créé par défaut par Dokploy).
* Deux noms de domaine ou sous-domaines pointant vers l'IP de votre serveur :
  * `aegis.votre-domaine.fr` (accès au Cockpit SOC d'administration)
  * `app.votre-domaine.fr` (l'application ou API que vous souhaitez protéger)

---

## 🚀 Étape 1 : Créer le Projet dans Dokploy

1. Connectez-vous à votre interface Dokploy (`https://dokploy.votre-serveur.fr`).
2. Cliquez sur **Projects** > **Create Project** et nommez-le `Aegis Production`.
3. À l'intérieur du projet, cliquez sur **Create Service** et sélectionnez **Compose**.
4. Nommez le service `aegis-stack`.

---

## 📦 Étape 2 : Déployer `docker-compose.dokploy.yml`

Collez la composition de production suivante dans l'éditeur de configuration Compose de Dokploy :

```yaml
version: '3.8'

services:
  # 1. BASE DE DONNÉES TEMPORELLE TIMESCALEDB
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

  # 2. BACKEND API & MOTEUR D'ÉVALUATION (GO)
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

  # 3. PASSERELLE SORTANTE AEGIS EGRESS (DNS NIMBLE)
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

  # 4. AGENT DE TÉLÉMÉTRIE ÉNERGÉTIQUE RUST
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

  # 5. MOTEUR IA SYSTEM ONE (OLLAMA NIMBLE LOCAL)
  ollama-nimble:
    image: ollama/ollama:latest
    container_name: aegis_ollama_nimble
    restart: always
    networks:
      - aegis-internal
    volumes:
      - aegis_ollama_data:/root/.ollama
    entrypoint: ["/bin/sh", "-c", "ollama serve & sleep 5 && (ollama pull nimble || true) && wait"]

  # 6. APPLICATION WEB & COCKPIT SOC (ASTRO / VUE 3)
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

  # 7. PASSERELLE INGRESS PEP & WAF (PURE BFF & VIRTUAL PATCHING)
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

  # 8. PORTAIL DE DOCUMENTATION OFFICIELLE
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

## 🔑 Étape 3 : Configurer les Variables d'Environnement

Dans l'onglet **Environment Variables** du service Dokploy, configurez les valeurs de production :

| Variable | Description | Exemple / Valeur recommandée |
| :--- | :--- | :--- |
| `AEGIS_TENANT_ID` | Identifiant UUID de votre organisation | `00000000-0000-0000-0000-000000000001` |
| `POSTGRES_DB` | Nom de la base TimescaleDB | `aegis_db` |
| `POSTGRES_USER` | Utilisateur de base de données | `aegis_admin` |
| `POSTGRES_PASSWORD` | Mot de passe chiffré complexe | *(Généré aléatoirement 32 caractères)* |
| `APP_SECRET` | Clé secrète de signature Symfony/Go | *(Généré aléatoirement 32 octets)* |
| `BFF_SESSION_SECRET` | Clé de chiffrement AES-256 des cookies | *(Chaîne secrète de 32 caractères min.)* |
| `OIDC_ISSUER_URL` | URL de votre IdP (Keycloak, Okta, Authelia) | `https://auth.votre-domaine.fr/realms/aegis` *(Optionnel)* |
| `OIDC_CLIENT_ID` | Client OIDC enregistré | `aegis-cockpit` *(Optionnel)* |

---

## 🛡️ Étape 4 : Définir le Middleware Traefik ForwardAuth

Pour activer l'interception automatique de Traefik sur toutes vos applications hébergées sur le serveur :

1. Dans Dokploy, rendez-vous dans les paramètres globaux de **Traefik** (ou éditez le fichier dynamique `/etc/dokploy/traefik/dynamic/aegis-middleware.yml`).
2. Ajoutez la définition du middleware `aegis-auth` :

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

### Protection d'une Application Client avec le Middleware
Pour protéger n'importe quelle application cliente gérée sur Dokploy, il vous suffit d'ajouter le middleware `aegis-auth@file` dans les labels Traefik de votre conteneur applicatif :

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.monapp.rule=Host(`monapp.votre-domaine.fr`)"
  - "traefik.http.routers.monapp.entrypoints=websecure"
  - "traefik.http.routers.monapp.tls.certresolver=letsencrypt"
  - "traefik.http.routers.monapp.middlewares=aegis-auth@file"
```

Désormais, Traefik soumettra **chaque requête** à Aegis Gate PEP avant de la délivrer à `monapp` !

---

## 🧪 Étape 5 : Valider le Déploiement & Tester le Banc d'Essai

Une fois le déploiement lancé avec succès dans Dokploy :

### 1. Vérification du Flux Légitime
Exécutez une requête saine :
```bash
curl -I https://monapp.votre-domaine.fr
```
👉 La réponse retourne `HTTP 200 OK` avec les en-têtes certifiés injectés par le WAF :
```http
X-Aegis-Verified: true
X-Aegis-Engine: Aegis Gate PEP
```

### 2. Simulation d'un Scanner Agressif
Testez l'interception d'un scanner automatisé :
```bash
curl -I -A "Mozilla/5.0 (Nikto/2.1.6)" https://monapp.votre-domaine.fr/admin.php
```
👉 Le WAF intercepte la requête en **0,4 ms** et bloque immédiatement l'attaque :
```http
HTTP/2 403 Forbidden
content-type: application/json
x-aegis-decision: BLOCK
x-aegis-threat: PENTEST_SCANNER_DETECTED
```

### 3. Consultation du Cockpit SOC
Ouvrez votre navigateur sur `https://aegis.votre-domaine.fr/app/triage` : l'attaque simulée apparaît immédiatement sur votre tableau Kanban de triage avec l'IP attaquante, le score de risque et la signature neutralisée.
