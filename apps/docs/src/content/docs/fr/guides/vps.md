---
title: Déploiement Mono-Serveur & VPS
description: Guide de déploiement d'Aegis sur une machine virtuelle Linux (Debian, Ubuntu) via le script 1-clic, Docker Compose ou Dokploy.
---

Ce guide s'adresse aux administrateurs systèmes, CTOs et équipes DevOps souhaitant déployer la suite souveraine Aegis sur un **VPS Cloud** (Scaleway, OVHcloud, Hetzner Cloud, AWS EC2, DigitalOcean).

## 🏗️ Architecture du Déploiement VPS

Sur un VPS, Aegis fonctionne sous forme d'une stack de conteneurs contigus et hautement optimisés :

* **Aegis Gate PEP (:8000)** : Passerelle Ingress Zero-Trust filtrant les attaques en coupure réseau (< 1.5 ms).
* **Aegis Egress Gateway (:5053/udp)** : Résolveur DNS filtrant les fuites de données et communications C2.
* **Aegis Web (:4321)** : Cockpit d'administration, Triage Kanban, radar ESG et cartes GeoIP.
* **Aegis Backend (:8080)** : Moteur d'évaluation Symfony 7 couplé à une base TimescaleDB.
* **Sonde Énergétique** : Analyse de la charge `/proc/stat` et estimation thermodynamique continue en Watts selon le profil processeur de la VM.

---

## ⚡ Méthode 1 : Déploiement 1-Clic via Script (Recommandé)

Sur votre VPS vierge (Debian 12, Ubuntu 22.04 / 24.04), exécutez la commande suivante :

```bash
curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- --profile vps
```

### Ce que fait le script :
1. Vérifie et installe Docker Engine et Docker Compose si nécessaires.
2. Déploie le monorepo dans `/opt/aegis`.
3. Lance l'ensemble des conteneurs via Docker Compose.
4. Active les sondes de surveillance et configure les réseaux isolés.

---

## 🛠️ Méthode 2 : Déploiement Manuel avec Git & Docker Compose

Si vous préférez orchestrer le déploiement manuellement :

```bash
# 1. Cloner le dépôt dans /opt/aegis
sudo git clone https://github.com/aivo-labs/aegis.git /opt/aegis
cd /opt/aegis

# 2. Démarrer la composition complète
sudo docker compose up -d --build
```

Vérifiez le statut des conteneurs :
```bash
sudo docker compose ps
```

---

## 🌐 Configuration du Reverse Proxy & Agnosticisme d'Infrastructure

Aegis a été conçu dès l'origine pour être **100% agnostique** vis-à-vis de votre infrastructure d'hébergement et de vos outils de terminaison TLS. Que vous utilisiez **Nginx**, **Traefik**, **Caddy**, **HAProxy** ou **Envoy**, deux modes d'intégration s'offrent à vous :

### Option A : Nginx en Coupure `auth_request` (Similaire à ForwardAuth)
Dans ce mode, Nginx sert directement votre site ou votre API métier (ex: un WordPress, une application Symfony, Python ou Node.js), mais soumet **chaque requête entrante** à Aegis Gate sur `/_aegis/verify` avant de la traiter :

```nginx
# Configuration Nginx (/etc/nginx/sites-available/mon-application.conf)
server {
    listen 443 ssl http2;
    server_name mon-app.votre-entreprise.fr;

    ssl_certificate /etc/letsencrypt/live/mon-app.votre-entreprise.fr/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mon-app.votre-entreprise.fr/privkey.pem;

    # 1. Protection de l'application via sous-requête Aegis WAF
    location / {
        # Interrogation in-line du WAF Aegis (< 0.5 ms)
        auth_request /_aegis/verify;

        # Récupération des en-têtes certifiés
        auth_request_set $aegis_verified $upstream_http_x_aegis_verified;
        auth_request_set $aegis_client_ip $upstream_http_x_aegis_client_ip;

        # Redirection vers votre application applicative locale
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Aegis-Verified $aegis_verified;
    }

    # 2. Point de contrôle interne de vérification WAF
    location = /_aegis/verify {
        internal;
        proxy_pass http://127.0.0.1:8000/_aegis/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        
        # Transmission des métadonnées de la requête originale
        proxy_set_header X-Forwarded-Method $request_method;
        proxy_set_header X-Forwarded-Uri $request_uri;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Host $host;
    }

    # 3. Page d'erreur personnalisée si Aegis bloque l'attaquant
    error_page 403 = @aegis_blocked;
    location @aegis_blocked {
        default_type application/json;
        return 403 '{"status":403,"verdict":"BLOCKED","error":"Accès neutralisé par Aegis Gate PEP"}';
    }
}
```

### Option B : Nginx en Reverse Proxy Transparent
Si vous préférez qu'Aegis prenne en charge le routage applicatif interne et le Token Handler Pure BFF :

```nginx
server {
    listen 443 ssl http2;
    server_name soc.votre-entreprise.fr;

    ssl_certificate /etc/letsencrypt/live/soc.votre-entreprise.fr/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.votre-entreprise.fr/privkey.pem;

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

## 🔑 Agnosticisme Total des Fournisseurs d'Identité (IdP / IAM)

Le module **Pure BFF** d'Aegis repose sur les standards ouverts **OpenID Connect (OIDC)** et **OAuth 2.0 PKCE (RFC 7636)**. Vous n'êtes aucunement lié à Keycloak : Aegis s'interconnecte nativement avec n'importe quel fournisseur conforme :

| Fournisseur d'Identité | Configuration `OIDC_ISSUER_URL` | Spécificités & Endpoints |
| :--- | :--- | :--- |
| **Keycloak (Défaut)** | `https://auth.votre-domaine.fr/realms/aegis` | Endpoints standard `/protocol/openid-connect/*` gérés nativement. |
| **Okta** | `https://dev-xxxx.okta.com/oauth2/default` | Résolution automatique des endpoints `/v1/authorize` et `/v1/logout`. |
| **Authelia** | `https://auth.votre-domaine.fr` | Solution souveraine légère. Endpoints `/api/oidc/authorization`. |
| **Authentik** | `https://authentik.votre-domaine.fr/application/o/aegis/` | Fournisseur open-source moderne. Endpoints dérivés automatiquement. |
| **Auth0 / Okta CIC** | `https://mon-tenant.eu.auth0.com` | Renseigner `OIDC_CLIENT_ID` et `OIDC_CLIENT_SECRET`. |
| **Microsoft Entra ID** | `https://login.microsoftonline.com/{tenant-id}/v2.0` | Compatible flux OIDC PKCE Azure d'entreprise. |

### Définition Manuelle des Endpoints (Optionnelle)
Si votre serveur d'authentification utilise des URI atypiques, Aegis permet de spécifier directement les endpoints sans dépendre de découverte dynamique :
```bash
OIDC_AUTHORIZATION_ENDPOINT="https://auth.mon-entreprise.fr/oauth/custom/authorize"
OIDC_TOKEN_ENDPOINT="https://auth.mon-entreprise.fr/oauth/custom/token"
OIDC_END_SESSION_ENDPOINT="https://auth.mon-entreprise.fr/oauth/custom/logout"
```

---

## ⚙️ Déploiement via Dokploy / Coolify

Si vous gérez vos VPS avec des interfaces de PaaS open-source comme **Dokploy** ou **Coolify** :

1. Créez un nouveau projet *"Aegis Production"*.
2. Ajoutez un service de type **Docker Compose**.
3. Renseignez la source Git : `https://github.com/aivo-labs/aegis.git` (branche `main`).
4. Indiquez le chemin du fichier : `docker-compose.yml`.
5. Mappez les domaines publics sur le port `4321` (Cockpit) et `8000` (WAF Ingress).

---

## 🧪 Éprouver l'Installation avec le Banc d'Essai

Dès la fin de l'installation, validez que le WAF et le Kanban de triage réagissent correctement :

```bash
cd /opt/aegis
./scripts/run-pentest-demo.sh
```

Consultez [`http://votre-ip:4321/app/triage`](http://votre-ip:4321/app/triage) pour observer le traitement en direct des requêtes suspectes.
