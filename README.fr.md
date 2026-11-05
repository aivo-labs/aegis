# 🛡️ Aegis par AIVO — Suite Souveraine Zero-Trust & Cockpit ESG (AGPLv3)

<p align="center">
  <a href="README.md">English</a> | <strong>Français</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-AGPLv3-emerald?style=flat-square" alt="Licence AGPLv3" />
  <img src="https://img.shields.io/badge/Architecture-Zero--Trust-blue?style=flat-square" alt="Zero Trust" />
  <img src="https://img.shields.io/badge/Go-1.22-00ADD8?style=flat-square&logo=go" alt="Go 1.22" />
  <img src="https://img.shields.io/badge/Rust-RAPL-orange?style=flat-square&logo=rust" alt="Rust RAPL" />
  <img src="https://img.shields.io/badge/Astro-5.x-purple?style=flat-square&logo=astro" alt="Astro 5" />
  <img src="https://img.shields.io/badge/NIS%202-Prêt-success?style=flat-square" alt="Conformité NIS 2" />
  <img src="https://img.shields.io/badge/RGESN%20%2F%20EFRAG-Conforme-brightgreen?style=flat-square" alt="Sobriété Énergétique" />
</p>

**Centre de Contrôle Opérationnel (SOC), Protection In-Line (Ingress/Egress) & Pilotage Énergétique Conforme RGESN / ANSSI / EFRAG**

Aegis est une suite logicielle unifiée conçue pour sécuriser le système d'information des PME/ETI et piloter sa sobriété numérique selon le modèle **Open-Core Éthique (AGPLv3)**. Développé en **Go et Rust**, Aegis fonctionne comme une surcouche transparente ultra-frugale (< 200 Mo RAM hors modèle LLM local) sans aucune taxe SaaS par siège.

---

## 🏛️ Architecture & Cartographie des Services

```
                        [ TRAFIC ENTRANT (Ingress Web & API) ]
                                          │
                                          ▼
       ┌─────────────────────────────────────────────────────────────────┐
       │     Aegis Gate PEP / WAF (apps/gate-proxy : Port 8000)          │
       │     Interception in-line OWASP & Scanners (Nikto, SQLmap, RCE)  │
       └────────────────────────────────┬────────────────────────────────┘
                     ┌──────────────────┴──────────────────┐
              (Trafic Bloqué 403)                   (Trafic Légitime 200)
                     │                                     │
                     ▼                                     ▼
       ┌───────────────────────────┐         ┌───────────────────────────┐
       │   Aegis Backend (Go)      │         │    Aegis Web Cockpit      │
       │   (apps/backend : 8080)   │ ◀────── │    (apps/web : 4321)      │
       │   • Triage Feed / API     │         │    • Astro 5 + Vue 3      │
       │   • Scanner Passif Réel   │         │    • Reverse-proxy /docs  │
       └─────────────┬─────────────┘         └─────────────┬─────────────┘
                     │                                     │
                     ▼                                     ▼
       ┌───────────────────────────┐         ┌───────────────────────────┐
       │  TimescaleDB (Port 5432)  │ ◀────── │  Aegis Docs (Starlight)   │
       │  (Hypertables Télémétrie) │         │  (apps/docs : profile)    │
       └───────────────────────────┘         └───────────────────────────┘
                     ▲                                     ▲
                     │ (Télémétrie Énergétique)            │ (Sinkhole DNS & IA)
       ┌───────────────────────────┐         ┌───────────────────────────┐
       │ Aegis Telemetry Agent     │         │ Aegis Egress (Port 5053)  │
       │ (apps/telemetry-agent)    │         │ CoreDNS durci + SLM Local │
       │ Sonde Rust RAPL (/sys)    │         │ Nimble 9B (Ollama :11434) │
       └───────────────────────────┘         └───────────────────────────┘
```

### Cartographie des Ports

| Service | Port Public | Technologie | Rôle Opérationnel |
| :--- | :--- | :--- | :--- |
| **`web`** | **`4321`** (-> 80) | Astro 5, Vue 3, Nginx | **Cockpit SOC & ESG Unifié**, Triage Kanban, Documentation `/docs/`. |
| **`gate-proxy`** | **`8000`** | Go / Node.js Reverse-Proxy | **Passerelle Ingress PEP / WAF** (latence < 1.5 ms, RAM < 25 Mo). |
| **`backend`** | **`8080`** | Go natif (Zero-Mock) | **API Control Plane Go** (Triage feed, scanner passif, métriques). |
| **`egress-gateway`** | **`5053` (UDP/TCP)** | CoreDNS & SLM Inférence | **Passerelle Egress DNS** (Cache CTI + IA locale Nimble 9B). |
| **`telemetry-agent`**| *Host network* | Rust compilé natif | **Sonde Matérielle** (Watts réels Linux RAPL `/sys/class/powercap`). |
| **`timescaledb`** | **`5432`** | PostgreSQL 16 + TimescaleDB | **Stockage Sécurisé Souverain** (Logs immuables & séries temporelles). |
| **`ollama-nimble`** | **`11434`** | Ollama Air-Gapped | **IA Locale Nimble 9B** (0 jeton transmis à des tiers américains). |
| **`docs`** | *Interne* (`/docs/`) | Astro Starlight | **Documentation Officielle** (Profile Docker `--profile docs`). |

---

## 🎛️ Architecture & Services
 
Aegis est architecturé comme une suite Zero-Trust souveraine, autonome et sans aucune dépendance aux clouds des GAFAM :

### 1. Ingress PEP & Token Handler Pure BFF (`gate-proxy:8000`)
- **Latence ultra-faible (< 1,5 ms)** : WAF OWASP Top 10, Virtual Patching, calcul d'entropie de Shannon et réputation IP dynamique.
- **Pure BFF Token Handler** : Scellement de session chiffré AES-256-GCM via cookies HttpOnly (compatible Keycloak OIDC ou mode autonome souverain). Zéro fuite de jetons dans le JavaScript du navigateur.

### 2. Cockpit SOC & ESG Unifié (`web:4321`)
- Cartographie des cyberattaques en temps réel, flux SSE en direct, commandes WAF instantanées et jauges de consommation électrique matérielle.
- Accessible directement ou via le point d'entrée Ingress PEP à l'adresse `/app/`.

### 3. Portail Communautaire Souverain (`/`)
- Page d'accueil sobre et minimaliste sur `/` (EN) et `/fr/` (FR) offrant un accès en 1 clic au Cockpit SOC, à la documentation technique et au dépôt GitHub.

---

## 📋 Prérequis

* **Système d'exploitation** : Linux (Ubuntu 22.04/24.04, Debian 12, Rocky Linux 9, etc.) ou macOS.
* **Docker Engine** : version 24.0+ (`docker --version`).
* **Docker Compose** : version v2.20+ (`docker compose version`).
* **Ressources recommandées** :
  * *Standard (sans modèle IA lourd)* : 2 vCPU, 2 Go RAM, 20 Go SSD.
  * *Complet (avec inférence locale Nimble 9B)* : 4 vCPU, 8 Go RAM (ou GPU compatible).

---

## 🚀 Démarrage Rapide

### 1. Cloner le dépôt
```bash
git clone https://github.com/aivo-labs/aegis.git
cd aegis
```

### 2. Démarrer la suite complète
```bash
# Démarre l'ensemble des conteneurs en mode souverain
docker compose up -d

# (Optionnel) Démarrer également le conteneur de documentation officielle
docker compose --profile docs up -d
```

### 3. Accéder aux interfaces
- **Point d'entrée principal Ingress PEP & WAF** : `http://localhost:8000/`
- **Cockpit SOC & ESG Unifié** : `http://localhost:8000/app/` (ou `http://localhost:4321/app/`)
- **Mire de Connexion Souveraine (Pure BFF)** : `http://localhost:8000/login/` (EN) | `http://localhost:8000/fr/login/` (FR)
- **Documentation Technique (Starlight)** : `http://localhost:8000/docs/` (ou port 4322)
- **Support Bilingue (i18n)** : Anglais par défaut à la racine, Français sous le préfixe `/fr/`, avec bascule de langue sur toutes les barres de navigation.

---

## 🌐 Déploiement VPS & PaaS (Dokploy, Coolify, Traefik)

L'architecture Nginx d'Aegis a été conçue pour une portabilité totale sur VPS sans configuration complexe :
- **Composition Dokploy dédiée** : Utilisez `docker-compose.dokploy.yml` sur Dokploy pour rattacher automatiquement `gate-proxy` et `egress-gateway` au réseau `dokploy-network`.
- **Zéro port tiers à exposer** : L'API Go (`/api/`) et la documentation (`/docs/`) sont relayées de façon transparente via le réseau bridge interne de Docker.
- **Redirections relatives préservées** : Grâce aux directives Nginx `absolute_redirect off;` et `port_in_redirect off;`, Traefik et les reverse-proxies SSL gèrent le trafic sans perte de port ou de protocole.

---

## 🧪 Validation du Banc d'Essai & Batterie de Pentest

Un script automatisé de simulation d'attaques réelles est inclus pour tester l'interception in-line et vérifier sa remontée instantanée dans le Cockpit :

```bash
./scripts/run-pentest-demo.sh
```

### Attaques simulées et bloquées :
1. **Scanners automatisés** : Détection du User-Agent `Nikto/2.1.6` (**403 Forbidden**).
2. **Injections SQL (SQLi)** : Payload `' UNION SELECT username,password FROM users--` (**403 Forbidden**).
3. **Traversée de répertoires (LFI)** : Requête vers `../../../../etc/passwd` (**403 Forbidden**).
4. **Exécution de commandes à distance (RCE)** : Payload `; cat /etc/shadow` (**403 Forbidden**).
5. **Cross-Site Scripting (XSS)** : Injection de balises `<script>` (**403 Forbidden**).
6. **Exfiltration DNS & C2** : Résolution de domaine malveillant sur le port `5053` (**Sinkhole 0.0.0.0**).
7. **Algorithme DGA** : Détection par entropie de Shannon et quarantaine via le modèle SLM **Nimble 9B**.
8. **Flux Conforme** : Requête authentifiée transmise avec latence inférieure à 1.5 ms (**200 OK**).

---

## ⎈ Déploiement Kubernetes & Helm

Aegis supporte le déploiement sur Kubernetes avec attribution énergétique granulaire par Namespace grâce à **Kepler eBPF** :

* **Installation Helm en 1 commande** :
  ```bash
  helm upgrade --install aegis ./deploy/kubernetes/helm/aegis \
    --namespace aegis-system \
    --create-namespace
  ```
* **Manifestes purs (GitOps / ArgoCD)** :
  ```bash
  kubectl apply -f deploy/kubernetes/manifests/
  ```

---

## 📁 Structure du Projet

```
aegis/
├── apps/
│   ├── backend/            # Moteur souverain en Go natif (API REST, Scanner passif, Honeypot)
│   ├── docs/               # Documentation officielle en Astro Starlight (Bilingue EN/FR)
│   ├── egress-gateway/     # Passerelle DNS sortante avec CoreDNS durci & Sinkhole C2
│   ├── gate-proxy/         # Passerelle Ingress PEP / WAF ultra-légère (< 25 Mo RAM)
│   ├── telemetry-agent/    # Sonde matérielle native en Rust (Watts réels Linux RAPL)
│   └── web/                # Interface unifiée : Cockpit SOC Vue 3, Kanban, Landing page Astro 5
├── deploy/
│   ├── docker-compose/     # Variantes Docker (bare-metal, enterprise)
│   └── kubernetes/         # Chart Helm et manifestes Kubernetes
├── docs/                   # Livres blancs, comparatifs techniques et guides d'architecture
├── scripts/                # Scripts d'installation et bancs d'essai de pentest
└── docker-compose.yml      # Composition Docker officielle
```

---

## ⚖️ Licence & Engagements

* **Licence Libre** : Distribué sous licence **AGPLv3** (*GNU Affero General Public License v3*). Code source auditable et librement modifiable.
* **Souveraineté** : Conçu en France par **AIVO Labs** — Immunisé contre le Cloud Act américain.
* **Conformité Réglementaire** : Prêt pour **NIS 2**, **DORA**, le **RGESN 2024** et la **Norme VS (EFRAG 2026)**.

---

## 🧭 Matrice des Priorités de Développement

Pour le détail des verrous techniques et des spécifications d'implémentation, consultez la [Roadmap Technique Complète](ROADMAP.fr.md).  
Pour interconnecter vos serveurs, passerelles et équipements tiers au Control Plane, consultez le [Guide de Raccordement à l'API du Centre de Contrôle](docs/GUIDE_RACCORDEMENT_API.md).

| Verrou / Module | Priorité | Domaine | Gain Majeur |
| :--- | :--- | :--- | :--- |
| **Verrou n°1 : Confinement Egress Réseau** | **P0 (Critique)** | Infrastructure Docker / Egress | Bloque 98 % des Reverse-Shells par IP directe brute |
| **Verrou n°2 : Normalisation Multi-Encodage** | **P1 (Haute)** | Ingress WAF (`gate-proxy`) | Bloque les évasions d'inspection (Unicode, Hex, Base64) |
| **Verrou n°3 : Rate-Limiting & Quarantaine IP** | **P1 (Haute)** | Ingress WAF (`gate-proxy`) | Neutralise le brute-force et le fuzzing automatisé |
| **Verrou n°4 : Virtual Patching Mémoire (PHP2Shell)** | **P1 (Haute)** | Ingress WAF & Agent Hôte | Rejette les saturations OOM HTTP & anti-spawn de shell |
| **Verrou n°5 : Filtre Réseau eBPF/XDP L3/L4 (Kernel UAF)**| **P2 (Moyenne)** | Sonde Rust & Kernel Hôte | Rejette les paquets SYN malveillants avant le noyau Linux |
| **Verrou n°6 : Filtrage DNS Entreprise & Shadow IT** | **P2 (Moyenne)** | Egress Gateway (DHCP / DoH) | Bloque l'exfiltration C2 et encadre les outils de télémaintenance |
| **Verrou n°7 : Agent de Posture Endpoint Frugal Rust** | **P2 (Moyenne)** | Endpoint multiplateforme & SOC | Inventaire local des failles CVE (< 10 Mo RAM) & accès conditionnel |
| **Verrou n°8 : Micro-Segmentation ZTNA Assume Breach** | **P2 (Moyenne)** | Architecture Réseau & PEP | Isole les serveurs critiques des postes de travail bureautiques |

