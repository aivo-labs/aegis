---
title: Démarrage Rapide (2 min)
description: Lancez le banc d'essai complet d'Aegis en local ou sur un serveur via le script 1-clic ou Docker Compose.
---

Ce guide vous permet de déployer et de tester immédiatement la suite souveraine **Aegis** sur votre machine locale, un VPS ou un serveur de test.

## 📋 Prérequis

* Un système Linux (Debian, Ubuntu, AlmaLinux, Fedora) ou macOS avec Docker.
* **Docker Engine** (v24.0+) et **Docker Compose** (v2.20+).
* Ports réseau disponibles :
  * `4321` : Cockpit Opérationnel SOC & ESG
  * `8000` : Passerelle Ingress PEP (WAF)
  * `5053` : Passerelle Egress (DNS UDP)
  * `8080` : API Backend Control Plane (Go / TimescaleDB)
  * `5432` : Base de données TimescaleDB
  * `11434` : Moteur IA local souverain (Micro-SLM Nimble / Ollama)

---

## ⚡ Méthode 1 : Script d'Installation 1-Clic (Recommandé)

Sur un serveur ou une machine de test, exécutez le script d'installation officiel :

```bash
# Déploiement automatique durci (profil VPS / Mono-Serveur)
curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- --profile vps
```

Le script installe automatiquement les dépendances, configure `/opt/aegis` et démarre l'ensemble des conteneurs avec le profil frugal (< 200 Mo RAM).

> [!TIP]
> Sur un **serveur dédié physique**, utilisez le profil Bare-Metal pour activer la captation directe des registres matériels processeur Intel/AMD RAPL :
> ```bash
> curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- --profile baremetal
> ```

---

## 🛠️ Méthode 2 : Clonage Git & Banc d'Essai Manuel

Si vous préférez cloner le monorepo et inspecter le code source :

```bash
# 1. Cloner le monorepo officiel
git clone https://github.com/aivo-labs/aegis.git
cd aegis

# 2. Démarrer toute la suite avec Docker Compose
docker compose up -d --build
```

> [!NOTE]
> Depuis la version **v1.2.2**, la composition Docker injecte automatiquement un lien `/etc/hosts` et un mécanisme de reconnexion dynamique multi-niveaux (`lastGoodIP`) entre le backend Go et TimescaleDB, garantissant une résilience absolue face aux latences du résolveur DNS interne Docker.

---

## 🧭 Accéder aux Interfaces en Direct

Dès que les conteneurs sont opérationnels (`docker compose ps`) :

* 📊 **Cockpit Opérationnel SOC & ESG** : [`http://localhost:4321/app`](http://localhost:4321/app) (Interface « Précision Souveraine » avec bascule mode sombre/clair haute lisibilité)
* 🗂️ **File de Triage des Flux en Direct (Kanban)** : [`http://localhost:4321/app/triage`](http://localhost:4321/app/triage)
* 🛡️ **Centre de Remédiation Cybersécurité** : [`http://localhost:4321/app/actions/security`](http://localhost:4321/app/actions/security)
* 🌿 **Pilotage Énergétique & Mode Frugal** : [`http://localhost:4321/app/actions/green`](http://localhost:4321/app/actions/green)
* 📜 **Tableau de Bord Conformité EFRAG / ANSSI** : [`http://localhost:4321/app/actions/compliance`](http://localhost:4321/app/actions/compliance)

---

## 🧪 Valider le Banc d'Essai avec la Batterie de Pentest

Aegis embarque un banc d'essai complet pour simuler immédiatement des attaques réelles contre la passerelle Ingress et la passerelle Egress :

```bash
# Exécuter la suite complète de 8 attaques
./scripts/run-pentest-demo.sh
```

Ce script déclenche successivement :
1. **Scanner Nikto** (détection de signature User-Agent) ➔ `HTTP 403 Forbidden`
2. **Injection SQL** (`UNION SELECT` sur les tables utilisateurs) ➔ `HTTP 403 Forbidden`
3. **Path Traversal / LFI** (tentative de lecture `/etc/passwd`) ➔ `HTTP 403 Forbidden`
4. **Exécution de Code à Distance (RCE)** (injection de commandes shell) ➔ `HTTP 403 Forbidden`
5. **Cross-Site Scripting (XSS)** (injection de payload script) ➔ `HTTP 403 Forbidden`
6. **Flux Conforme** (requête API légitime) ➔ `HTTP 200 OK`
7. **Exfiltration C2 CrowdSec** (requête DNS sortante vers domaine malveillant) ➔ Sinkholé vers `0.0.0.0`
8. **Exfiltration DGA haute entropie** (détection algorithmique par IA locale Nimble 9B) ➔ Bloqué / Mis en quarantaine

Ouvrez simultanément la page du **Triage Kanban** ([`http://localhost:4321/app/triage`](http://localhost:4321/app/triage)) : vous verrez chaque attaque apparaître en direct, classée par criticité avec sa localisation géographique et ses métadonnées techniques.
