---
title: Passerelle Ingress PEP (WAF, Pure BFF & Virtual Patching)
description: Architecture Zero-Trust de coupure réseau, filtrage OWASP Top 10, protection overflow 413, détection d'entropie de Shannon et gestionnaire de session Pure BFF.
---

La passerelle **Aegis Gate PEP (Policy Enforcement Point)** constitue le bouclier réseau frontal souverain d'Aegis (`apps/gate-proxy`). Déployée en coupure réseau directe ou interfacée comme sous-requête d'authentification (`ForwardAuth`), elle inspecte chaque paquet entrant avant qu'il n'atteigne le réseau applicatif interne, garantissant une décision de sécurité déterministe en **moins de 1,5 milliseconde**.

---

## 🏛️ Schéma d'Architecture Ingress PEP

```
                           [ Requête HTTP/HTTPS Entrante ]
                                          │
                                          ▼
                ┌──────────────────────────────────────────────────┐
                │   Reverse Proxy / Load Balancer Frontal          │
                │   (Traefik v3 Dokploy / Nginx / Caddy / Envoy)   │
                └─────────────────────────┬────────────────────────┘
                                          │
                        Mode ForwardAuth  │  Mode Reverse Proxy
                       (Subrequest /_aegis/verify)     Transparent (:8000)
                                          │
                                          ▼
    ┌────────────────────────────────────────────────────────────────────────┐
    │                 AEGIS GATE PEP — PIPELINE D'INTERCEPTION               │
    │                                                                        │
    │  1. Token Handler Pure BFF (/api/auth/*)                               │
    │     ↳ Résolution OIDC PKCE + Cookies scellés AES-256-GCM               │
    │                                                                        │
    │  2. Moteur de Décanonisation & Normalisation Récursive                 │
    │     ↳ Décodage multi-niveaux URL/Hex/Unicode, suppression null-bytes   │
    │                                                                        │
    │  3. Bouclier Overflow RFC 413 (Payload Body Cap)                       │
    │     ↳ Troncature immédiate à 32 Ko (Anti-DDoS & Buffer Overflow)       │
    │                                                                        │
    │  4. Moteur d'Entropie de Shannon (H)                                   │
    │     ↳ Détection mathématique de shellcodes, binaires & tokens suspects  │
    │                                                                        │
    │  5. Registre de Règles WAF Durcies (OWASP CRS)                         │
    │     ↳ Scanners (Nikto, Nuclei), SQLi, XSS, RCE, LFI, SSRF, CMS Probes  │
    │                                                                        │
    │  6. Virtual Patching Zero-Day Dynamique                                │
    │     ↳ Neutralisation CVE amont (ex: PHP2Shell, JNDI Injection)         │
    └───────────────────────────────────┬────────────────────────────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                 [ VERDICT : BLOCK ]           [ VERDICT : ALLOW ]
                 • HTTP 403 / 413 Immédiat      • HTTP 200 Transmis
                 • Télémétrie JSON temps réel   • Headers X-Aegis-Verified
                 • Envoi vers TimescaleDB       • Transmission aux Apps
```

---

## 🛡️ Les 6 Piliers du Pipeline d'Inspection

### 1. Architecture Pure BFF (Backend-for-Frontend)
Aegis élimine totalement les failles de vol de jetons par scripts malveillants (XSS) :
* Aucun jeton d'accès (`access_token`, `id_token` ou `refresh_token`) n'est jamais stocké dans le navigateur (ni en `localStorage`, ni en `sessionStorage`, ni en mémoire volatile JavaScript).
* Le module `apps/gate-proxy/src/bff` intercepte les routes `/api/auth/*`, orchestre le protocole OIDC standardisé avec échange **PKCE (RFC 7636)**, et délivre au navigateur un cookie de session chiffré **AES-256-GCM**, `HttpOnly`, `SameSite=Strict`, `Secure`.
* En amont des microservices internes, Aegis Gate déchiffre la session et injecte les en-têtes d'identité certifiés (`X-Aegis-User-Id`, `X-Aegis-User-Role`, `X-Aegis-Tenant-Id`).

### 2. Normalisation Multi-Encodage & Anti-Obfuscation (Verrou n°2)
Les attaquants utilisent fréquemment l'obfuscation imbriquée pour contourner les règles de motifs (multi-encodage `%252e%252e%252f`, caractères nuls `%00`, encodages mixtes UTF-8, entités HTML et conteneurs Base64).
* **Décodage Récursif 3 Passes** : Le moteur décanonise récursivement l'ensemble des chemins d'URI, chaînes de requête, en-têtes et corps jusqu'à atteindre la forme brute stable.
* **Normalisation des Entités & Échappements** : Suppression des octets nuls, décodage des entités HTML nommées, décimales et hexadécimales (`&quot;`, `&#x27;`), et résolution des échappements Hex/Unicode (`\x..`, `\u....`, `%u....`).
* **Assainissement des Chemins** : Normalisation stricte des séparateurs de chemin (`/./`, `//`, Windows `\`) avant inspection de traversée de répertoires (*Path Traversal*).
* **Extraction Base64 Automatique** : Tout segment Base64 suspect (`>= 16` caractères alphanumériques avec padding valide) est décodé à la volée et soumis à l'inspection WAF primaire.

### 3. Rate-Limiting Volumétrique & Quarantaine IP Auto-Jail (Verrou n°3)
Aegis Gate protège les serveurs applicatifs contre les rafales d'attaques et le fuzzing automatisé :
* **Limiteur à Fenêtre Glissante** : Applique un budget strict de **60 requêtes par 10 secondes** par adresse IP cliente, retournant un code `HTTP 429 Too Many Requests` avec en-tête standard `Retry-After: 10`.
* **Auto-Jail Automatique de 15 Minutes** : Toute IP non authentifiée cumulant **3 infractions critiques** (`risk_score >= 90`) en moins de **5 minutes** est automatiquement placée en quarantaine dans la liste de blocage persistante pour 15 minutes (`AUTO_JAIL_TEMPORARY_QUARANTINE`), synchronisée avec le Control Plane Go et visualisable dans le Cockpit.

### 4. Durcissement Protocole HTTP & Défense RFC 413 / 431 (Verrou n°4)
* **Budgets d'En-têtes (`HTTP 431`)** : Tout paquet dépassant `8 Ko` d'en-têtes cumulés, `4 Ko` pour un en-tête individuel ou plus de `64` en-têtes est rejeté avec `HTTP 431 Request Header Fields Too Large`.
* **Plafond Volumétrique du Corps (`HTTP 413`)** : Impose une coupure matérielle stricte (configurable via `AEGIS_MAX_PAYLOAD_BYTES`, fixé par défaut à `32 Ko`), coupe immédiatement la transmission avec `HTTP 413 Payload Too Large` et neutralise les bombes de compression.
* **Validation Multipart RFC** : Valide le format des frontières `multipart/form-data`, limite la profondeur des conteneurs imbriqués (`<= 3`) et bloque les extensions téléversées exécutables (`.php`, `.phtml`, `.phar`, `.sh`).

### 5. Moteur d'Entropie de Shannon
* Le calcul de l'entropie de Shannon $H(X) = -\sum P(x) \log_2 P(x)$ évalue la dispersion informationnelle des segments d'URL et des corps de requêtes.
* Une chaîne présentant une entropie supérieure à **3,85** sur une longueur significative signale immédiatement un binaire compilé injecté, un shellcode obfusqué en base64 ou une tentative d'exfiltration de clés cryptographiques.

### 5. Filtrage WAF & Détection des Outils Offensifs
Aegis bloque à la racine les vecteurs d'attaque les plus destructeurs :
* **Scanners offensifs** : Cartographieurs de vulnérabilités bloqués dès le premier paquet (`Nikto`, `SQLmap`, `Nuclei`, `Gobuster`, `Dirbuster`, `Nmap`, `Acunetix`, `WPScan`, `Hydra`, etc.).
* **Injections SQL (SQLi)** : Détection des requêtes aveugles temporelles (`benchmark()`, `pg_sleep()`), `UNION SELECT`, extraction de schéma (`information_schema`).
* **Path Traversal & LFI** : Neutralisation des fuites de fichiers sensibles (`/etc/passwd`, `/etc/shadow`, `.env`, `.git/config`, `wp-config.php`).
* **Injections de Commandes (RCE)** : Interception des exécutions shell non sollicitées (`; cat`, `| id`, `$(whoami)`, `/bin/sh`).
* **Cross-Site Scripting (XSS)** : Filtrage strict des balises exécutables et gestionnaires d'événements DOM (`<script>`, `onerror=`, `onload=`, `javascript:`).

### 6. Virtual Patching Zero-Day
Lorsqu'une nouvelle vulnérabilité critique est découverte sur un composant applicatif sous-jacent (par exemple la vulnérabilité PHP2Shell CVE-2026-33044 ou les injections JNDI Log4j), Aegis Gate applique immédiatement une règle de patch virtuel au niveau du proxy. Les applications vulnérables sont immunisées instantanément, sans exiger l'arrêt du service ni le redéploiement d'urgence du code source métier.

---

## ⚙️ Deux Modes de Fonctionnement Disponibles

Aegis Gate s'intègre de façon non intrusive à n'importe quelle topologie réseau existante :

### Mode A : External Authorizer (ForwardAuth)
Le proxy frontal principal (ex: **Traefik v3** dans Dokploy ou **Nginx**) conserve la terminaison TLS Let's Encrypt et interroge Aegis sur son point de contrôle `/_aegis/verify` :
* La sous-requête transmet les en-têtes d'origine (`X-Forwarded-Uri`, `X-Forwarded-Method`, `X-Forwarded-For`).
* Aegis évalue la requête en **0,4 ms**. Si le flux est sain, il retourne un code `HTTP 200 OK` avec les en-têtes de validation. Traefik transmet alors la requête au conteneur cible.
* Si une menace est détectée, Aegis retourne immédiatement `HTTP 403 Forbidden` ou `HTTP 413`, interrompant la requête avant qu'elle n'atteigne le conteneur cible.

### Mode B : Reverse Proxy Transparent (Edge Gateway)
Aegis Gate est positionné en frontal direct sur le port `8000` (ou derrière un routeur réseau L4). Il prend en charge l'inspection in-line et réexpédie le trafic vérifié vers les upstreams configurés (`BACKEND_URL`, `WEB_URL` ou table `AEGIS_UPSTREAM_ROUTING`).

---

## 📡 Télémétrie d'Audit & Corrélation Temps Réel

Chaque évaluation produit une charge utile de télémétrie structurée transmise au backend Go/TimescaleDB :

```json
{
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "client_ip": "185.220.101.5",
  "user_agent": "Mozilla/5.0 (Nikto/2.1.6)",
  "http_method": "GET",
  "request_uri": "/admin/wp-config.php.bak",
  "decision": "BLOCK",
  "http_status_returned": 403,
  "latency_ms": 0.8,
  "threat_type": "PENTEST_SCANNER_DETECTED",
  "severity": "CRITICAL",
  "risk_score": 96,
  "entropy": 4.12,
  "metadata": {
    "engine": "Aegis Gate PEP (OWASP CRS)",
    "rule_triggered": "ScannerSignatureRule",
    "virtual_patch_active": true
  }
}
```

L'incident est instantanément projeté dans le **Triage Kanban** du Cockpit d'administration SOC pour analyse d'impact et bannissement automatique d'IP.

---

## 📚 Articles & Références Techniques AIVO

Pour explorer les fondations théoriques et les retours d'expérience en production ayant mené à la conception d'Aegis Gate PEP, consultez nos publications détaillées :

* 📖 [**Guide Architecture Pure BFF : Sécurité OIDC sans compromis**](https://aivo.fr/blog/guide-architecture-pure-bff-securite-oidc) — Démonstration approfondie du modèle Token Handler, de l'élimination des tokens XSS et du chiffrement AES-GCM des sessions.
* 📖 [**Entropie de Shannon & Décision Zero-Trust : L'IA Frugale au service du WAF**](https://aivo.fr/blog/entropie-shannon-decision-zero-trust-ia-frugale) — Formalisation mathématique du calcul d'entropie pour la classification instantanée de menaces à coût énergétique quasi-nul.
* 📖 [**Anatomie d'un VPS sous assaut continu : Scanners, Énergie et Réponses Actives**](https://aivo.fr/blog/anatomie-vps-sous-assaut-continu-scanners-energie) — Analyse terrain des volumes de scans automatisés reçus sur nos serveurs et mesure de l'empreinte matérielle de l'interception.
* 🔬 [**Étude de cas Aegis Sovereign Gate sur AIVO.fr**](https://aivo.fr/realisations/aegis-sovereign-gate) — Synthèse exécutive du projet, de ses jalons d'homologation souveraine et des perspectives CTI / agent harness.
