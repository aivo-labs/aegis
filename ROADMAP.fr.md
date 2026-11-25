# 🛡️ Roadmap Technique Aegis — Durcissement Zero-Trust, GreenOps & Sécurité IA

<p align="center">
  <a href="ROADMAP.md">English</a> | <strong>Français</strong>
</p>

Ce document constitue la **source de vérité unique** de la feuille de route d'ingénierie d'Aegis, partagée entre le dépôt open source et l'[étude de cas architecturale AIVO](https://aivo.fr/realisations/aegis-sovereign-gate).

Chaque chantier est suivi strictement par **statut d'implémentation (`✅ Livré`, `🚧 Partiel`, `⏳ Planifié / En conception`)** et **priorité technique (`P0` à `P3`)** — sans dates calendaires fictives — autour de trois objectifs mesurables :
1. Porter le taux de neutralisation face aux techniques d'évasion manuelles (Red Team / Pentest), aux **orchestrateurs de pentest IA autonomes (type ARTEX / Hexstrike)** et aux failles mémoire de **~78 % à > 95 %**.
2. Déployer une **défense en profondeur « Assume Breach »** couvrant conteneurs, noyau Linux et postes bureautiques (`agent Rust < 10 Mo RAM`), sans taxe SaaS par siège.
3. Étendre le filtrage souverain aux **charges d'IA générative et agentique** (garde-fous anti-exfiltration LLM, sandboxing d'Agent Harnesses, CTI collaborative P2P et micro-SLM `< 1B` sur CPU).

---

## 🧭 Matrice Unifiée des Priorités & Statuts

| Phase | Verrou / Module | Statut | Priorité | Périmètre Codebase | Gain Sécurité & GreenOps Majeur |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **Socle v1** | **WAF Ingress, PHP2Shell VP, Pure BFF & Cockpit RAPL** | **✅ Livré** | **Socle v1** | `gate-proxy`, `backend`, `telemetry-agent`, `web` | Edge PEP `< 1,5 ms` au repos, `HTTP 413` (`32 Ko`), `100 %` blocage PHP2Shell (`0 %` CPU cible), Pure BFF OIDC & certificats RAPL PDF/CSV |
| **P0/P1** | **n°1 Confinement Egress Réseau Strict & Allowlist DNS-to-IP** | **✅ Livré (v1.2)** | **P0 (Critique)** | `docker-compose*.yml`, `egress-gateway`, `deploy/security/` | Bloque les reverse-shells TCP par IP brute sans résolution DNS (réseau `internal: true`, `DnsToIpAllowlist` TTL 60s + `egress-lockdown.nft`) |
| **P0/P1** | **n°2 Normalisation Multi-Encodage (Base64 / HTML / Hex)** | **✅ Livré (v1.2)** | **P1 (Haute)** | `apps/gate-proxy/src/engine/canonicalizer.ts`, `sandboxEngine.ts` | Décodage URL 3 passes, entités HTML, séquences Hex/Unicode, normalisation de chemin (`/./`, `//`, `\`) & décodage Base64 automatique (`>= 16` car.) |
| **P0/P1** | **n°3 Rate-Limiting Volumétrique (`429`) & Quarantaine IP Auto-Jail** | **✅ Livré (v1.2)** | **P1 (Haute)** | `apps/gate-proxy/src/quarantine/ip-reputation.ts`, `backend` | Blacklist SOC persistante + fenêtre glissante (`60 req/10s`, `HTTP 429`) & Auto-Jail (`3` offenses critiques en `5 min` → `15 min` de quarantaine) |
| **P0/P1** | **n°4 Durcissement Protocole (`431`), Multipart RFC & Anti-Spawn Shell** | **✅ Livré (v1.2)** | **P1 (Haute)** | `apps/gate-proxy/src/`, `apps/telemetry-agent/src/collector/` | Plafonds en-têtes `HTTP 431` (`8 Ko` total / `4 Ko` unitaire / `64` max), validation RFC multipart, anti-compression bomb & sonde Rust `/proc` anti-spawn shell |
| **P0/P1** | **n°5 Audit Passif Continu, PQC (`ML-KEM`), CERT-FR & Remédiation** | **✅ Livré (v1.2)** | **P1 (Haute)** | `apps/backend/internal/scanner/`, `service/audit_service.go`, `web` | Audits périodiques planifiés (`6h`/`12h`/`24h`), détection de dérive, snippets guidés Traefik/Nginx/Caddy/PHP, sonde PQC `X25519MLKEM768` & scoring pondéré CVSS |
| **Durcissement** | **v1.2.1/v1.2.2 Failover TimescaleDB, Filtre Spawn Worker & UI Précision Souveraine** | **✅ Livré (v1.2.2)** | **P1 (Haute)** | `apps/backend/internal/database/`, `telemetry-agent`, `web`, `aegis-cloud` | Lien Docker `/etc/hosts` & failover `lastGoodIP` (zéro 500), filtre spawn workers légitimes, clamp CPU `[0, 100]%`, résilience micro-SLM Ollama & refonte UI/UX anti-vibe |
| **v1.3 (P1.5)** | **n°5-Bis Bouclier « Anti-Artex » (Défense Contre le Pentest IA Autonome)** | **✅ Livré (v1.3)** | **P1.5 (Haute)** | `gate-proxy`, `egress-gateway` | Mode `403` opaque, Tarpit & Canary Honeypot anti-LLM, Sinkhole OAST/LOTC (`interact.sh`), bouclier API BOLA/IDOR/Swagger, détection faux UA & Context-Binding BFF |
| **P2** | **n°6 Filtre Réseau `eBPF / XDP` L3/L4, Kill-Switch `SIGKILL` & Veille Kernel** | **⏳ En conception** | **P2 (Moyenne)** | `apps/telemetry-agent/src/` | Rejet carte réseau `XDP_DROP` (`< 0,005 ms`) contre SYN forgés, `SIGKILL < 10 ms` actif sur spawn shell illégitime + veille version `uname -r` |
| **P2** | **n°7 Filtrage DNS Entreprise & Shadow IT (DoH/DoT)** | **⏳ À planifier** | **P2 (Moyenne)** | `apps/egress-gateway/src/` | Résolveur central DHCP/`:5053` + DoH/DoT nomade encadrant les outils RAT (TeamViewer, AnyDesk, RustDesk) en Prod/DMZ |
| **P2** | **n°8 Agent Posture Endpoint Rust (`< 10 Mo`) & `mTLS` PQC** | **⏳ En conception** | **P2 (Moyenne)** | Nouveau `aegis-node-agent` (Rust) + `web` | Inventaire CVE local & hygiène poste multi-OS via **canal `mTLS` hybride post-quantique (`X25519MLKEM768`)** + accès conditionnel |
| **P2** | **n°9 Micro-Segmentation ZTNA « Assume Breach »** | **⏳ En conception** | **P2 (Moyenne)** | Architecture réseau & PEP | Supprime les routes L3 bureautique → BDD et détecte les scans ARP/ports internes (Honeypot réseau) |
| **P3** | **n°10 Gouvernance IA « Two-Door » & Zero-Secret Egress** | **⏳ En conception** | **P3 (R&D)** | `gate-proxy` (Ingress) & `egress-gateway` | Garde-fous Prompt Injection en entrée + **Zero-Secret Placeholder** (zéro clé API dans l'agent, anonymisation PII & injection en bordure) |
| **P3** | **n°11 Passerelle MCP Zero-Trust & Registre PQC AI Act** | **⏳ En conception** | **P3 (R&D)** | `gate-proxy`, sonde `seccomp`/eBPF & `backend` | Filtrage granulaire MCP (`tools/list`, `tools/call`) par identité, sandboxing noyau & registre immuable signé **`Ed25519 + ML-DSA` (FIPS 204)** |
| **P3** | **n°12 CTI Collaborative P2P & Micro-SLM `< 1B` CPU** | **🚧 Partiel** | **P3 (R&D)** | `apps/egress-gateway/src/cti/blocklist.ts`, Ollama | Blocklist C2 statique + option **Nimble 9B** (Ollama) **livrés en v1** ; ajout flux Abuse.ch/CERT-FR/CISA KEV, partage P2P & SLM `< 1B` CPU-only |

---

## ✅ Socle v1 / v1.1 / v1.2 Déjà Livré & Vérifié dans le Dépôt

Avant les prochains verrous P2/P3, les briques suivantes sont **opérationnelles et testées** dans les piles Docker actuelles :

| Pilier | Implémentation Vérifiée dans le Code | Preuves & Métriques Mesurées |
| :--- | :--- | :--- |
| **Ingress PEP & Virtual Patching** | [`apps/gate-proxy/src/server.ts`](apps/gate-proxy/src/server.ts), [`engine/inspector.ts`](apps/gate-proxy/src/engine/inspector.ts), [`engine/entropy.ts`](apps/gate-proxy/src/engine/entropy.ts), [`rules/zeroday.rule.ts`](apps/gate-proxy/src/rules/zeroday.rule.ts) | Benchmark rafale `CVE-2024-4577` PHP2Shell : **`602 / 602` bloquées (`100 %`)**, **`0 %` CPU PHP-FPM**, **`5,81 W` moy.** vs **`24,14 W` moy. (`37,58 W` pic)** et **`743,4 %` CPU** sans bouclier (**`×4,34` d'énergie gaspillée**) |
| **Pure BFF Token Handler** | [`apps/gate-proxy/src/bff/auth-handler.ts`](apps/gate-proxy/src/bff/auth-handler.ts), [`bff/session.ts`](apps/gate-proxy/src/bff/session.ts) | Zéro JWT dans le `localStorage`/JS navigateur ; cookies chiffrés AES-256-GCM (`HttpOnly`) ; compatible Keycloak, Authelia, Okta ou mode autonome |
| **Egress DNS Sinkhole & SLM v1** | [`apps/egress-gateway/src/index.ts`](apps/egress-gateway/src/index.ts), [`dns/udp-server.ts`](apps/egress-gateway/src/dns/udp-server.ts), [`engine/system-one.ts`](apps/egress-gateway/src/engine/system-one.ts) | Sinkhole DNS `:5053` (`0.0.0.0`), entropie de Shannon anti-DGA (`H > 4.2`), blocklist CTI statique + SLM optionnel **Nimble 9B** (`ollama-nimble:11434`) air-gapped |
| **Télémétrie RAPL & Certificat CSRD** | [`apps/telemetry-agent/src/main.rs`](apps/telemetry-agent/src/main.rs), `collector/rapl.rs`, `collector/cpu.rs`, TimescaleDB | Lecture directe `/sys/class/powercap` + `/proc/stat`, support Kepler eBPF sous Kubernetes, exports PDF & CSV conformes Scope 2 / CSRD |
| **Cockpit SOC, Scanner PQC & CVE Feed** | [`apps/backend/internal/scanner/engine.go`](apps/backend/internal/scanner/engine.go), [`scanner/pqc.go`](apps/backend/internal/scanner/pqc.go), [`internal/service/cve_service.go`](apps/backend/internal/service/cve_service.go), `apps/web` | Flux SSE temps réel, audit passif multi-pages (en-têtes, TLS, DNS, EcoIndex, **sonde Post-Quantique NIST FIPS 203 `X25519MLKEM768`**), matrice CVE Feed interactive |

---

## 🔥 Phase P0 / P1 — Durcissement Périmétrique, Egress & Posture Continue (✅ Livré en v1.2.0)

### 🔒 Verrou n°1 : Confinement Egress Réseau Strict & Allowlist DNS-to-IP (Anti-Reverse Shell par IP brute)
- **Statut :** ✅ Livré (`v1.2.0`)
- **Priorité :** Critique (**P0**) — Prérequis avant hébergement de charges tierces / exposition VPS multi-tenant
- **Gain d'efficacité Egress :** Passe de `0 %` à `~98 %` sur les appels TCP sortants vers IP codée en dur sans résolution DNS
- **Implémentation livrée :**
  1. Segmentation réseau Docker dans [`docker-compose.yml`](docker-compose.yml) et [`docker-compose.dokploy.yml`](docker-compose.dokploy.yml) : réseau isolé `aegis-internal` (`internal: true`) pour `timescaledb`, `web` et `telemetry-agent`, et pont contrôlé `aegis-edge` pour les passerelles.
  2. Moteur d'allowlist dynamique [`apps/egress-gateway/src/engine/ip-allowlist.ts`](apps/egress-gateway/src/engine/ip-allowlist.ts) (`DnsToIpAllowlist` avec TTL 60s) intégré dans [`evaluator.ts`](apps/egress-gateway/src/engine/evaluator.ts) et [`tcp-server.ts`](apps/egress-gateway/src/http/tcp-server.ts) (`POST /api/v1/egress/verify-connection`) rejetant tout appel sortant vers une IP littérale (`RAW_IP_REVERSE_SHELL_BLOCKED`) ou non préalablement résolue via `:5053` (`UNRESOLVED_DIRECT_IP_EGRESS_BLOCKED`).
  3. Règles de confinement hôte [`deploy/security/egress-lockdown.nft`](deploy/security/egress-lockdown.nft) pour serveurs Linux bare-metal / VPS.

### 🔒 Verrou n°2 : Normalisation Multi-Encodage Anti-Obfuscation
- **Statut :** ✅ Livré (`v1.2.0`)
- **Priorité :** Haute (**P1**)
- **Gain mesuré :** **+12 % à +15 %** de couverture face aux contournements WAF manuels
- **Implémentation livrée :**
  1. Pipeline complet dans [`apps/gate-proxy/src/engine/canonicalizer.ts`](apps/gate-proxy/src/engine/canonicalizer.ts) et [`apps/web/src/services/sandboxEngine.ts`](apps/web/src/services/sandboxEngine.ts) : décodage URL récursif (3 passes), suppression des octets nuls, décodage des entités HTML nommées/décimales/hexadécimales, séquences d'échappement Hex/Unicode (`\x..`, `\u....`, `%u....`), et extraction + décodage automatique des charges Base64 suspectes (`>= 16` caractères) avant l'inspection WAF.
  2. Normalisation stricte des séparateurs de chemin (`/./`, `//`, `\`) avant `TRAVERSAL_REGEX`.

### 🔒 Verrou n°3 : Rate-Limiting Volumétrique & Quarantaine IP Automatique (Auto-Jail)
- **Statut :** ✅ Livré (`v1.2.0`)
- **Priorité :** Haute (**P1**)
- **Gain mesuré :** Neutralise **99 %** du fuzzing automatisé et des rafales de force brute
- **Implémentation livrée :**
  1. Limiteur volumétrique à fenêtre glissante (`60 req / 10 s` par IP avec en-tête `Retry-After: 10` et retour `HTTP 429 Too Many Requests`) dans [`apps/gate-proxy/src/quarantine/ip-reputation.ts`](apps/gate-proxy/src/quarantine/ip-reputation.ts) et [`server.ts`](apps/gate-proxy/src/server.ts).
  2. **Auto-Jail 15 minutes** : toute IP non authentifiée cumulant `3` alertes critiques (`risk_score >= 90`) en moins de `5` minutes passe en quarantaine automatique de **15 minutes** (`AUTO_JAIL_TEMPORARY_QUARANTINE`), synchronisée avec le Control Plane Go (`ttlMinutes` / `expires_at`) et visible dans le panneau Contrôles du Cockpit.

### 🔒 Verrou n°4 : Durcissement Protocole HTTP (`431`), Multipart RFC & Surveillance Anti-Spawn
- **Statut :** ✅ Livré (`v1.2.0`)
- **Priorité :** Haute (**P1**)
- **Implémentation livrée :**
  1. **Durcissement HTTP dans [`inspector.ts`](apps/gate-proxy/src/engine/inspector.ts)** : plafonnement strict des en-têtes HTTP (`> 8 Ko` global, `> 4 Ko` par en-tête ou `> 64` en-têtes → `HTTP 431 Request Header Fields Too Large`), conformité `multipart/form-data` (profondeur `<= 3`, bornes RFC valides, blocage des extensions exécutables `.php`, `.phtml`, `.phar`, `.sh`) et blocage du chaînage `Content-Encoding` anti-bombes de compression.
  2. **Détection de spawn de shell côté hôte** : module Rust [`apps/telemetry-agent/src/collector/process_spawn.rs`](apps/telemetry-agent/src/collector/process_spawn.rs) inspectant `/host/proc` et `/proc` pour lever une alerte critique dès qu'un worker web (`php-fpm`, `php-cgi`, `node`, `nginx`, `apache2`, `caddy`) engendre un interpréteur shell ou un binaire d'exfiltration (`sh`, `bash`, `nc`, `curl`, `python`, `perl`, `socat`).

### 🔒 Verrou n°5 : Supervision Continue des Postures, Sonde Post-Quantique (`ML-KEM`) & Remédiation Guidée
- **Statut :** ✅ Livré (`v1.2.0`)
- **Priorité :** Haute (**P1**)
- **Implémentation livrée :**
  1. **Audits passifs planifiés en continu & détection de dérive** : endpoints `GET/POST /api/v1/audit/schedule` dans [`audit_service.go`](apps/backend/internal/service/audit_service.go) et [`audit_handler.go`](apps/backend/internal/http/handlers/audit_handler.go), avec évaluation automatique de dérive (`EvaluatePostureDrift`) et contrôle visuel (`6h` / `12h` / `24h`) dans [`AuditPanel.vue`](apps/web/src/components/soc/actions/AuditPanel.vue).
  2. **Assistant de remédiation guidée dans le Cockpit** : génération dynamique d'extraits prêts au copier-coller (`GenerateGuidedRemediationSnippets`) pour **Traefik**, **Nginx**, **Caddy** et **Apache / `php.ini`** couvrant les en-têtes HTTP manquants, le TLS 1.3 Post-Quantique (`X25519MLKEM768`) et le confinement PHP SAPI.
  3. **Ingestion Souveraine CERT-FR & Qualification Continue (`PENDING_VERIFICATION`)** : synchronisation avec le flux officiel du CERT-FR (ANSSI) et marquage des alertes émergentes sous le statut `« Procédure en cours de vérification (Aegis Lab) »`.
  4. **Scoring Composite Pondéré CVSS (Zero Fake-Positive)** : pénalités de score indexées sur la sévérité CVSS des failles exposées (`-25 pts` par faille CRITICAL non mitigée, plafonnement du score à `65/100` en présence d'une CVE critique).

### 🔒 Stabilisation & Durcissement : Failover DNS TimescaleDB, Filtrage Spawn Workers & UI Précision Souveraine (v1.2.1 / v1.2.2)
- **Statut :** ✅ Livré (`v1.2.2`)
- **Priorité :** Haute (**P1**)
- **Implémentation livrée :**
  1. **Failover de Connexion TimescaleDB Multi-Niveaux** : durcissement du driver PostgreSQL Go ([`apps/backend/internal/database/pgwire.go`](apps/backend/internal/database/pgwire.go)) avec inspection statique de `/etc/hosts`, TCP KeepAlive à 30s et repli dynamique sur `lastGoodIP`, complété par la directive Docker Compose `links: - timescaledb:timescaledb` éliminant les erreurs `SERVFAIL` du résolveur DNS interne Docker (`127.0.0.11:53`) en topologie multi-bridge.
  2. **Filtrage Contextuel du Spawn de Processus Worker** : ajout de `is_benign_worker_child_cmd` dans [`apps/telemetry-agent/src/collector/process_spawn.rs`](apps/telemetry-agent/src/collector/process_spawn.rs) pour ignorer les wrappers légitimes (`sh -c dotenv ...`, `npm`, `pnpm`, `node dist/`) tout en maintenant une vigilance absolue sur les vrais reverse shells interactifs et binaires d'exfiltration.
  3. **Ingestion Haute Résilience & Clamping Métrique** : plafonnement mathématique garanti de l'utilisation CPU entre `0.0` et `100.0%` dans [`telemetry_service.go`](apps/backend/internal/service/telemetry_service.go) pour satisfaire la contrainte `CHECK` PostgreSQL, et résolution résiliente en 4 niveaux de la clé étrangère `node_id`.
  4. **Résilience du Modèle Micro-SLM** : mise à jour des manifestes Docker Compose pour télécharger le modèle léger standard `qwen2.5:0.5b` et l'associer localement à `nimble` via `ollama cp`, contournant les erreurs 412 de schéma v2 du registre public.
  5. **Système de Design UI/UX Précision Souveraine** : éradication complète des emojis décoratifs au profit d'icônes SVG nettes, refonte du mode clair haute lisibilité via des sélecteurs d'attributs globaux (`[class*="bg-slate-900"]`) et alignement des métriques techniques en `font-mono tabular-nums` sur `Aegis` et `aegis-cloud`.

---

## ⚔️ Phase P1.5 (v1.3) — Bouclier Souverain « Anti-Artex » (Défense Contre le Pentest IA Autonome — ✅ Livré)

### 🔒 Verrou n°5-Bis : Neutralisation des Orchestrateurs Offensifs Multi-Agents (ARTEX, Hexstrike, CyberStrikeAI)
- **Statut :** ✅ Livré (`v1.3.0`)
- **Priorité :** Haute (**P1.5** — Réponse directe aux frameworks de pentest IA autonomes pilotés par LLM)
- **Contexte & Menace :** Les orchestrateurs offensifs agentiques (tels qu'**ARTEX**) décomposent un objectif d'intrusion en sous-tâches exécutées à vitesse machine (*Machine-Speed Kill Chain* `< 3h`) par des *Agent Workers* autonomes. Contrairement aux scanners classiques, ils analysent les réponses HTTP `403` pour adapter leurs payloads, attaquent la logique métier des API (**BOLA / IDOR**, schémas OpenAPI/GraphQL), valident leurs exploits à l'aveugle via des relais **OAST** (`interact.sh`) et chaînent les jetons volés.
- **Plan d'action technique (6 Briques « Anti-Artex ») :**
  1. **Déception Cognitive Anti-LLM, Mode Opaque `403`, Tarpit Adaptatif & Canary Honeypot ([`apps/gate-proxy/src/server.ts`](apps/gate-proxy/src/server.ts))** :
     - **Mode `STEALTH_BLOCK` en production** : masquage complet du nom de la règle (`threat_detected`) et du motif (`pattern`) dans la réponse HTTP externe (ne renvoyant qu'un `event_id` opaque tandis que le détail est enregistré dans TimescaleDB), privant le *Planner* LLM d'ARTEX de tout oracle d'apprentissage.
     - **Tarpit Adaptatif** : injection d'une latence progressive (`3s` $\rightarrow$ `10s` $\rightarrow$ `25s`) sur les IP cumulant des anomalies pour paralyser les boucles d'orchestration synchrones et épuiser les budgets de timeouts des *Workers* IA.
     - **Canary Honeypot & Pièges Contextuels (`/.env` piégé)** : distribution optionnelle sur des routes pièges de jetons *Canary* factices traçables ; toute réutilisation d'un jeton Canary dans une requête ultérieure prouve mathématiquement un chaînage automatisé et déclenche un bannissement immédiat (`CANARY_TOKEN_TRIPWIRE_TRIGGERED`).
  2. **Neutralisation Egress des Serveurs OAST & Relais « Living-off-the-Trusted-Cloud » (LOTC) ([`apps/egress-gateway/src/cti/blocklist.ts`](apps/egress-gateway/src/cti/blocklist.ts))** :
     - **Blocklist OAST native dans le Sinkhole DNS (`:5053`)** : blocage par défaut des infrastructures de callback d'outils de pentest (`*.interact.sh`, `*.interactsh.com`, `*.oast.pro`, `*.oast.live`, `*.oast.site`, `*.oast.online`, `*.oast.fun`, `*.oast.me`, `*.burpcollaborator.net`, `*.oastify.com`, `*.canarytokens.com`, `*.webhook.site`, `*.requestbin.com`, `*.pipedream.net`), rendant ARTEX **100 % aveugle** sur les vulnérabilités asynchrones (*Blind SSRF, Blind RCE, Blind XXE*).
     - **Politique LOTC Serveur** : blocage optionnel des tunnels et relais d'exfiltration publics (`*.ngrok-free.app`, `*.ngrok.io`, `*.trycloudflare.com`, `*.loca.lt`, `transfer.sh`, `pastebin.com`) depuis les conteneurs de production.
  3. **Bouclier de Logique Métier API : Anti-BOLA / IDOR, Anti-Mass Assignment & Masquage OpenAPI/GraphQL ([`apps/gate-proxy/src/rules/`](apps/gate-proxy/src/rules/default-rules.ts))** :
     - **Verrouillage des schémas de découverte d'API** : blocage en production de l'accès public non authentifié aux spécifications (`/swagger*`, `/openapi.json`, `/api-docs*`, `/v2/api-docs`, `/v3/api-docs`, `/redoc`, `/actuator*`) ainsi qu'aux requêtes d'introspection GraphQL (`__schema`, `__type`).
     - **Détecteur d'énumération séquentielle (Anti-BOLA / IDOR)** : suivi par fenêtre glissante de la cardinalité des identifiants interrogés sur une même route paramétrée (`/api/v1/resource/{id}`) pour bloquer l'extraction automatisée d'objets métiers (`API_BOLA_ENUMERATION_DETECTED`).
     - **Filtre Anti-Mass Assignment & Prototype Pollution** : inspection des corps JSON (`POST`/`PUT`/`PATCH`) contre l'injection de champs d'élévation de privilèges (`"role":"admin"`, `"is_admin":true`, `"permissions"`, `"__proto__"`, `"constructor.prototype"`).
  4. **Détection Comportementale « Low-and-Slow » & Incohérence d'Empreinte Navigateur (`Header Fingerprint Mismatch`) ([`apps/gate-proxy/src/engine/inspector.ts`](apps/gate-proxy/src/engine/inspector.ts))** :
     - **Démasquage des Workers Go/Python déguisés** : détection des requêtes déclarant un `User-Agent` de navigateur moderne (Chrome/Edge/Firefox) mais dépourvues des en-têtes structurels obligatoires (`Sec-Ch-Ua`, `Sec-Fetch-Mode`, `Sec-Fetch-Site`, `Accept-Language`).
     - **Mémoire de suspicion longue (24h)** : accumulation des rafales lentes d'erreurs `404` / `401` / `403` sous le seuil volumétrique (`60 req/10s`) pour neutraliser les scans *Low-and-Slow* distribués.
  5. **Context-Binding Cryptographique des Sessions Pure BFF (Anti-Token Replay) ([`apps/gate-proxy/src/bff/session.ts`](apps/gate-proxy/src/bff/session.ts))** :
     - Scellement de l'empreinte client (hash `User-Agent` + préfixe sous-réseau IP `/24` ou `/64`) directement dans le jeton chiffré `AES-256-GCM` du cookie `HttpOnly` `aegis_session`. Tout rejeu d'un cookie volé depuis un Worker ARTEX ou une autre IP révoque instantanément la session et lève une alerte critique `SESSION_HIJACK_REPLAY_DETECTED`.
  6. **Auto-Audit « Purple Team » Souverain ([`apps/backend/internal/scanner/`](apps/backend/internal/scanner/engine.go))** :
     - Enrichissement du scanner continu (Verrou n°5) pour vérifier proactivement l'absence de fichiers sensibles (`.env`, `.git`, backups), de schémas Swagger/GraphQL ouverts ou de sous-domaines non protégés, offrant aux entreprises la visibilité défensive que promettait initialement ARTEX sans jamais exposer d'outil offensif détournable.

---

## 🔒 Phase P1.6 (v1.3.1) — Durcissement Sécurité P0 & Arène CTF (✅ Livré)

- **Statut :** ✅ Livré (`v1.3.1`)
- **Priorité :** Critique (**P0** — Pré-requis CTF & exposition publique)
- **Correctifs livrés :**
  1. **Verrouillage du Control Plane & Kill-Switch** : authentification obligatoire par jeton interne en temps constant (`X-Aegis-Internal-Token`) ou session admin BFF (hors mode CTF) sur `/_aegis/mode` et `/_aegis/simulate`, suppression du CORS `*` sur les routes de contrôle, et ajout du middleware `requireInternalAuth` sur les routes mutatrices du Backend Go ([`apps/backend/internal/http/router.go`](apps/backend/internal/http/router.go)).
  2. **Résolution IP Anti-Spoofing (`X-Forwarded-For`) & Suppression des IP codées en dur** : durcissement de [`getClientIp`](apps/gate-proxy/src/server.ts) (lecture droite $\rightarrow$ gauche uniquement depuis des reverse-proxies de confiance) et suppression de l'IP administrateur codée en dur dans [`ip-reputation.ts`](apps/gate-proxy/src/quarantine/ip-reputation.ts) et [`docker-compose.ctf.yml`](docker-compose.ctf.yml).
  3. **Durcissement BFF OIDC & Secrets Cryptographiques** : désactivation par défaut de l'auto-login admin (réservé à `AEGIS_ALLOW_DEMO_AUTH=true` hors mode CTF), validation stricte du `state` PKCE et échange réel auprès du `tokenEndpoint`, et génération d'une clé aléatoire éphémère 256-bit si `BFF_SESSION_SECRET` est absent ou par défaut.
  4. **Élargissement de la Surface WAF L7 & Anti-Auto-DoS** : inspection des en-têtes HTTP (`Referer`, `User-Agent`, `X-Forwarded-Host`, `Cookie` hors session), blocage du bypass `/api/*.css`, durcissement des règles XSS/RCE/SSRF, bornage des buffers M2M/contrôle, et plafond de connexions Tarpit simultanées (`MAX_CONCURRENT_TARPIT = 50`) adapté aux VM `e2-micro`.
  5. **Durcissement des défauts CTF** : activation par défaut de `AEGIS_STEALTH_BLOCK=true` et `AEGIS_ALLOW_DEMO_AUTH=false` dans [`docker-compose.ctf.yml`](docker-compose.ctf.yml).

---

## 🛡️ Phase P2 — Durcissement Infrastructure Cœur (Recentrage sur 3 Piliers)

Pour maximiser la maturité production sans disperser l'effort d'ingénierie, la feuille de route cœur d'Aegis se concentre sur **3 piliers différenciants** (*Bouclier Edge & Anti-Artex*, *Frontière Egress & IA/MCP*, *Preuve Énergétique RAPL & Conformité Post-Quantique*). Les domaines IT périphériques (EDR postes de travail, DNS bureautique/RAT, ZTNA VLAN, CTI P2P) sont adressés via des **intégrations et partenariats souverains** (voir tableau ci-dessous).

### 🔒 Verrou n°6 : Moteur WAF Production (Coraza / OWASP CRS v4), Consolidation Go & Confinement Noyau
- **Statut :** ⏳ Prochaine étape (P1/P2)
- **Priorité :** Haute (**P2** — Pilier n°1 : Bouclier Edge)
- **Plan d'action technique :**
  1. **Coraza WAF (OWASP CRS v4) + Couche Anti-Artex** : embarquer **Coraza** (moteur WAF open-source natif en Go compatible OWASP CRS v4) comme socle éprouvé de scoring d'anomalies L7, tout en conservant au-dessus la couche propriétaire **Aegis Anti-Artex** (Stealth Block, Canary Honeypot, BOLA, OAST, Context-Binding de session).
  2. **Consolidation Native Go** : porter `gate-proxy` et `egress-gateway` (`miekg/dns` + résolution DNS upstream réelle + confinement réseau `nftables`/`iptables`) en Go pour diviser la RAM par 3, garantir une latence sub-milliseconde et supprimer tout risque de blocage de l'event-loop Node.js.
  3. **Confinement Noyau (`eBPF / XDP` & `sched_process_exec` `SIGKILL`)** : faire évoluer [`apps/telemetry-agent`](apps/telemetry-agent/src/main.rs) du polling `/proc` (5s) vers un hook temps réel eBPF `sched_process_exec` (`SIGKILL < 10 ms` sur tout shell enfant illégitime d'un worker web) et `XDP_DROP` contre les paquets IPv4 TCP SYN malformés.

### 🔒 Verrou n°7 : Canal `mTLS` Hybride Post-Quantique (`X25519MLKEM768`) & Preuves Conformité NIS 2 / EFRAG
- **Statut :** ⏳ En conception
- **Priorité :** Haute (**P2** — Pilier n°3 : Souveraineté Green & Conformité)
- **Plan d'action technique :**
  1. **Transport `mTLS` Hybride Post-Quantique (`X25519MLKEM768` — NIST FIPS 203)** : exploiter le support natif Go 1.25 `crypto/tls` + Rust `rustls-post-quantum` entre les sondes `telemetry-agent` / nœuds Edge et le Control Plane pour immuniser la télémétrie d'infrastructure contre la collecte rétroactive (*Harvest Now, Decrypt Later — HNDL*) à coût d'ingénierie quasi nul.
  2. **Rapports Auditables NIS 2 & EFRAG/RGESN** : génération automatisée de rapports PDF/JSON signés combinant les Joules/Watts physiques Intel/AMD RAPL, la posture CVE CERT-FR et les preuves d'interception WAF.

---

## 🤖 Phase P3 — Sécurité IA, Passerelle MCP « Two-Door » & Registre Post-Quantique AI Act

### 🔒 Verrou n°8 : Architecture « Two-Door » & Injection Sortante « Zero-Secret Placeholder » (DLP IA)
- **Statut :** ⏳ En conception
- **Priorité :** Évolution Stratégique (**P3** — Pilier n°2 : Frontière Egress & IA/MCP)
- **Contexte :** L'adoption rapide des assistants IA et agents connectés aux bases documentaires expose les organisations aux fuites involontaires de secrets, au vol de clés d'API par *Prompt Injection* et aux manipulations d'instructions.
- **Plan d'action technique :**
  1. **Porte 1 — Garde-fous d'entrée (`gate-proxy`)** : détection en bordure de réseau des *Prompt Injections*, tentatives de *Jailbreak* et dépassements de quotas de jetons ciblant les endpoints d'IA applicatifs avant passage aux modèles.
  2. **Porte 2 — Pattern « Zero-Secret Placeholder » & DLP Sortant (`egress-gateway`)** : l'environnement d'exécution de l'agent IA ne détient **aucune clé d'API réelle** en mémoire ou dans ses variables d'environnement (uniquement un jeton fantôme `AEGIS_PLACEHOLDER_KEY`). `egress-gateway` inspecte et anonymise les données personnelles (PII / RGPD), le code propriétaire et les secrets à la volée, puis injecte la véritable clé d'API externe uniquement à la frontière réseau sortante si la requête est conforme.

### 🔒 Verrou n°9 : Passerelle MCP Zero-Trust (Filtrage d'Outils par Identité) & Registre Post-Quantique AI Act (`ML-DSA-65`)
- **Statut :** ⏳ En conception
- **Priorité :** Évolution Stratégique (**P3** — Piliers n°2 & n°3)
- **Contexte :** Les orchestrateurs multi-agents utilisent le protocole **MCP (*Model Context Protocol*)** pour invoquer des outils sensibles (accès SQL, exécution de scripts, appels API métiers), créant un risque majeur d'élévation de privilèges par injection indirecte.
- **Plan d'action technique :**
  1. **Filtrage granulaire MCP par identité (`tools/list` & `tools/call`)** : inspection native du flux JSON-RPC MCP dans `gate-proxy` pour filtrer dynamiquement la liste des outils exposés et valider chaque appel `tools/call` selon l'identité OIDC / SPIFFE de l'agent ou de l'utilisateur, combinée au *sandboxing* noyau éphémère (`seccomp-bpf`, hooks `eBPF`, `namespaces` Linux).
  2. **Registre de traçabilité immuable à signature Post-Quantique (EU AI Act)** : journalisation cryptographique *append-only* dans TimescaleDB de chaque action d'agent IA, scellée par une **double signature hybride classique + post-quantique (`Ed25519 + ML-DSA-65` — NIST FIPS 204)** garantissant une non-répudiation à long terme conforme à l'**AI Act européen**.

### 🔒 Verrou n°10 : Flux CTI Open-Source Temps Réel & Micro-SLM Frugaux `< 1B` CPU-Only
- **Statut :** 🚧 Partiel (blocklist C2/OAST statique + option `qwen2.5:0.5b` / `Nimble` Ollama actifs en v1)
- **Priorité :** Évolution Stratégique (**P3**)
- **Plan d'évolution :**
  1. **Enrichissement continu automatisé** : synchronisation des flux open source consolidés (**Abuse.ch URLhaus**, **ThreatFox**, **CERT-FR**, **CISA KEV**) en recherche `O(1)` (`< 0,05 ms`, empreinte `< 5 Mo RAM`).
  2. **Micro-SLM spécialisés `< 1B` sur CPU** : modèles quantifiés de moins d'un milliard de paramètres exécutables sur CPU standard (*Air-Gapped*, sans ferme de GPU).

---

## 🤝 Écosystème, Partenariats Souverains & Périmètre Reporté

Plutôt que de disperser l'effort produit sur des métiers connexes très concurrentiels, Aegis privilégie des **connecteurs natifs et partenariats souverains européens** pour les périmètres suivants (reportés hors roadmap serveur cœur) :

| Périmètre (Reporté hors cœur) | Stratégie Recommandée | Écosystème & Partenaires Souverains / Open Source |
| :--- | :--- | :--- |
| **CTI Collaborative P2P** | Connecteur / Bouncer natif | **CrowdSec** (réputation IP communautaire), **MISP**, **Abuse.ch**, **CERT-FR** |
| **EDR & Posture Postes (Win/macOS)** | Ingestion Webhook / API Posture | **Wazuh** (Open Source), **HarfangLab** / **Tehtris** (EDR souverains FR), **FleetDM / osquery**, **GLPI** |
| **ZTNA & Micro-Segmentation VLAN** | Intégration Identité & Réseau | **NetBird**, **Headscale / WireGuard**, **OPNsense / pfSense** |
| **DNS Bureautique & Filtrage RAT** | Brique dédiée / Stack Partenaire | **Bind9 RPZ**, **AdGuard Home**, **Technitium DNS**, **NextDNS** (UE) |
