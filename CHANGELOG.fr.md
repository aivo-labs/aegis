# 📋 Journal des Modifications (Changelog) — Aegis Sovereign Gate

<p align="center">
  <a href="CHANGELOG.md">English</a> | <strong>Français</strong> •
  <a href="README.fr.md">README</a> •
  <a href="ROADMAP.fr.md">Roadmap</a> •
  <a href="CONTRIBUTING.fr.md">Contribuer (Gitflow)</a>
</p>

Toutes les évolutions notables d'**Aegis Sovereign Gate** sont documentées dans ce fichier.

Le format suit le standard [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet applique strictement le [Versionnage Sémantique (SemVer 2.0.0)](https://semver.org/lang/fr/) couplé au cycle de publication [Gitflow](https://nvie.com/posts/a-successful-git-branching-model/) :
- **`MAJEUR` (`vX.0.0`)** : Changements d'architecture ou d'API non rétrocompatibles.
- **`MINEUR` (`v1.X.0`)** : Nouveaux verrous de sécurité, nouvelles sondes d'audit passif, capacités de télémétrie ou fonctionnalités rétrocompatibles fusionnées via `release/v1.X.0` vers `main`.
- **`CORRECTIF` (`v1.0.X`)** : Correctifs de sécurité critiques ou corrections de bugs fusionnés via `hotfix/v1.0.X` ou `release/v1.0.X` vers `main`.

---

## [Unreleased / En cours sur `develop`]

---

## [1.2.2] — 2026-11-21 (Tag `v1.2.2` sur `main`)

### Corrigé (Fixed)
- **Failover DNS & Résolution `/etc/hosts` pour l'Ingestion TimescaleDB** :
  - Résolution des erreurs SERVFAIL intermittentes du résolveur interne de Docker (`127.0.0.11:53`) dans le backend Go (`apps/backend/internal/database/pgwire.go`) via inspection directe de `/etc/hosts`, KeepAlive TCP de 30s et bascule d'exécution vers la dernière IP valide connue.
  - Ajout des liaisons `links: - timescaledb:timescaledb` dans `docker-compose.yml`, `docker-compose.dokploy.yml` et `deploy/docker-compose/docker-compose.yml`.
- **Requêtes de Secours pour les Métriques & Verrouillage Conditionnel du Cache** :
  - Élimination des métriques vides dans le cockpit en intégrant des requêtes globales de repli dans `DashboardService` (`dashboard_service.go`) lorsque les requêtes par tenant retournent un ensemble vide, empêchant la mise en cache d'un état à 0.
- **Filtrage des Spawns de Processus dans l'Agent de Télémétrie & Bornage CPU** :
  - Implémentation du filtre `is_benign_worker_child_cmd` dans `apps/telemetry-agent` pour éliminer les faux positifs d'alerte P1 lors de l'exécution normale de scripts (`node`, `npm`, `dotenv`), tout en maintenant la neutralisation temps réel des shells hostiles (`nc`, `bash -i`).
  - Encadrement strict de l'utilisation CPU dans `[0,0, 100,0]%` garantissant des calculs de Joules fiables.
- **Résilience de l'Initialisation du Micro-SLM Ollama** :
  - Configuration de l'alias vers `qwen2.5:0.5b` pour `nimble`, éliminant les erreurs HTTP 412 lors du pull des manifestes de modèles entre différentes versions d'Ollama.
- **Contraste Thème Clair & Finitions UI Précision Souveraine** :
  - Correction des contrastes dégradés (cartes gris sur gris, flux CVE) dans le Cockpit et harmonisation du design vectoriel SVG sur l'ensemble des pages.

---

### Ajouté (Added)
- **Verrou n°1 (P0 Critique) — Confinement Réseau Egress Strict & Allowlist DNS-to-IP Anti-Reverse Shell** :
  - Ajout du moteur [`apps/egress-gateway/src/engine/ip-allowlist.ts`](apps/egress-gateway/src/engine/ip-allowlist.ts) (`DnsToIpAllowlist` avec TTL de 60s) et de l'endpoint `POST /api/v1/egress/verify-connection` dans [`tcp-server.ts`](apps/egress-gateway/src/http/tcp-server.ts) bloquant toute tentative de callback TCP sortant sur adresse IP brute (`RAW_IP_REVERSE_SHELL_BLOCKED`) ou IP non préalablement résolue via `:5053` (`UNRESOLVED_DIRECT_IP_EGRESS_BLOCKED`).
  - Segmentation réseau Docker dans [`docker-compose.yml`](docker-compose.yml) et [`docker-compose.dokploy.yml`](docker-compose.dokploy.yml) (`aegis-internal` en mode `internal: true` sans route Internet par défaut + `aegis-edge`) et politique [`deploy/security/egress-lockdown.nft`](deploy/security/egress-lockdown.nft).
- **Verrou n°2 (P1 Haute) — Canonisation Multi-Encodage Anti-Évasion (Base64 / HTML / Hex / Chemins)** :
  - Extension de [`apps/gate-proxy/src/engine/canonicalizer.ts`](apps/gate-proxy/src/engine/canonicalizer.ts) et [`apps/web/src/services/sandboxEngine.ts`](apps/web/src/services/sandboxEngine.ts) avec le décodage des entités HTML (nommées, décimales, hexadécimales), des séquences d'échappement Hex/Unicode (`\x..`, `\u....`, `%u....`), la normalisation des chemins (`/./`, `//`, `\`) et l'extraction + décodage automatique des charges Base64 suspectes (`>= 16` caractères).
- **Verrou n°3 (P1 Haute) — Rate-Limiting Volumétrique (`HTTP 429`) & Quarantaine IP Automatique (`Auto-Jail 15 min`)** :
  - Ajout d'un limiteur de débit à fenêtre glissante (`60 req / 10 s` par IP, en-tête `Retry-After: 10`) et d'une mise en quarantaine automatique de **15 minutes** (`AUTO_JAIL_TEMPORARY_QUARANTINE`) dès `3` offenses critiques (`risk_score >= 90`) en moins de `5` minutes dans [`apps/gate-proxy/src/quarantine/ip-reputation.ts`](apps/gate-proxy/src/quarantine/ip-reputation.ts), synchronisée avec le Control Plane Go (`ttlMinutes` / `expires_at`).
- **Verrou n°4 (P1 Haute) — Durcissement Protocole HTTP (`HTTP 431`), Multipart RFC & Sonde Rust Anti-Spawn Shell** :
  - Plafonnement des en-têtes HTTP (`> 8 Ko` total, `> 4 Ko` par en-tête ou `> 64` en-têtes → `HTTP 431`), validation RFC `multipart/form-data` (profondeur `<= 3`, rejet d'extensions exécutables `.php`, `.phtml`, `.phar`, `.sh`) et blocage des chaînes `Content-Encoding` suspectes dans [`apps/gate-proxy/src/engine/inspector.ts`](apps/gate-proxy/src/engine/inspector.ts).
  - Ajout du collecteur Rust [`apps/telemetry-agent/src/collector/process_spawn.rs`](apps/telemetry-agent/src/collector/process_spawn.rs) inspectant `/host/proc` et `/proc` pour détecter tout shell enfant (`sh`, `bash`, `nc`, `curl`, `python`, `socat`) engendré par un worker web (`php-fpm`, `node`, `nginx`, `caddy`).
- **Verrou n°5 (P1 Haute) — Audits de Posture Continus Planifiés, Détection de Dérive & Assistant de Remédiation Guidée** :
  - Ajout des endpoints `GET/POST /api/v1/audit/schedule`, de l'évaluation de dérive (`EvaluatePostureDrift`) et du générateur d'extraits de durcissement (`GenerateGuidedRemediationSnippets` pour Traefik, Nginx, Caddy et Apache/`php.ini`) dans [`audit_service.go`](apps/backend/internal/service/audit_service.go) et [`AuditPanel.vue`](apps/web/src/components/soc/actions/AuditPanel.vue).

### Modifié (Changed)
- **Refonte UI/UX « Aegis Sovereign Precision » (Élimination de l'esthétique « Vibe Codé »)** :
  - Création du système d'icônes vectorielles monochromes [`AegisIcon.vue`](apps/web/src/components/soc/AegisIcon.vue) (`stroke-width: 1.75px`) remplaçant l'ensemble des emojis Unicode dans le Cockpit SOC et la Landing Page.
  - Application de la discipline chromatique `90/5/5` (surfaces sobres `slate-950`/`slate-900`, bordures `1px` `slate-800`, accent unique `emerald-400`, couleurs sémantiques réservées aux alertes réelles), géométrie technique `rounded-lg` (`8px`), typographie duale (`font-sans` pour l'interface / `font-mono tabular-nums` pour les métriques, IP, CVE et Watts) et suppression des bandeaux promotionnels dans le Cockpit.

---

## [1.1.0] — 2026-11-15 (Tag `v1.1.0` sur `main`)

### Ajouté (Added)
- **Sonde Passive de Maturité Post-Quantique (`X25519MLKEM768` — NIST FIPS 203)** :
  - Ajout de [`apps/backend/internal/scanner/pqc.go`](apps/backend/internal/scanner/pqc.go) et [`pqc_test.go`](apps/backend/internal/scanner/pqc_test.go) exécutant une poignée de main TLS 1.3 passive (`InspectDomainPQC`) qui propose le groupe hybride `X25519MLKEM768` (`0x11ec`) ainsi que le groupe pré-standard `X25519Kyber768Draft00` (`0x6399`).
  - Ajout de la structure `PQCAnalysis` (`post_quantum`) au rapport [`PassiveAuditResult`](apps/backend/internal/domain/audit.go) avec évaluation du risque *Harvest Now, Decrypt Later (HNDL)* et extraits de configuration prêts au copier-coller pour **Traefik**, **Nginx**, **Caddy** et **Go TLS**.
  - Ajout automatique du badge technologique `Cryptographie TLS Post-Quantique (NIST FIPS 203)` lorsque `0x11ec` est négocié, ou génération d'une alerte `PQC-HNDL-EXPOSURE` avec procédure de remédiation lorsque le serveur replie sur une courbe elliptique classique (`X25519` / `P-256`).
- **Documentation Officielle du Scanner Passif, Mandat Légal & Sonde Post-Quantique (FR/EN)** :
  - Création des pages bilingues [`apps/docs/src/content/docs/fr/security/passive-scanner.md`](apps/docs/src/content/docs/fr/security/passive-scanner.md) et [`apps/docs/src/content/docs/security/passive-scanner.md`](apps/docs/src/content/docs/security/passive-scanner.md) détaillant l'architecture en 2 niveaux du scanner (Niveau 1 : EcoIndex, DNS hiérarchique RFC 7489/7208, Headers, CVE, PQC ; Niveau 2 : vérification de propriété DNS TXT / `/.well-known` et mandat scellé SHA-256 conforme à l'Article 323-1 du Code pénal).
- **Journal des Versions (`CHANGELOG`) & Procédure de Tagging Gitflow** :
  - Création des fichiers [`CHANGELOG.fr.md`](CHANGELOG.fr.md) et [`CHANGELOG.md`](CHANGELOG.md) et ajout de la procédure complète de création de versions et de tags Git annotés (`release/vX.Y.Z` & `hotfix/vX.Y.Z` $\rightarrow$ `git tag -a vX.Y.Z`) dans [`CONTRIBUTING.fr.md`](CONTRIBUTING.fr.md) et [`CONTRIBUTING.md`](CONTRIBUTING.md).

### Modifié (Changed)
- **Mise à niveau de la chaîne de compilation Go vers `1.25`** :
  - Mise à jour de `apps/backend/go.mod`, `apps/backend/Dockerfile` et `.github/workflows/ci.yml` de Go `1.22` vers **Go `1.25`** afin d'exploiter nativement `tls.X25519MLKEM768` et l'inspection `tls.ConnectionState.CurveID` dans `crypto/tls`.
- **Alignement de la Roadmap Technique (Verrous n°5, n°8, n°10 et n°11)** :
  - Synchronisation de [`ROADMAP.fr.md`](ROADMAP.fr.md), [`ROADMAP.md`](ROADMAP.md), [`README.fr.md`](README.fr.md) et [`README.md`](README.md) intégrant la sonde passive **NIST FIPS 203 `X25519MLKEM768`** livrée (Verrou n°5), le canal **`mTLS` hybride post-quantique** de l'agent endpoint Rust (Verrou n°8), le pattern **« Two-Door & Zero-Secret Placeholder »** pour les agents IA (Verrou n°10) et la **Passerelle MCP Zero-Trust (`tools/list`, `tools/call`) + registre immuable signé `Ed25519 + ML-DSA` (FIPS 204)** conforme à l'EU AI Act (Verrou n°11).

---

## [1.0.0] — 2026-11-14 (Tag `v1.0.0` sur `main`)

### Ajouté (Added)
- **Première Publication Open-Source d'Aegis Sovereign Gate (AGPLv3)** :
  - **Passerelle Ingress PEP (`apps/gate-proxy`)** : Point d'application de politique Zero-Trust en coupure directe ou en mode `ForwardAuth` Traefik/Nginx (`/_aegis/verify`), intégrant la décanonisation récursive URL/Hex/Unicode, le bouclier anti-overflow RFC 413 (plafond 32 Ko), le moteur mathématique d'entropie de Shannon ($H$), le filtrage OWASP Top 10 / scanners offensifs et le Virtual Patching à chaud (`CVE-2024-4577` PHP2Shell, Log4Shell, traversée de chemin) en `< 1,5 ms`.
  - **Authentification Pure BFF OIDC** : Pattern Token Handler avec OAuth2/OIDC PKCE (Keycloak, Okta, Authelia, Authentik) et cookies `HttpOnly; Secure; SameSite=Strict` scellés en **AES-256-GCM** (`zéro jeton exposé dans le navigateur`).
  - **Passerelle Egress & IA Locale Souveraine (`apps/egress-gateway` + `infra/coredns`)** : Double filtrage sortant combinant le sinkhole DNS CoreDNS RPZ (~15 Mo RAM) et l'analyse comportementale / DGA asynchrone par SLM local quantifié **Qwen 3.5 9B (`Q4_K_M`)** via Ollama (`zéro exfiltration vers le Cloud`).
  - **Control Plane Go & Scanner Passif à 2 Niveaux (`apps/backend`)** :
    - Niveau 1 (100 % passif) : Moteur officiel de quantiles EcoIndex RGESN, inspection DNS avec traversée hiérarchique RFC 7489 (DMARC) et wildcard RFC 7208 (SPF), analyse des en-têtes HTTP de sécurité, fingerprinting technologique passif et matrice de couverture CVE / CISA KEV.
    - Niveau 2 (sous mandat légal) : Sondes d'exposition approfondies (`/.env`, `/.git/config`, `/phpinfo.php`, `/wp-login.php`, `/xmlrpc.php`) débloquées uniquement après vérification de propriété DNS `TXT` ou `/.well-known/aegis-verify.txt` et scellement `SHA-256` du contrat d'audit.
  - **Télémétrie Matérielle RAPL & GreenOps (`agents/energy-agent` & TimescaleDB)** : Démon natif en Rust lisant directement les compteurs silicium Intel/AMD **RAPL** (`/sys/class/powercap/intel-rapl:0`), `/proc/stat` et les métriques Kubernetes **Kepler eBPF**, couplé à l'export officiel du certificat **CSRD / EFRAG VSME** en PDF.
  - **Cockpit Unifié SOC & GreenOps (`apps/web`) & Documentation Starlight (`apps/docs`)** : Cockpit opérationnel bilingue (FR/EN) Astro 5 + îlots Vue 3, rejeu interactif en bac à sable et guides complets de déploiement (Dokploy/Traefik, VPS Docker Compose, Bare-Metal RAPL, Kubernetes Helm, Agent autonome).
  - **Gouvernance Open-Source** : Ajout de [`VISION.fr.md`](VISION.fr.md) / [`VISION.md`](VISION.md), [`ROADMAP.fr.md`](ROADMAP.fr.md) / [`ROADMAP.md`](ROADMAP.md), [`CONTRIBUTING.fr.md`](CONTRIBUTING.fr.md) / [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), [`SECURITY.md`](SECURITY.md), [`LICENSE`](LICENSE) (GNU AGPLv3) et des Architecture Decision Records ([`docs/adr/ADR-0001`](docs/adr/ADR-0001-pure-bff-token-handler.md) à [`ADR-0007`](docs/adr/ADR-0007-keycloak-sso-iam-theming.md)).
