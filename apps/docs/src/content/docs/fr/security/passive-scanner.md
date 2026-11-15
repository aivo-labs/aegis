---
title: Scanner Passif, Mandat Légal & Sonde Post-Quantique (ML-KEM)
description: Architecture du scanner en 2 niveaux (Audit 100% passif RGESN/DNS/Headers/CVE/PQC vs Sondes Niveau 2 sous mandat cryptographique Article 323-1 CP) et détection NIST FIPS 203 X25519MLKEM768.
---

Le moteur de diagnostic d'**Aegis (`apps/backend/internal/scanner`)** a été conçu dès l'origine selon le principe d'**Éthique Juridique par Conception (*Legal-by-Design*)**. Contrairement aux scanners offensifs traditionnels qui lancent des requêtes intrusives sans autorisation, Aegis sépare strictement son analyse en **deux niveaux d'exécution** :

1. **Niveau 1 — Diagnostic 100 % Passif (Sans Mandat Préalable)** : Analyse uniquement les métadonnées publiques restituées lors d'une navigation standard (HTML public, en-têtes HTTP, enregistrements DNS publics et poignée de main TLS 1.3 Post-Quantique).
2. **Niveau 2 — Audit Approfondi sous Mandat Légal Cryptographique (Conformité Article 323-1 du Code pénal)** : Débloqué **exclusivement** après preuve mathématique de propriété du domaine (enregistrement DNS `TXT` ou fichier `/.well-known/aegis-verify.txt`) et signature d'un mandat scellé par empreinte `SHA-256`.

---

## 🏛️ Schéma d'Architecture du Scanner à 2 Niveaux

```
                      [ Demande d'Audit : Domaine Cible ]
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│            NIVEAU 1 : SONDE 100 % PASSIVE (SANS MANDAT PRÉALABLE)            │
│                      POST /api/v1/audit/passive-scan                         │
│                                                                              │
│  ┌──────────────────────────────┐    ┌────────────────────────────────────┐  │
│  │ 1. Crawl Léger & EcoIndex    │    │ 2. Analyse DNS Hiérarchique        │  │
│  │ • Jusqu'à 4 pages publiques  │    │ • Résolution A / AAAA              │  │
│  │ • Quantiles DOM / Req / Ko   │    │ • SPF direct & Wildcard (RFC 7208) │  │
│  │ • Score 0-100 (A-G), gCO2e,  │    │ • DMARC direct & Parent (RFC 7489) │  │
│  │   et empreinte Eau (cL)      │    └────────────────────────────────────┘  │
│  └──────────────────────────────┘                                            │
│  ┌──────────────────────────────┐    ┌────────────────────────────────────┐  │
│  │ 3. En-têtes HTTP & CVE       │    │ 4. Sonde Post-Quantique (PQC)      │  │
│  │ • HSTS, CSP, XFO, XCTO...    │    │ • Handshake TLS 1.3 (Go 1.25)      │  │
│  │ • Fingerprinting passif      │    │ • Groupe hybride X25519MLKEM768    │  │
│  │ • Matrice Virtual Patching   │    │ • Diagnostic HNDL & Snippets       │  │
│  └──────────────────────────────┘    └────────────────────────────────────┘  │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
               Propriétaire souhaitant │ débloquer les sondes d'exposition
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│         GARDE-FOU JURIDIQUE : PREUVE DE PROPRIÉTÉ & MANDAT SHA-256           │
│     POST /api/v1/audit/request-verification -> /api/v1/audit/verify-ownership│
│                                                                              │
│  1. Jeton unique : aegis-site-verification=aegis_verify_<24_hex_chars>       │
│  2. Vérification DNS TXT (@ ou _aegis-challenge + fallback 1.1.1.1 / 8.8.8.8)│
│     ou fichier HTTPS https://<domaine>/.well-known/aegis-verify.txt          │
│  3. Scellement SHA-256 : Hash(domaine | email | IP | timestamp | contrat)    │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼ (Si et seulement si vérifié)
┌──────────────────────────────────────────────────────────────────────────────┐
│            NIVEAU 2 : SONDES D'EXPOSITION APPROFONDIES (AUTORISÉES)          │
│                                                                              │
│  • Test d'exposition de secrets : /.env, /.git/config, /phpinfo.php          │
│  • Test de surfaces d'attaque CMS : /wp-login.php, /xmlrpc.php               │
│  • Verdict : PROTÉGÉ (Filtré) / BLOQUÉ À L'EDGE (HTTP 403) / EXPOSÉ (200)    │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔍 Détail des 4 Modules de la Sonde Passive (Niveau 1)

Lors d'un appel à `POST /api/v1/audit/passive-scan`, l'orchestrateur Go (`RunRealPassiveAudit` dans `apps/backend/internal/scanner/engine.go`) exécute en parallèle quatre modules non-intrusifs :

### 1. Audit d'Éco-Conception RGESN & Calcul EcoIndex (`eco.go`)
Le scanner inspecte la page d'accueil et jusqu'à 3 pages internes publiques (`<a href>` du même domaine) avec un timeout strict de `3,5 secondes` :
- **Métriques extraites** : Poids de transfert en Ko (`weight_kb`), complexité de l'arbre HTML (`dom_elements` via comptage des balises), et nombre de ressources externes déclenchées (`http_requests` : scripts, feuilles de style, images, iframes).
- **Formule officielle EcoIndex (Collectif GreenIT)** : Interpolation sur les tables de 20 quantiles officiels (`quantilesDOM`, `quantilesReq`, `quantilesSize`) :
  $$\text{EcoScore} = 100 - \frac{5 \times (3 \cdot Q_{\text{DOM}} + 2 \cdot Q_{\text{Req}} + Q_{\text{Size}})}{6}$$
- **Empreinte physique par visite** :
  - **Émissions carbone ($\text{gCO}_2\text{e}$)** : $2 + \frac{2 \times (50 - \text{EcoScore})}{100}$
  - **Consommation d'eau ($\text{cL}$)** : $3 + \frac{3 \times (50 - \text{EcoScore})}{100}$

### 2. Inspection DNS Passive & Traversée Hiérarchique (`dns.go`)
La fonction `InspectDomainDNS` résout les adresses IPv4/IPv6 (`A` / `AAAA`) et vérifie la protection anti-usurpation d'email avec prise en charge complète des sous-domaines :
- **SPF (RFC 7208)** : Recherche d'un enregistrement `v=spf1` sur le domaine cible, puis repli sur les enregistrements wildcard (`*.parent`) des domaines parents via `getParentDomains`.
- **DMARC (RFC 7489 Section 6.6.3)** : Recherche sur `_dmarc.<domaine>`. Si un sous-domaine ne possède pas d'enregistrement propre, le scanner remonte automatiquement vers le domaine organisationnel parent (`_dmarc.<parent>`) et valide l'héritage tant que la politique de sous-domaine n'est pas désactivée (`sp=none`).

### 3. En-têtes HTTP, Empreinte Technologique & Matrice CVE (`headers.go` & `fingerprint.go`)
- **En-têtes de sécurité (`AnalyzeSecurityHeaders`)** : Vérifie la présence et la conformité de `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` et `Permissions-Policy`.
- **Fingerprinting passif & Couverture CVE (`DetectTechAndCVEs`)** : Identifie les technologies exposées dans les en-têtes (`Server`, `X-Powered-By`) et le code HTML, puis associe chaque CVE pertinente à :
  - un **statut de couverture à chaud** (`COVERED_VIRTUAL_PATCH` via Aegis Ingress PEP ou `HOST_PATCH_REQUIRED`),
  - une **procédure de correction racine (`root_fix_procedure`)** étape par étape,
  - et une **commande de vérification (`verification_probe`)**.

---

## 🔐 Focus : Sonde Passive Post-Quantum Readiness (`pqc.go`)

### Pourquoi auditer la résistance post-quantique dès aujourd'hui ?
Même si les ordinateurs quantiques cryptanalytiques tolérants aux pannes (capables d'exécuter l'algorithme de Shor pour casser RSA et les courbes elliptiques classiques `X25519` / `P-256`) sont attendus à l'horizon 2030+, la menace **HNDL (*Harvest Now, Decrypt Later* — Collecter maintenant, déchiffrer plus tard)** est immédiate : des acteurs malveillants enregistrent dès aujourd'hui les flux TLS chiffrés transitant sur Internet pour les déchiffrer rétroactivement dans quelques années.

Pour neutraliser cette menace, le NIST a standardisé en août 2024 **FIPS 203 (`ML-KEM`, issu de CRYSTALS-Kyber)**. En TLS 1.3, il est déployé sous la forme du groupe d'échange de clés hybride **`X25519MLKEM768` (`0x11ec`)**, supporté nativement par **Go 1.25+**, **Cloudflare**, **OpenSSL 3.5+**, **BoringSSL** et les navigateurs modernes.

### Fonctionnement du Handshake Passif `InspectDomainPQC`

```
 Scanner Passif Aegis (Go 1.25)                         Serveur Cible (:443)
 ──────────────────────────────                         ────────────────────
               │                                                  │
               │ 1. TLS 1.3 ClientHello (Timeout 3s)              │
               │    Supported Groups (CurvePreferences) :         │
               │      [1] X25519MLKEM768 (0x11ec - NIST FIPS 203) │
               │      [2] X25519Kyber768Draft00 (0x6399 - Draft)  │
               │      [3] X25519 (0x001d - Classique)             │
               │      [4] P-256 (0x0017) / P-384 (0x0018)         │
               ├─────────────────────────────────────────────────►│
               │                                                  │
               │ 2. TLS 1.3 ServerHello                           │
               │    KeyShare sélectionné par le serveur           │
               │◄─────────────────────────────────────────────────┤
               │                                                  │
               │ 3. Inspection de conn.ConnectionState().CurveID  │
               │    • Si 0x11ec -> PostQuantumReady = true        │
               │    • Sinon     -> Alerte PQC-HNDL-EXPOSURE       │
               │                   + Snippets Traefik/Nginx/Caddy │
               │                                                  │
               │ 4. Fermeture propre immédiate du socket TLS      │
               ├─────────────────────────────────────────────────►│
```

1. **Négociation préférentielle** : `InspectDomainPQC` ouvre une connexion TLS sur le port `443` en plaçant `tls.X25519MLKEM768` (`0x11ec`) en tête de `CurvePreferences`.
2. **Inspection de l'état cryptographique (`EvaluateTLSConnectionState`)** :
   - **Cas 1 — Serveur compatible FIPS 203 (`0x11ec`)** :
     - `post_quantum_ready: true`
     - `standard: "NIST FIPS 203 (X25519MLKEM768)"`
     - `hndl_risk: "LOW — Protégé contre les attaques Harvest Now, Decrypt Later (HNDL) via encapsulation hybride X25519 + ML-KEM-768."`
     - Ajout automatique du badge `Cryptographie TLS Post-Quantique (NIST FIPS 203)` dans la `tech_stack`.
   - **Cas 2 — Serveur utilisant le brouillon pré-standard (`0x6399`)** :
     - `post_quantum_ready: true`
     - `standard: "IETF Draft (X25519Kyber768Draft00 — Migration FIPS 203 recommandée)"`
     - `hndl_risk: "MODERATE"` avec extraits de migration vers `X25519MLKEM768`.
   - **Cas 3 — Serveur limité aux courbes elliptiques classiques (`X25519`, `P-256`, `P-384`)** :
     - `post_quantum_ready: false`
     - `standard: "Classical ECDHE (Non-PQC)"`
     - `hndl_risk: "HIGH"`
     - Génération de l'alerte **`PQC-HNDL-EXPOSURE`** accompagnée des extraits de configuration prêts au copier-coller (`remediation_snippets`).

### Extraits de Remédiation Post-Quantique Fournis par Aegis

Lorsque `post_quantum_ready` vaut `false`, l'API retourne directement les configurations suivantes pour activer `X25519MLKEM768` :

#### Traefik (v3.3+ / Dokploy)
```yaml
tls:
  options:
    default:
      minVersion: VersionTLS13
      curvePreferences:
        - X25519MLKEM768
        - X25519
        - CurveP256
```

#### Nginx (avec OpenSSL 3.5+)
```nginx
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;
```

#### Caddy
```txt
tls {
    protocols tls1.3
    curves x25519mlkem768 x25519 secp256r1
}
```

#### Serveur Go Natif (Go 1.25+)
```go
tlsConfig := &tls.Config{
    MinVersion:       tls.VersionTLS13,
    CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
}
```

---

## 🧪 Comment Tester le Scanner Passif et la Sonde PQC ?

### 1. Exécuter les tests unitaires et le Handshake TLS 1.3 Post-Quantique local
Le fichier `apps/backend/internal/scanner/pqc_test.go` inclut un test de bout en bout (`TestLiveTLS13Handshake_NegotiatesX25519MLKEM768`) qui instancie un serveur TLS 1.3 local et vérifie la négociation réelle du groupe hybride `0x11ec` :

```bash
cd apps/backend
go test -v ./internal/scanner -run "TestEvaluateTLSConnectionState|TestLiveTLS13Handshake"
```

### 2. Interroger l'API du Scanner Passif (`/api/v1/audit/passive-scan`)
Lorsque le Control Plane Go est démarré :

```bash
curl -s -X POST http://localhost:8080/api/v1/audit/passive-scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "cloudflare.com"}' | jq '.post_quantum'
```

Exemple de réponse JSON sur un domaine protégé par `X25519MLKEM768` :
```json
{
  "post_quantum_ready": true,
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "negotiated_curve": "X25519MLKEM768 (0x11ec)",
  "standard": "NIST FIPS 203 (X25519MLKEM768)",
  "hndl_risk": "LOW — Protégé contre les attaques Harvest Now, Decrypt Later (HNDL) via encapsulation hybride X25519 + ML-KEM-768."
}
```

### 3. Vérifier manuellement avec OpenSSL 3.5+
```bash
openssl s_client -connect cloudflare.com:443 -groups X25519MLKEM768
```

---

## ⚖️ Niveau 2 : Mandat Légal & Vérification de Propriété (`ownership.go`)

Conformément à l'**Article 323-1 du Code pénal** (et aux cadres internationaux équivalents comme le CFAA), toute sonde susceptible de tester l'existence de fichiers sensibles non référencés (`/.env`, `/.git/config`, `/phpinfo.php`, `/wp-login.php`, `/xmlrpc.php`) requiert le consentement explicite du propriétaire légitime :

1. **Demande de challenge (`POST /api/v1/audit/request-verification`)** :
   Génère un jeton aléatoire cryptographique de 96 bits (`aegis-site-verification=aegis_verify_<24_hex>`).
2. **Validation multi-canal sans délai de cache (`POST /api/v1/audit/verify-ownership`)** :
   - Vérifie l'enregistrement DNS `TXT` sur `@` ou `_aegis-challenge.<domaine>` via le résolveur système, puis interroge directement **Cloudflare (`1.1.1.1:53`)** et **Google (`8.8.8.8:53`)** en UDP pour éviter tout cache DNS négatif.
   - À défaut, vérifie la présence du jeton dans `https://<domaine>/.well-known/aegis-verify.txt`.
3. **Preuve d'Audit Opposable (`contract_text_hash`)** :
   Le mandat signé, l'adresse IP du signataire, l'horodatage UTC RFC 3339 et le texte légal sont condensés par `SHA-256` et archivés dans la table PostgreSQL `domain_ownership_contracts` avant d'exécuter `runLevel2DeepChecks`.

---

## 📚 Lectures Complémentaires

- **[Passerelle Ingress PEP (WAF, Pure BFF & Virtual Patching)](/docs/fr/security/ingress-pep/)** : Comment les vulnérabilités détectées par le scanner passif sont neutralisées à chaud en moins de 1,5 ms.
- **[Simulation d'Attaques & Banc d'Essai Live](/docs/fr/pentest/banc-essai/)** : Rejouer des attaques contrôlées sur votre environnement de pré-production.
