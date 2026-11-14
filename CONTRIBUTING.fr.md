# 🤝 Contribuer à Aegis Sovereign Gate

<p align="center">
  <a href="CONTRIBUTING.md">English</a> | <strong>Français</strong>
</p>

Merci de votre intérêt pour **Aegis Sovereign Gate** ! Avant de soumettre une Pull Request, nous vous invitons à lire notre document [Vision & Principes d'Ingénierie](VISION.fr.md) ainsi que notre [Code de Conduite](CODE_OF_CONDUCT.md).

---

## 1. Modèle de Branches Gitflow (Obligatoire)

Le dépôt Aegis applique strictement le modèle **Gitflow** formalisé par Vincent Driessen ([*A successful Git branching model*](https://nvie.com/posts/a-successful-git-branching-model/)).

```
main       ────●─────────────────────────────●───────────●──── (Tags de Production : v1.0.0, v1.1.0, v1.1.1)
                \                           /           /
hotfix/*         \                         /           ●────── (Correctifs critiques depuis main)
                  \                       /           /
release/*          \                 ●───●           /
                    \               /     \         /
develop    ──────────●──────●──────●───────●───────●────────── (Branche d'intégration principale)
                      \    /        \     /
feature/*              ●──●          ●───●                     (Branches fonctionnelles depuis develop)
```

### Branches Permanentes
* **`main`** : Code stable de production **uniquement**. Tout commit direct sur `main` est interdit. Chaque fusion vers `main` correspond à une version taguée (`vX.Y.Z`).
* **`develop`** : Branche d'intégration principale regroupant les développements validés pour la prochaine version.

### Branches Temporaires (Cycle de Vie)
1. **`feature/<scope>-<description-courte>`** (ex. `feature/pqc-readiness`, `feature/waf-base64-decoder`)
   * **Créée depuis** : `develop`
   * **Fusionnée vers** : `develop` (via Pull Request en mode `--no-ff`)
   * **Commandes types** :
     ```bash
     git checkout develop
     git pull origin develop
     git checkout -b feature/scanner-pqc-readiness develop
     ```
2. **`release/vX.Y.Z`** (ex. `release/v1.1.0`)
   * **Créée depuis** : `develop` lorsque les fonctionnalités ciblées sont prêtes.
   * **Objectif** : Incrément de version, gel fonctionnel, alignement documentaire et tests finaux de pré-production.
   * **Fusionnée vers** : `main` (avec tag `vX.Y.Z`) **puis reversée dans** `develop`.
3. **`hotfix/vX.Y.Z`** (ex. `hotfix/v1.0.1`)
   * **Créée depuis** : `main` pour corriger immédiatement une vulnérabilité ou anomalie critique en production.
   * **Fusionnée vers** : `main` (avec tag `vX.Y.Z`) **et dans** `develop`.

---

## 2. Convention de Nommage des Commits (Conventional Commits)

Tous les messages de commit doivent respecter la norme [Conventional Commits](https://www.conventionalcommits.org/) :

```text
<type>(<scope-optionnel>): <résumé concis à l'impératif>
```

* **`feat`** : Nouveau verrou de sécurité, nouvelle sonde ou fonctionnalité du cockpit (`feat(scanner): add NIST FIPS 203 X25519MLKEM768 PQC readiness probe`).
* **`fix`** : Correction de bug (`fix(rse): resolve blank page when printing CSRD PDF certificate`).
* **`security`** : Durcissement de sécurité ou remédiation de vulnérabilité.
* **`perf`** : Optimisation de latence, d'empreinte RAM ou de consommation énergétique RAPL.
* **`docs`** : Mise à jour de la documentation, des ADR ou de la Roadmap.
* **`test`** : Ajout ou mise à jour de tests unitaires / pentest.
* **`chore` / `ci`** : Scripts de build, Dockerfiles ou workflows GitHub Actions.

---

## 3. Vérifications Locales avant Pull Request

Avant d'ouvrir une Pull Request vers `develop`, vérifiez que l'ensemble des suites concernées passent avec succès :

### A. Control Plane Go & Scanner Passif (`apps/backend`)
```bash
cd apps/backend
go test -v ./...
```

### B. Passerelles TypeScript & Cockpit Web (`apps/gate-proxy`, `apps/egress-gateway`, `apps/web`, `apps/docs`)
```bash
pnpm install
pnpm --filter @aivo/aegis-gate-proxy build
pnpm --filter @aivo/aegis-egress-gateway build
pnpm test
pnpm --filter @aivo/aegis-web build
pnpm --filter @aivo/aegis-docs build
```

### C. Sonde Matérielle Rust (`apps/telemetry-agent`)
```bash
cd apps/telemetry-agent
cargo check
cargo test
```

### D. Banc d'Essai Docker & Batterie Pentest de Bout en Bout
```bash
docker compose up -d --build timescaledb backend gate-proxy web egress-gateway
./scripts/run-pentest-demo.sh
docker compose down -v
```

---

## 4. Standards d'Ingénierie & d'Éco-Conception

1. **Zéro Dépendance Superflue (Sobriété)** : Privilégiez systématiquement les bibliothèques standard (`crypto/tls`, `net/http` en Go ; `node:crypto`, `node:http` en Node.js) plutôt que des dépendances tierces lourdes.
2. **Parité Bilingue (FR & EN)** : Toute modification apportée à `README.md`, `ROADMAP.md`, `VISION.md` ou à la documentation Starlight (`apps/docs/src/content/docs/`) doit être répercutée dans son équivalent français (`README.fr.md`, `ROADMAP.fr.md`, `VISION.fr.md`, `apps/docs/src/content/docs/fr/`).
3. **Architecture Decision Records (`docs/adr/`)** : Tout choix structurant doit faire l'objet d'un ADR documenté.
4. **Aucun Secret dans Git** : Ne commitez jamais de fichier `.env`, de clé privée TLS ou de capture de trafic contenant des données personnelles.
