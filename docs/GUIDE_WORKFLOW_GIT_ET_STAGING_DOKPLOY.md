# Guide Opérationnel — Workflow Git & Déploiement Staging sur Dokploy (`aegis.baud.dev`)

Ce guide détaille la mise en place et l'utilisation quotidienne de notre pipeline de développement sécurisé, évitant tout risque d'indisponibilité sur l'environnement de production (`aegis.aivo.fr`).

---

## 1. Vue d'Ensemble des Environnements

| Caractéristique | 🧪 Environnement STAGING | 🚀 Environnement PRODUCTION |
| :--- | :--- | :--- |
| **Branche Git** | `develop` | `main` |
| **Domaine Public** | `https://aegis.baud.dev` | `https://aegis.aivo.fr` |
| **Fichier Compose** | `docker-compose.staging.yml` | `docker-compose.dokploy.yml` |
| **Conteneurs** | `aegis_staging_*` | `aegis_*` |
| **Base de Données** | `aegis_staging_db` (Volume isolé) | `aegis_db` (Volume de production) |
| **Client OIDC Keycloak** | `aegis-staging` | `aegis-cockpit` |
| **Objectif** | Développement, tests d'intégration, audits WAF, recettes | Disponibilité haute 99.9%, clients et audits officiels |

---

## 2. Le Cycle de Développement Quotidien (Workflow Git)

### Règle d'or : On ne pousse JAMAIS directement sur `main`

```
  (Feature / Fix)                 (Staging)                   (Production)
  feature/ma-branche  ──► PR ──►   develop    ──► PR ──►          main
                                      │                            │
                                      ▼                            ▼
                               aegis.baud.dev                aegis.aivo.fr
```

### Étape 1 : Créer une branche de travail depuis `develop`
```bash
# Se positionner sur develop à jour
git checkout develop
git pull origin develop

# Créer votre branche fonctionnelle ou de correction
git checkout -b feature/nouveau-detecteur-waf
# ou git checkout -b fix/correctif-tms
```

### Étape 2 : Développer et valider les tests localement
```bash
# Tests Backend Go
cd apps/backend && go test ./...

# Tests Monorepo (WAF PEP, Egress DNS, Web)
pnpm test

# Compilation Astro / Vue 3
pnpm --filter @aivo/aegis-web build
```

### Étape 3 : Pousser et ouvrir une Pull Request vers `develop`
```bash
git push -u origin feature/nouveau-detecteur-waf
```
* Ouvrir la PR sur GitHub avec pour cible : `base: develop` ◄ `compare: feature/...`.
* Le GitHub Actions CI valide automatiquement les tests unitaires et le build.
* Une fois mergée dans `develop`, Dokploy déploie automatiquement sur **`https://aegis.baud.dev`**.

### Étape 4 : Recette & Validation en Staging (`aegis.baud.dev`)
* Tester l'authentification Keycloak.
* Vérifier le comportement du WAF et de l'ingestion de télémétrie.
* Valider que la base de données et les fonctionnalités répondent parfaitement.

### Étape 5 : Promotion en Production (`main`)
* Ouvrir une Pull Request sur GitHub : `base: main` ◄ `compare: develop`.
* Vérifier que tous les contrôles CI sont verts.
* Merger la PR : Dokploy déploie la version stable sur **`https://aegis.aivo.fr`**.

---

## 3. Configuration Pas-à-Pas dans Dokploy (`aegis.baud.dev`)

Pour instancier l'environnement de Staging dans votre panneau Dokploy sans perturber la production :

### 1. Créer une nouvelle Application Compose dans Dokploy
* **Nom de l'application** : `aegis-staging`
* **Type de déploiement** : `Docker Compose`
* **Dépôt Git** : `aivo-labs/aegis` (ou URL SSH de votre dépôt)
* **Branche** : `develop`
* **Compose Path** : `docker-compose.staging.yml`

### 2. Configurer le Domaine dans Dokploy
* **Domaine** : `aegis.baud.dev`
* **Service cible** : `gate-proxy` (conteneur `aegis_staging_gate_proxy`)
* **Port cible** : `8000`
* **Activer HTTPS** : Cocher `Certificat Let's Encrypt (Automatique Traefik)`.

### 3. Variables d'Environnement pour le Staging
Dans l'onglet "Environnement" de l'application Dokploy `aegis-staging`, configurer :
```dotenv
APP_ENV=staging
APP_URL=https://aegis.baud.dev
AEGIS_APP_URL=https://aegis.baud.dev

POSTGRES_DB=aegis_staging_db
POSTGRES_USER=aegis_staging_user
POSTGRES_PASSWORD=votre_mot_de_passe_staging_securise

BFF_SESSION_SECRET=cle_secrete_aleatoire_32_octets_pour_staging!!
OIDC_ISSUER_URL=https://auth.aivo.fr/realms/aegis
OIDC_CLIENT_ID=aegis-staging
OIDC_CLIENT_SECRET=secret_du_client_keycloak_staging
OIDC_REDIRECT_URI=https://aegis.baud.dev/api/auth/callback
```

---

## 4. Configuration du Client OIDC Keycloak (`aegis-staging`)

Dans la console Keycloak (`https://auth.aivo.fr/admin`) au sein du Realm `aegis` :
1. Aller dans **Clients** > **Create client**.
2. **Client ID** : `aegis-staging`.
3. **Client Protocol** : `openid-connect`.
4. **Capability config** :
   * Client authentication : **ON** (Confidential).
   * Standard Flow : **ON** (Authorization Code).
   * Direct access grants : OFF.
5. **Login settings** :
   * **Root URL** : `https://aegis.baud.dev`
   * **Home URL** : `https://aegis.baud.dev/app`
   * **Valid redirect URIs** : `https://aegis.baud.dev/api/auth/callback`
   * **Valid post logout redirect URIs** : `https://aegis.baud.dev/*`
   * **Web origins** : `https://aegis.baud.dev`
6. Récupérer le secret dans l'onglet **Credentials** et le coller dans la variable `OIDC_CLIENT_SECRET` de Dokploy Staging.

---

## 5. Règle Vitale de Non-Interférence avec Traefik

> [!WARNING] Règle Absolue de Disponibilité
> * Le conteneur `aegis_staging_gate_proxy` est uniquement destiné à protéger et servir `https://aegis.baud.dev`.
> * **Ne jamais appliquer le middleware Traefik ForwardAuth de staging sur les routeurs de production** (`aivo.fr`, `nicolas.baud.dev`, etc.) ni sur l'interface Dokploy.
> * Si vous devez redémarrer ou reconfigurer le service de production, assurez-vous au préalable de retirer temporairement le middleware Traefik ForwardAuth dans Dokploy afin d'éviter tout blocage global.
