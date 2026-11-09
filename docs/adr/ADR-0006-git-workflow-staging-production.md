# ADR-0006 : Stratégie de Branches Git, Environnements Staging (`develop` -> `aegis.baud.dev`) et Production (`main` -> `aegis.aivo.fr`)

* **Statut** : **Accepté**
* **Date** : 2026-11-09
* **Décideurs** : Équipe Architecture Aegis & Aivo Labs
* **Périmètre** : Git Workflow, CI/CD, Dokploy, `aegis` & `aegis-cloud`

---

## 1. Contexte & Problématique

Le développement itératif rapide sans séparation stricte entre environnement de validation et environnement de production a conduit à un incident critique :
1. Une règle de détection WAF trop stricte sur les callbacks OIDC a banni l'adresse IP de l'administrateur.
2. La suppression précipitée du service conteneurisé alors que le middleware Traefik ForwardAuth était toujours actif a entraîné l'interruption des sites publics (`aivo.fr`, `nicolas.baud.dev`) et la perte temporaire d'accès à l'interface Dokploy.
3. Des conflits de schémas de base de données ont failli corrompre l'historique de production.

Pour pérenniser l'écosystème Aegis et avancer sereinement vers l'onboarding client et les paiements Stripe, il est impératif d'instaurer une **discipline de déploiement stricte** avec un **environnement de Staging miroir (`aegis.baud.dev`)**.

---

## 2. Décision Architecturale

Nous adoptons une variante robuste et allégée du modèle **GitFlow**, couplée à une séparation étanche des environnements de déploiement sur Dokploy.

### 2.1 Arborescence des Branches Git

```mermaid
gitGraph
    commit id: "v4.2.0 (Stable Prod)"
    branch develop
    checkout develop
    commit id: "Init develop"
    branch feature/nouvelle-fonctionnalité
    checkout feature/nouvelle-fonctionnalité
    commit id: "Dev feature"
    commit id: "Tests unitaires"
    checkout develop
    merge feature/nouvelle-fonctionnalité id: "PR -> develop"
    commit id: "Deploy Staging (aegis.baud.dev)" tag: "STAGING TEST"
    checkout main
    merge develop id: "PR -> main (Release validée)" tag: "PROD (aegis.aivo.fr)"
    branch hotfix/patch-urgent
    checkout hotfix/patch-urgent
    commit id: "Hotfix P1"
    checkout main
    merge hotfix/patch-urgent id: "Hotfix Prod"
    checkout develop
    merge hotfix/patch-urgent id: "Backport Hotfix"
```

1. **Branche `main` (Production Souveraine)** :
   * **URL de Déploiement** : `https://aegis.aivo.fr`
   * **Règle absolue** : Aucun commit direct sur `main`. Seules les pull requests ou fusions depuis `develop` (après recette réussie sur le staging) ou depuis un `hotfix/*` sont autorisées.
   * **Stabilité** : 100% testée, compilée et auditée.
2. **Branche `develop` (Staging & Pré-production)** :
   * **URL de Déploiement** : `https://aegis.baud.dev`
   * **Rôle** : Branche d'intégration active. Déploiement automatique ou continu par Dokploy dès qu'une modification y est poussée.
   * Sert de bac à sable grandeur nature pour vérifier l'intégration Traefik, les certificats SSL, les sessions OIDC Keycloak et les migrations SQL sans aucun risque pour la production.
3. **Branches `feature/<nom>` & `fix/<nom>`** :
   * Dérivées systématiquement depuis `develop`.
   * Fusionnées dans `develop` une fois les tests locaux validés (`go test`, `npm test`, `npm run build`).
4. **Branches `hotfix/<nom>`** :
   * Dérivées directement depuis `main` en cas d'urgence opérationnelle.
   * Fusionnées immédiatement dans `main` ET réintégrées (*backportées*) dans `develop` pour éviter toute régression ultérieure.

---

### 2.2 Règles d'Étanchéité des Environnements sur Dokploy

| Critère | Environnement de Staging | Environnement de Production |
| :--- | :--- | :--- |
| **Branche Git** | `develop` | `main` |
| **Domaine Public** | `aegis.baud.dev` | `aegis.aivo.fr` |
| **Fichier Compose** | `docker-compose.staging.yml` | `docker-compose.dokploy.yml` |
| **Nom des Conteneurs** | Préfixés `aegis_staging_*` | Préfixés `aegis_*` |
| **Base de Données** | `aegis_staging_db` (Volume isolé) | `aegis_db` (Volume de production) |
| **Mode WAF Ingress** | `AUDIT` / `DRY_RUN` ou permissif | `BLOCK` (Protection Active) |
| **Middleware Traefik** | `aegis-staging-auth-pep` | `aegis-auth-pep` |
| **Raccordement Traefik** | Uniquement branché sur `aegis.baud.dev` | Branché sur les domaines de production |

---

### 2.3 Règle Vitale de Non-Régression pour Traefik

> [!CAUTION] Règle Anti-Verrouillage Traefik
> 1. Le middleware Traefik ForwardAuth de staging (`aegis-staging-auth-pep`) ne doit **jamais** être associé à des routeurs de production ni au routeur système de Dokploy.
> 2. Si une instance d'Aegis doit être arrêtée ou redéployée, **toujours vérifier dans Dokploy que le middleware Traefik est détaché des sites tiers**, ou s'assurer que le Gate PEP répond en mode *Fail-Open* si le conteneur est en maintenance.
> 3. L'adresse IP de l'administrateur (`92.157.163.164`) et le loopback (`127.0.0.1`) disposent d'une clause d'immunité inviolable dans le code source du WAF.

---

## 3. Conséquences

### 3.1 Avantages (Positifs)
* **Sérénité de Développement** : Les nouveaux tests, modifications d'ingestion ou règles WAF peuvent être éprouvés en conditions réelles sur `aegis.baud.dev` sans le moindre stress d'interrompre les activités commerciales de `aivo.fr`.
* **Traçabilité des versions** : Passage formalisé de Staging vers Prod avec tags Git sémantiques (`v4.3.0`, `v4.3.1`, etc.).
* **Indépendance des bases de données** : Une fausse manipulation ou une purge de base sur le staging n'altère en rien les tables de production.

### 3.2 Coût Opérationnel
* Gestion de deux applications conteneurisées dans l'interface Dokploy.
* Veiller à reporter les éventuelles nouvelles variables d'environnement dans les deux configurations Dokploy.
