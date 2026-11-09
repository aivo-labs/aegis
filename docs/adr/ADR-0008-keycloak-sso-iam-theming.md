# ADR-0008 : Intégration Keycloak Multi-Realm & Thèmes Souverains Aivo / Aegis

* **Statut** : **Accepté**
* **Date** : 2026-11-09
* **Décideurs** : Équipe Architecture Aegis & Aivo Labs
* **Périmètre** : `tools/keycloak`, IAM OIDC, Thèmes Keycloak, Single Sign-On (SSO)

---

## 1. Contexte & Problématique

L'identité, l'authentification et les autorisations (IAM) de l'ensemble de notre écosystème sont orchestrées par **Keycloak**, déployé de manière souveraine sur notre VPS (`https://auth.aivo.fr` via le répertoire [`tools/keycloak`](file:///home/andjurka/Work/aivo/Sites/tools/keycloak)).

Cependant, l'utilisation des mires par défaut de Keycloak pose plusieurs limites :
1. **Rupture d'expérience utilisateur (UX)** : Les mires par défaut grises/bleues de Keycloak contrastent fortement avec l'esthétique Cyber-SOC sombre d'Aegis (palette ardoise, vert émeraude, cyan).
2. **Gestion des flux de déconnexion (SLO)** : Le Single Log-Out OIDC standard déclenche parfois des pages de confirmation de déconnexion déroutantes si le thème n'est pas adapté pour finaliser la redirection vers le cockpit.
3. **Multi-environnements (Prod vs Staging)** : Les clients OIDC doivent gérer distinctement les redirections vers `https://aegis.aivo.fr` (production) et `https://aegis.baud.dev` (staging) sans conflits de sessions.

---

## 2. Décision Architecturale

Nous adoptons une **gestion centralisée des thèmes dans [`tools/keycloak/themes`](file:///home/andjurka/Work/aivo/Sites/tools/keycloak/themes)** et une configuration normalisée des clients OIDC.

### 2.1 Structure des Thèmes Souverains (`tools/keycloak/themes`)

Les thèmes Keycloak sont organisés selon l'arborescence standard FreeMarker (FTL) :
```
tools/keycloak/themes/
├── aivo/
│   ├── login/
│   │   ├── theme.properties
│   │   ├── resources/
│   │   │   ├── css/ (cyber-soc.css, tailwind base)
│   │   │   └── img/ (aivo-logo.svg, aegis-shield.svg)
│   │   └── login.ftl (Formulaire d'authentification sombre)
│   │   └── login-reset-password.ftl
│   │   └── logout-confirm.ftl (Gestion fluide du Single Log-Out)
└── aegis/ (Déclinaison spécifique SOC GreenOps)
```

### 2.2 Paramétrage des Clients OIDC Keycloak

Pour chaque environnement, un client OIDC dédié est configuré dans le Realm `aegis` :
1. **Client Production (`aegis-cockpit`)** :
   * **Root URL** : `https://aegis.aivo.fr`
   * **Valid Redirect URIs** : `https://aegis.aivo.fr/api/auth/callback`
   * **Post Logout Redirect URIs** : `https://aegis.aivo.fr/*`
   * **Flow** : Standard Flow (Authorization Code) avec **PKCE activé**.
   * **Client Authentication** : Confidential (Client Secret injecté dans `gate-proxy`).
2. **Client Staging (`aegis-staging`)** :
   * **Root URL** : `https://aegis.baud.dev`
   * **Valid Redirect URIs** : `https://aegis.baud.dev/api/auth/callback`
   * **Post Logout Redirect URIs** : `https://aegis.baud.dev/*`
   * **Flow** : Standard Flow avec PKCE.

---

## 3. Conséquences

### 3.1 Avantages (Positifs)
* **Image de Marque Impeccable** : L'utilisateur passe du cockpit à la mire de connexion sans aucune rupture visuelle.
* **Sécurité RBAC Granulaire** : Les rôles attribués dans Keycloak (`admin`, `analyst`, `auditor`, `client_starter`) sont inclus dans les claims du token que le Gate Proxy extrait et valide.
* **Isolation Staging / Production** : Un test d'authentification sur le staging `aegis.baud.dev` n'altère ni n'interrompt les sessions ouvertes sur la production `aegis.aivo.fr`.

### 3.2 Déploiement du Thème
* Dans le `docker-compose.yml` de Keycloak sur le VPS, le dossier local `./themes` est monté en volume dans `/opt/keycloak/themes`.
* L'activation du thème s'effectue dans la console d'administration Keycloak : `Realm Settings` > `Themes` > `Login Theme: aivo`.
