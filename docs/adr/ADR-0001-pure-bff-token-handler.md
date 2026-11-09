# ADR-0001 : Architecture Pure BFF & Token Handler OIDC (Keycloak)

* **Statut** : **Accepté**
* **Date** : 2026-11-09
* **Décideurs** : Équipe Architecture Aegis & Aivo Labs
* **Périmètre** : `apps/gate-proxy`, `apps/web`, Keycloak IAM

---

## 1. Contexte & Problématique

Dans les applications web modernes (Single Page Applications, frameworks SSR/SSG comme Astro/Vue), le stockage des jetons d'authentification OpenID Connect (Access Token JWT et Refresh Token) dans le stockage local du navigateur (`localStorage`, `sessionStorage` ou mémoire JavaScript) présente une vulnérabilité critique majeure :
* **Risque de vol de jetons par XSS** : Tout script malveillant injecté (dépendance npm compromise, injection de script) peut lire et exfiltrer les jetons.
* **Exposition de métadonnées** : Les payloads JWT contiennent des revendications d'identité, adresses e-mail, rôles et identifiants de locataire accessibles à tout script tiers.
* **Non-conformité ANSSI NIS 2 / RGPD** : Les référentiels de sécurité recommandent d'empêcher formellement l'accès du JavaScript aux jetons d'accès et d'authentification.

Nous devions concevoir un mécanisme d'authentification qui permette au cockpit web (`apps/web`) d'interagir avec les APIs sécurisées sans jamais manipuler ni détenir le moindre jeton JWT dans le navigateur.

---

## 2. Décision Architecturale

Nous adoptons le patron d'architecture **Pure BFF (Backend-For-Frontend) avec Token Handler**, directement intégré dans notre composant de passerelle [`apps/gate-proxy`](file:///home/andjurka/Work/aivo/Sites/Aegis/apps/gate-proxy).

### 2.1 Principes Fondamentaux

1. **Architecture "Zero-Token" côté Client** :
   Le navigateur ne reçoit et ne stocke **aucun JWT ni Refresh Token**.
2. **Cookie de Session Chiffré Hermétique** :
   Le Gate Proxy émet un cookie de session nommé `__aegis_bff_session` muni des attributs de protection maximaux :
   * `HttpOnly` (inaccessible à `document.cookie` ou à tout code JavaScript).
   * `Secure` (strictement réservé au transport chiffré HTTPS).
   * `SameSite=Lax` (protection native contre les attaques CSRF).
   * `Path=/` (portée globale sur l'application).
3. **Chiffrement Authentifié AES-256-GCM** :
   Le contenu du cookie est chiffré et signé symétriquement par le Gate Proxy à l'aide d'une clé secrète de 32 octets (`BFF_SESSION_SECRET`). Toute tentative de falsification ou de modification de charge utile invalide instantanément la session.
4. **Proxying & Injection des Jetons Amont** :
   Lorsqu'une requête authentifiée se dirige vers le backend Go ([`apps/backend`](file:///home/andjurka/Work/aivo/Sites/Aegis/apps/backend)), le Gate Proxy déchiffre la session en mémoire, injecte l'en-tête `Authorization: Bearer <access_token>` et transmet l'identité de l'utilisateur (`X-Aegis-User-Id`, `X-Aegis-User-Email`).

### 2.2 Endpoints d'Authentification Normalisés (Pure BFF)

Le Gate Proxy intercepte et gère nativement les routes suivantes sans solliciter le backend :
* `GET /api/auth/me` : Renvoie les informations du profil utilisateur courant (sans jamais renvoyer les jetons).
* `GET /api/auth/login` : Initie le flux OIDC Authorization Code Flow avec PKCE vers le serveur Keycloak.
* `GET /api/auth/callback` : Réceptionne le code d'autorisation, échange le code contre les jetons auprès de Keycloak, crée le cookie chiffré et redirige l'utilisateur vers le Cockpit.
* `POST /api/auth/logout` : Révoque les jetons côté Keycloak (Single Log-Out / SLO) et détruit le cookie de session.

---

## 3. Conséquences

### 3.1 Avantages (Positifs)
* **Éradication totale du vol de jetons par XSS** : Même en cas de faille XSS sur le front Astro/Vue, les jetons restent hors de portée car ils n'existent que dans le Gate Proxy.
* **Compatibilité OIDC / Keycloak transparente** : Support natif du Single Sign-On (SSO) et du Single Log-Out (SLO) d'entreprise.
* **Conformité réglementaire** : Répond aux exigences les plus strictes de l'ANSSI NIS 2 et de l'OWASP Top 10 API Security.

### 3.2 Contraintes & Risques Atténués
* **Clé secrète partagée** : Nécessite la définition rigoureuse de la variable `BFF_SESSION_SECRET` dans les configurations d'environnement Dokploy.
* **Taille du cookie de session** : Les jetons Keycloak pouvant contenir plusieurs rôles, le cookie est compacté et chiffré en binaire base64url sécurisé pour rester largement sous la limite de 4 Ko imposée par les navigateurs.
