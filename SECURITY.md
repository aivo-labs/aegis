# 🔐 Security Policy & Responsible Disclosure / Politique de Sécurité

<p align="center">
  <a href="#english-version">English</a> | <a href="#version-française">Français</a>
</p>

---

<a id="english-version"></a>

## 🇬🇧 Security Policy

### Supported Versions

Security patches are released on the `main` branch via Gitflow `hotfix/vX.Y.Z` branches for the following versions:

| Version | Supported |
| :--- | :---: |
| `1.x` (`main`) | ✅ |
| `< 1.0` | ❌ |

### Reporting a Vulnerability (Responsible Disclosure)

**Please do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

If you discover a potential vulnerability in `gate-proxy` (WAF bypass, Pure BFF session handling), `egress-gateway` (DNS sinkhole / egress bypass), `backend` (Control Plane API / RBAC), or `telemetry-agent`:

1. Send a detailed report to **security@aivo.fr** (or via GitHub Private Vulnerability Reporting once enabled on the repository).
2. Include:
   * Affected component(s) and file path(s)
   * Step-by-step reproduction or minimal Proof-of-Concept (`curl` command, DNS query, or unit test)
   * Potential impact and suggested remediation (if any)

### Our Response Commitment

* **Acknowledgment**: Within **48 hours** of receipt.
* **Triage & Assessment**: Within **5 business days**.
* **Patch & Coordinated Disclosure**: Critical fixes are developed via a dedicated `hotfix/*` branch, verified against our pentest suite, and credited to the reporter upon public release (unless anonymity is requested).

---

<a id="version-française"></a>

## 🇫🇷 Politique de Sécurité & Divulgation Responsable

### Versions Supportées

Les correctifs de sécurité sont publiés sur la branche `main` via le flux Gitflow `hotfix/vX.Y.Z` :

| Version | Supportée |
| :--- | :---: |
| `1.x` (`main`) | ✅ |
| `< 1.0` | ❌ |

### Signaler une Vulnérabilité

**Merci de NE PAS signaler de failles de sécurité via des Issues ou Pull Requests publiques.**

Si vous identifiez une vulnérabilité potentielle dans `gate-proxy` (contournement WAF, session Pure BFF), `egress-gateway` (contournement DNS sinkhole), `backend` (Control Plane Go) ou `telemetry-agent` :

1. Envoyez votre rapport détaillé à **security@aivo.fr** (ou via le signalement privé GitHub Security Advisories).
2. Précisez :
   * Le composant et les fichiers concernés
   * La procédure exacte de reproduction (`curl`, requête DNS ou test unitaire)
   * L'impact estimé et, le cas échéant, votre piste de correctif

### Engagements de Traitement

* **Accusé de réception** : Sous **48 heures**.
* **Qualification technique** : Sous **5 jours ouvrés**.
* **Correctif & Publication coordonnée** : Tout correctif critique fait l'objet d'une branche `hotfix/*`, d'un test de non-régression dans la batterie pentest et d'une mention de remerciement dans les notes de version.
