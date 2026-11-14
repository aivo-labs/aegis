# Architecture Decision Records (ADR) — Écosystème Aegis Sovereign Gate

Ce répertoire consigne l'ensemble des décisions d'architecture structurantes prises pour **Aegis Sovereign Gate** (Moteur Souverain Open-Core, Passerelles Zero-Trust & Cockpit SOC GreenOps).

Ces enregistrements suivent le standard **MADR (Markdown Any Decision Record)** et garantissent la traçabilité, la résilience, la maintenabilité et l'opposabilité technique de notre architecture face aux exigences de souveraineté européenne (ANSSI NIS 2, SecNumCloud, RGPD, CSRD/RSE).

---

## 📋 Registre des Décisions d'Architecture

| Identifiant                                                      | Titre | Statut | Date | Périmètre |
|:-----------------------------------------------------------------| :--- | :---: | :---: | :--- |
| [**ADR-0001**](./ADR-0001-pure-bff-token-handler.md)             | Architecture Pure BFF & Token Handler OIDC (Keycloak) | **Accepté** | 2026-11-09 | Sécurité Web / IAM |
| [**ADR-0002**](./ADR-0002-traefik-forwardauth-waf-pep.md)        | Traefik ForwardAuth PEP Ingress & WAF In-Memory Zero-Latency | **Accepté** | 2026-11-09 | Ingress / WAF / Traefik |
| [**ADR-0003**](./ADR-0003-dns-sinkhole-egress-security.md)       | DNS Sinkhole Egress & Filtrage Anti-Exfiltration C2 (Port 5053) | **Accepté** | 2026-11-09 | Egress / DNS / Sécurité Réseau |
| [**ADR-0004**](./ADR-0004-timescaledb-hybrid-metrics-storage.md) | Stockage Hybride Relationnel & Séries Temporelles avec TimescaleDB | **Accepté** | 2026-11-09 | Données / TimescaleDB |
| [**ADR-0005**](./ADR-0005-greenops-frugal-rapl-telemetry.md)     | Télémétrie Frugale GreenOps & Nœud Souverain Consolidé (RAPL/Scaphandre) | **Accepté** | 2026-11-09 | GreenOps / Télémétrie / RSE |
| [**ADR-0006**](./ADR-0006-git-workflow-staging-production.md)    | Stratégie de Branches Git, Environnements Staging (`develop` -> `aegis.baud.dev`) et Production (`main` -> `aegis.aivo.fr`) | **Accepté** | 2026-11-09 | CI/CD / DevOps / Staging |
| [**ADR-0007**](./ADR-0007-keycloak-sso-iam-theming.md)           | Intégration Keycloak Multi-Realm & Thèmes Souverains Aivo / Aegis | **Accepté** | 2026-11-09 | IAM / Keycloak / UX |

---

## 🛡️ Principes Fondateurs de l'Écosystème

1. **Zero-Trust & Défense en Profondeur** : Aucun trafic n'est implicitement fiable, qu'il provienne d'Internet ou de notre réseau interne. Chaque requête entrante et sortante est évaluée par un PEP (*Policy Enforcement Point*).
2. **Zero-Token dans le Navigateur (Pure BFF)** : Les jetons cryptographiques sensibles (JWT d'accès, jetons de rafraîchissement) ne transitent jamais dans le code JavaScript côté client. Le navigateur n'a accès qu'à un cookie chiffré hermétique `HttpOnly`, `SameSite=Lax`, `Secure`.
3. **Frugalité Numérique & RSE Opposable** : La sécurité ne doit pas engendrer une empreinte carbone disproportionnée. La télémétrie matérielle s'appuie directement sur les registres matériels CPU (Intel/AMD RAPL) sans surcoût d'agents tiers énergivores.
4. **Disponibilité & Isolation Stricte (Garde-fous Staging)** : Toute modification logicielle doit impérativement être validée sur l'environnement de staging (`aegis.baud.dev`) branché sur `develop` avant toute intégration en production (`aegis.aivo.fr`). Le middleware de sécurité en staging ne doit en aucun cas interférer avec la production ou Dokploy.
