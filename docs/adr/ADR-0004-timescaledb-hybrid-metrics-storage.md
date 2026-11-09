# ADR-0004 : Stockage Hybride Relationnel & Séries Temporelles avec TimescaleDB

* **Statut** : **Accepté**
* **Date** : 2026-11-09
* **Décideurs** : Équipe Architecture Aegis & Aivo Labs
* **Périmètre** : `apps/backend`, Base de données `aegis_db`, TimescaleDB

---

## 1. Contexte & Problématique

L'écosystème Aegis manipule deux typologies de données radicalement distinctes :
1. **Données Relationnelles Transactionnelles (ACID)** :
   * Nœuds d'infrastructure (`infrastructure_nodes`).
   * Liste des organisations et locataires (`tenants`).
   * Liste noire des adresses IP bannies (`ip_ban_list`).
   * Contrats d'audit de domaine et mandats de propriété (`domain_ownership_contracts`).
   * Configuration de rétention légale (`system_retention_config`).
2. **Séries Temporelles à Haute Fréquence (Time-Series)** :
   * Métriques matérielles énergétiques RAPL émises toutes les 5 secondes (`telemetry_energy_metrics`).
   * Journaux médico-légaux de sécurité Ingress (`security_audit_logs`).
   * Journaux d'interception DNS Egress (`egress_security_logs`).

Déployer deux moteurs de bases de données séparés (par exemple PostgreSQL pour le relationnel + Prometheus / InfluxDB pour les métriques) alourdirait considérablement la pile logicielle, augmenterait la consommation mémoire du VPS et compliquerait la sauvegarde et la corrélation SQL entre les incidents de sécurité et la charge énergétique.

---

## 2. Décision Architecturale

Nous retenons l'image **TimescaleDB basée sur PostgreSQL 16** (`timescale/timescaledb:latest-pg16`) comme moteur de stockage unique et souverain pour l'ensemble des données d'Aegis.

### 2.1 Avantages du Moteur Hybride

* **Moteur SQL Unique & Unifié** : Une seule instance PostgreSQL à superviser, sauvegarder (`pg_dump`) et répliquer.
* **Fonctionnalité native `time_bucket()`** : Permet des agrégations ultra-rapides sur des fenêtres temporelles dynamiques (1 min, 15 min, 1h, 4h, 1 jour) sans saturer la bande passante ni faire exploser le nombre de points renvoyés au frontend Astro/Vue.
* **Résilience & Fallback `date_bin`** : Pour garantir la portabilité du code dans les environnements où l'extension TimescaleDB ne serait pas activement préchargée, notre backend Go implémente un repli automatique vers la fonction native PostgreSQL 14+ `date_bin(INTERVAL, timestamp, TIMESTAMP)`.
* **Rétention Réglementaire Configurable (`system_retention_config`)** :
  * `hot_window_days` (défaut : 30 jours) : Données en cache chaud pour affichage temps réel.
  * `anssi_forensic_days` (défaut : 180 jours) : Conservation légale d'investigation post-incident conforme à la directive NIS 2.
  * `rgpd_clean_ip_days` (défaut : 7 jours) : Purge automatique des adresses IP brutes après 7 jours pour anonymisation conforme RGPD.

---

## 3. Conséquences

### 3.1 Avantages (Positifs)
* **Empreinte mémoire frugale** : Environ 80 Mo de RAM au repos contre plus de 400 Mo pour un couple Postgres + InfluxDB + Prometheus.
* **Requêtes analytiques puissantes** : Capacité de croiser en une seule requête SQL les pics de consommation électrique avec les attaques applicatives WAF subies à la même seconde.
* **Maintenance simplifiée** : Sauvegarde unifiée sur un seul volume Docker persistant (`aegis_pgdata`).

### 3.2 Bonnes Pratiques d'Exploitation
* Toujours utiliser le compte non-root `aegis_user` et la base `aegis_db`.
* Ne jamais réinitialiser la base de données en production sans avoir préalablement vérifié et détaché les middlewares Traefik.
