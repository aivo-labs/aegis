---
title: Mesure Physique & Norme VS (EFRAG)
description: Télémétrie énergétique matérielle, registres RAPL, sondes eBPF Kepler, mode frugal RGESN et génération d'attestation RSE certifiée.
---

Aegis Green rompt définitivement avec les modèles comptables théoriques en s'appuyant sur **la supériorité de la mesure physique réelle** : des Watts et Joules consommés au niveau des registres matériels des processeurs.

---

## ⚡ Schéma d'Architecture de la Télémétrie Énergétique

```
    ┌──────────────────────────┐  ┌──────────────────────────┐  ┌──────────────────────────┐
    │     SERVEUR DÉDIÉ        │  │    CLUSTER KUBERNETES    │  │        VPS CLOUD         │
    │      (Bare-Metal)        │  │     (EKS, GKE, Bare)     │  │    (KVM, QEMU, Cloud)    │
    │                          │  │                          │  │                          │
    │ Registres MSR Physiques  │  │ Sonde Kernel eBPF Kepler │  │ Cycles CPU /proc/stat    │
    │ Intel/AMD RAPL (±1%)     │  │ Ventilation Pod/Namespace│  │ Modèle thermodynamique  │
    └────────────┬─────────────┘  └────────────┬─────────────┘  └────────────┬─────────────┘
                 │                             │                             │
                 └───────────────────────┬─────┴─────────────────────────────┘
                                         ▼
                 ┌───────────────────────────────────────────────────────────┐
                 │          AGENT DE TÉLÉMÉTRIE RUST SOVERAIN                │
                 │              (apps/telemetry-agent)                       │
                 │                                                           │
                 │  • Binaire natif compilé sans garbage collector           │
                 │  • Empreinte CPU négligeable (< 0,2%)                     │
                 │  • Isolation PID: host & montage /proc, /sys en lecture   │
                 │  • Échantillonnage continu toutes les 5 secondes          │
                 └─────────────────────────────┬─────────────────────────────┘
                                               │
                                               ▼ Ingestion JSON (/api/v1/gate/telemetry/energy)
                 ┌───────────────────────────────────────────────────────────┐
                 │           BACKEND GO & BASE TIMESCALEDB                   │
                 │                                                           │
                 │  • Hypertables temporelles compressées (Chunk 7 jours)    │
                 │  • Croisement temps réel intensité RTE EcoWatt            │
                 │  • Calcul Scope 2 : Énergie (kWh), CO₂eq (g), Eau (L)     │
                 └─────────────────────────────┬─────────────────────────────┘
                                               │
                                ┌──────────────┴──────────────┐
                                ▼                             ▼
                 [ COCKPIT WEB AEGIS ]        [ EXPORTS RSE & CERTIFICATIONS ]
                 • Radar de conformité EFRAG  • Certificat Officiel RSE (PDF)
                 • Suivi des Watts en direct  • Rapport d'audit standard JSON
                 • Commutateur Mode Frugal    • Export tabulaire CSV brut
```

---

## 🔬 Les 3 Modes de Captation selon l'Infrastructure

L'agent de télémétrie Rust sélectionne automatiquement la méthode de mesure la plus précise disponible sur l'environnement hôte :

### 1. Serveurs Dédiés Physiques (Bare-Metal) : Registres RAPL
Sur les serveurs dédiés (OVHcloud, Hetzner, Scaleway Dedibox), l'agent accède directement à l'interface noyau **Intel/AMD RAPL (Running Average Power Limit)** via `/sys/class/powercap/intel-rapl` :
* Lecture des compteurs matériels en microjoules au niveau du socket CPU, de la mémoire vive (DRAM) et des cœurs (*Package Energy Status*).
* Précision certifiée à **±1%** par rapport à un wattmètre physique de banc d'essai.

### 2. Clusters Conteneurisés (Kubernetes) : Sonde eBPF Kepler
Dans les environnements Kubernetes, Aegis s'interface avec les sondes eBPF de **Kepler (Kubernetes Efficient Power Level Exporter)** :
* Attribue la consommation d'énergie physique réelle au prorata des cycles d'instructions et interruptions de chaque **Namespace**, **Deployment** ou **Pod**.
* Permet aux équipes DevOps de refacturer précisément l'empreinte carbone à chaque microservice métier.

### 3. VPS Virtualisés (KVM / QEMU / Proxmox) : Modèle Thermodynamique
Sur les machines virtuelles où les registres MSR physiques sont masqués par l'hyperviseur :
* Lecture directe des compteurs de cycles CPU dans `/proc/stat` (`user`, `system`, `iowait`, `idle`).
* Application continue d'un modèle thermodynamique étalonné sur le profil matériel de la machine hôte (consommation de base à vide de 12 W, montant jusqu'à 48 W à pleine charge par vCPU).
* **Bornage CPU Strict** : Encadrement mathématique dans l'intervalle `[0,0, 100,0]%` éliminant tout artefact de surconsommation induit par les dérives temporelles d'hyperviseur ou réétalonnages de fréquence.

---

## 🛡️ Détection d'Intrusions Hôte & Résilience d'Ingestion

L'agent de télémétrie Rust (`apps/telemetry-agent`) combine la surveillance énergétique avec une télémétrie de sécurité au niveau du noyau :

### 1. Surveillance des Processus Enfants & Filtrage des Workers Légitimes
L'agent intercepte les appels système fork/exec pour repérer en temps réel les comportements anormaux sur l'hôte :
* **Filtrage des Workers Bénins (`is_benign_worker_child_cmd`)** : Détection intelligente des invocations normales de développement et d'orchestration (ex: `node` exécutant `sh -c dotenv -e ...`, gestionnaires de paquets, bundlers), évitant la pollution du flux par de fausses alertes P1.
* **Neutralisation des Objections & Shells Malveillants** : Tout spawn de shell interactif ou binaire réseau non autorisé (`nc -e /bin/sh`, connexions TCP inverses, `bash -i`) génère instantanément une alerte d'urgence dans le Cockpit.

### 2. Haute Disponibilité d'Ingestion & Failover DNS TimescaleDB
Pour garantir une intégrité totale de la comptabilité énergétique sans interruption lors des congestions réseau ou défaillances de résolution interne :
* **Résolution Directe `/etc/hosts`** : Dans le backend Go, le pool de connexions pgx inspecte `/etc/hosts` pour s'affranchir des erreurs SERVFAIL intermittentes du résolveur interne de Docker (`127.0.0.11:53`).
* **Cache d'IP Persistant & KeepAlive TCP** : Maintien continu des connexions avec KeepAlive 30s et bascule automatique sur la dernière adresse IP valide connue en mémoire, éliminant tout rejet de télémétrie.

---

## 🎯 Conformité Réglementaire Européenne 2026

Aegis Green transforme vos données de consommation électrique en indicateurs d'audit directement exploitables pour vos obligations extra-financières :

### 1. Norme Volontaire VS (EFRAG / ex-VSME)
* Conforme au **Volet E3 (Changement climatique & Sobriété Numérique)** de la directive européenne **CSRD** pour les PME et ETI.
* Calcul automatisé des émissions **Scope 2** (méthodes *Market-based* et *Location-based*) et de la consommation d'eau induite par le refroidissement des datacenters.

### 2. Référentiel RGESN 2024 (Règle 4.15 & Mode Frugal)
* Le Cockpit Aegis intègre le commutateur **Energy Saver (Mode Frugal)** conforme à la règle 4.15 du Référentiel Général d'Éco-conception de Services Numériques (RGESN).
* Son activation réduit instantanément la fréquence d'échantillonnage de télémétrie, décharge les animations graphiques du tableau de bord et optimise les requêtes de base de données pour réduire de 25% la sollicitation CPU du serveur en période de veille.

### 3. Synchronisation Réseau RTE EcoWatt & « Green Window »
* Croisement en direct avec les données d'intensité carbone du mix électrique français (gCO₂eq/kWh).
* Mise en avant de la **Green Window** (plage d'heures creuses et de production solaire/éolienne maximale, généralement 11h-15h) pour planifier les traitements par lots, backups et sauvegardes énergivores.

---

## 📑 Formats d'Exportation & Attestation Certifiée

Le Cockpit Aegis propose trois formats d'exportation pour répondre à tous les besoins d'audit :

1. **Certificat Officiel RSE (PDF)** : Document officiel soigné aux couleurs de votre entreprise, attestant de votre consommation électrique (kWh), de vos émissions évitées et de votre conformité aux directives européennes. Idéal pour transmission aux commissaires aux comptes, investisseurs ou clients grands comptes.
2. **Rapport d'Audit JSON Standardisé** (`AEGIS-VSME-EFRAG-AUDIT-2026.json`) : Fichier structuré et horodaté respectant les schémas de données EFRAG pour intégration automatisée dans les logiciels de reporting RSE.
3. **Export Brute CSV** : Historique granulaire point par point pour analyse statistique dans vos outils de business intelligence.

---

## 📚 Articles & Références Techniques AIVO

Pour explorer les mesures de laboratoire et l'impact de l'efficacité logicielle sur la facture énergétique :

* 📖 [**Anatomie d'un VPS sous assaut continu : Scanners, Énergie et Réponses Actives**](https://aivo.fr/blog/anatomie-vps-sous-assaut-continu-scanners-energie) — Mesures comparatives de consommation électrique lors d'attaques volumétriques et démonstration de l'économie d'énergie apportée par le blocage en amont.
* 📖 [**Entropie de Shannon & Décision Zero-Trust : L'IA Frugale au service du WAF**](https://aivo.fr/blog/entropie-shannon-decision-zero-trust-ia-frugale) — Pourquoi le calcul mathématique local consomme 1 000 fois moins d'énergie qu'un appel d'API vers un grand modèle de langage cloud.
* 🔬 [**Étude de cas Aegis Sovereign Gate sur AIVO.fr**](https://aivo.fr/realisations/aegis-sovereign-gate) — Comment combiner cyberdéfense de pointe et respect des engagements climatiques européens.
