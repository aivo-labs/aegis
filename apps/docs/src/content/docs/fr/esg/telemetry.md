---
title: Mesure Physique & Norme VS (EFRAG)
description: Télémétrie énergétique brute, registres matériels RAPL, mode frugal RGESN et génération d'attestation ESG.
---

Aegis Green rompt avec les estimations monétaires théoriques en s'appuyant exclusivement sur **la supériorité de la mesure physique réelle** (Watts et Joules consommés au niveau matériel).

## ⚡ Mécanismes de Mesure selon l'Infrastructure

L'agent de télémétrie Rust (`apps/telemetry-agent`) sélectionne automatiquement la meilleure source de captation disponible :

1. **Serveur Dédié (Bare-Metal)** : Lecture matérielle directe des compteurs Intel/AMD **RAPL** dans `/sys/class/powercap/intel-rapl` (précision ±1%).
2. **Cluster Kubernetes** : Intégration de la sonde eBPF **Kepler** pour ventiler la puissance physique au prorata des cycles CPU utilisés par chaque **Namespace** et **Pod**.
3. **VPS Cloud Virtualisé (KVM/QEMU)** : Lecture de la charge processeur réelle du serveur hôte via `/proc/stat` et application d'un modèle thermodynamique calibré sur le TDP moyen du VPS (12W à vide jusqu'à 48W à pleine charge).

---

## 🎯 Conformité Réglementaire 2026

Les métriques captées alimentent le radar de conformité ESG du Cockpit :

### 1. Norme Volontaire VS (EFRAG / ex-VSME)
* Conforme au **Volet E3 (Changement climatique & Sobriété Numérique)** de la directive européenne CSRD pour les PME.
* Génération en un clic d'un rapport certifié au format JSON standardisé (`AEGIS-VSME-EFRAG-AUDIT-2026.json`).

### 2. Référentiel RGESN 2024 (Éco-conception Logicielle)
* Intégration de la règle **RGESN 4.15** : Commutateur **Energy Saver (Mode Frugal)** permettant de réduire instantanément la charge processeur, d'espacer les sondages et de délester les animations GPU lors des alertes réseau.

### 3. Croisement Réseau RTE EcoWatt
* Suivi de l'intensité carbone temps réel du réseau électrique français (gCO2e/kWh).
* Mise en avant de la **Green Window** (fenêtre d'heures creuses et de forte production renouvelable, généralement 10h-14h) pour planifier les traitements de données volumineux.
