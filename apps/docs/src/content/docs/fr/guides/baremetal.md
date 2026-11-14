---
title: Déploiement Serveur Dédié Bare-Metal
description: Guide de déploiement d'Aegis sur serveur dédié physique avec accès direct aux compteurs matériels Intel/AMD RAPL.
---

Ce guide est destiné aux entreprises et institutions exploitant des serveurs physiques dédiés (OVH Rise/Kimsufi, Hetzner Dedicated, Scaleway Dedibox, Dell PowerEdge sur site).

## ⚡ Pourquoi le Bare-Metal avec Aegis ?

Sur un serveur dédié physique, Aegis accède sans intermédiaire aux registres matériels **RAPL (Running Average Power Limit)** d'Intel et d'AMD situés dans `/sys/class/powercap/intel-rapl`.

* **Précision physique absolue** : Mesure directe des microjoules consommés par les packages processeurs et la mémoire vive (précision silicium ±1%).
* **Zéro approximation statistique** : Pas d'estimation basée sur un TDP théorique, mais la consommation réelle en Watts.
* **Certificats d'Audit CSRD / EFRAG** : Génération d'attestations opposables conformes au volet E3 de la norme volontaire PME (VSME).

---

## 🚀 Méthode 1 : Déploiement 1-Clic via Script (Recommandé)

Sur votre serveur dédié (accès root requis) :

```bash
curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- --profile baremetal
```

Le script d'installation détecte automatiquement les registres RAPL, monte l'arborescence `/sys/class/powercap` et démarre la composition durcie.

---

## 🛠️ Méthode 2 : Déploiement Manuel avec Docker Compose

Si vous déployez manuellement depuis le dépôt Git :

### 1. Vérifier la disponibilité des modules noyau RAPL

```bash
# Vérifier la présence du répertoire de puissance
ls -la /sys/class/powercap/intel-rapl/

# Si le module n'est pas chargé :
sudo modprobe intel_rapl_msr
```

### 2. Démarrer avec le profil Bare-Metal

```bash
git clone https://github.com/aivo-labs/aegis.git /opt/aegis
cd /opt/aegis

# Déploiement avec montage des registres matériels
docker compose -f deploy/docker-compose/docker-compose-baremetal.yml up -d --build
```

---

## 🔍 Vérification de la Captation Matérielle Directe

Inspectez les journaux de l'agent de télémétrie :

```bash
docker compose -f deploy/docker-compose/docker-compose-baremetal.yml logs telemetry-agent
```

Vous devez observer la mention :
```log
✅ [Ingest OK] Total: 64.20W (RAPL_HARDWARE_DIRECT) | CPU: 18.5% | Delta Joules: 321.00J
```

Le tag `RAPL_HARDWARE_DIRECT` atteste que la mesure provient directement du capteur de puissance intégré au processeur physique.

---

## 🧪 Valider la Réaction sous Charge avec le Banc d'Essai

Pour observer l'élévation immédiate de puissance en Watts lors d'une attaque, exécutez la batterie de tests :

```bash
cd /opt/aegis
./scripts/run-pentest-demo.sh
```

Sur votre Cockpit ([`http://localhost:4321/app`](http://localhost:4321/app)), observez la corrélation instantanée entre le blocage des requêtes offensives et le graphique de consommation physique du processeur.
