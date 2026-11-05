---
title: Déploiement Kubernetes (K8s) & Attribution par Namespace
description: Guide officiel pour sécuriser un cluster K8s et attribuer la consommation d'énergie (Watts et gCO2e) par Namespace avec Kepler eBPF.
---

L'extension d'Aegis sur **Kubernetes** répond au défi majeur des architectures conteneurisées : **comment savoir quelle application consomme quelle énergie lorsque des dizaines de services se partagent le même cluster de serveurs ?**

Grâce à l'intégration de **Kepler (CNCF)** et du Helm Chart officiel d'Aegis, vous pouvez suivre en temps réel la consommation en Watts et en gCO2e découpée par **Namespace** (ex: `production`, `staging`, `data-pipeline`).

---

## 🏗️ Architecture dans Kubernetes

```
                  [ Cluster Kubernetes ]
┌───────────────────────────────────────────────────────────┐
│                                                           │
│  [ Namespace : production ]      [ Namespace : staging ]  │
│  ┌───────────────────────┐       ┌───────────────────────┐│
│  │ Pods Web & Microserv. │       │ Pods de Recette / CI  ││
│  └───────────┬───────────┘       └───────────┬───────────┘│
│              │                               │            │
│              ▼                               ▼            │
│  ┌─────────────────────────────────────────────────────┐  │
│  │          Sonde eBPF Kepler (DaemonSet K8s)          │  │
│  │ Attribue les cycles CPU & Joules à chaque Namespace │  │
│  └──────────────────────────┬──────────────────────────┘  │
│                             │                             │
│                             ▼                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │            Aegis Node Agent (DaemonSet)             │  │
│  │ Transmet la télémétrie vers le Cockpit Centralisé  │  │
│  └──────────────────────────┬──────────────────────────┘  │
│                             │                             │
└─────────────────────────────┼─────────────────────────────┘
                              │ (HTTPS / mTLS)
                              ▼
        [ Cockpit Centralisé Aegis : Reporting ESG ]
        - Namespace 'production' : 142 W (68% de l'empreinte)
        - Namespace 'staging'    : 38 W  (18% de l'empreinte)
```

---

## 🚀 Méthode 1 : Déploiement 1-Clic via Script (Recommandé)

Sur votre poste configuré avec `kubectl` pointant vers votre cluster :

```bash
curl -sSL https://aegis.aivo.fr/install.sh | bash -s -- --profile k8s
```

Le script vérifie la présence de `kubectl` et `helm`, prépare le Chart officiel et déploie le DaemonSet Kepler ainsi que la passerelle Ingress dans le namespace `aegis-system`.

---

## 🛠️ Méthode 2 : Déploiement Manuel via Helm

### 1. Cloner ou ajouter le Chart Helm

Depuis le dépôt cloné :
```bash
helm upgrade --install aegis ./deploy/kubernetes/helm/aegis \
  --namespace aegis-system \
  --create-namespace
```

Ou en ajoutant le dépôt de charts officiel :
```bash
helm repo add aivo https://charts.aivo.fr
helm repo update
```

### 2. Personnaliser votre fichier de valeurs (`values.yaml`)

Créez un fichier `aegis-k8s-values.yaml` pour configurer l'attribution par Namespace :

```yaml
# =============================================================================
# AEGIS KUBERNETES CONFIGURATION — ATTRIBUTION PAR NAMESPACE
# =============================================================================
identity:
  tenantId: "00000000-0000-0000-0000-000000000001"
  clusterName: "k8s-production-eu-west"
  controlPlaneUrl: "https://aegis.votre-entreprise.fr"
  enrollToken: "aegis_tok_live_votre_token"

# 1. ATTRIBUTION ÉNERGÉTIQUE PAR NAMESPACE (KEPLER eBPF)
energy:
  enabled: true
  kepler:
    installDaemonSet: true # Déploie la sonde eBPF Kepler sur chaque nœud
    scrapeInterval: "5s"
  
  # Liste des namespaces à surveiller et ventiler
  namespaces:
    - name: "production"
      slaThresholdWatts: 150.0
    - name: "staging"
      slaThresholdWatts: 50.0
    - name: "monitoring"
      slaThresholdWatts: 30.0

# 2. SÉCURITÉ INGRESS & EGRESS CLUSTER
security:
  ingressWaf:
    enabled: true
    mode: "block" # "block" pour bloquer les attaques OWASP, "monitor_only" pour audit passif
  egressCoreDns:
    enabled: true
    sinkholeC2: true
```

### 3. Appliquer la configuration
```bash
helm upgrade --install aegis aivo/aegis -f aegis-k8s-values.yaml -n aegis-system --create-namespace
```

---

## ⚡ Comment Fonctionne l'Attribution par Namespace ?

Dans un environnement partagé, un nœud worker physique (ex: un serveur de 64 cœurs) exécute simultanément des pods issus de différents namespaces.

1. **Capture eBPF des compteurs matériels** :
   La sonde Kepler injecte un programme eBPF dans le noyau Linux du nœud worker qui trace les instructions processeur exécutées pour chaque groupe de contrôle (`cgroup`) de conteneur.
2. **Ventilation proportionnelle de la puissance** :
   Si le nœud physique consomme 180 Watts (mesurés via RAPL) et que les pods du namespace `production` utilisent 60% des cycles d'horloge CPU, Kepler alloue exactement `180 x 0.60 = 108 Watts` au namespace `production`.
3. **Conversion Carbone en Temps Réel** :
   Aegis croise ces Watts avec l'intensité carbone du réseau électrique de la région (fournie par RTE EcoWatt en France) pour générer l'empreinte en grammes de CO2e par heure :
   $$\text{gCO2e} = \text{Puissance (kW)} \times \text{PUE Datacenter} \times \text{Facteur d'émission (gCO2e/kWh)}$$

---

## 📊 Visualisation dans le Cockpit Aegis

Dès le déploiement du Helm Chart :
1. Les différents **Namespaces** apparaissent dans la section **Aegis Green** du Cockpit.
2. Un graphique empilé affiche la répartition en direct :
   * 🟢 `production` : 112.5 W (Conforme)
   * 🟡 `staging` : 45.0 W (Dépassement du seuil de sobriété RGESN)
3. Vous pouvez télécharger l'**Attestation Officielle VS (EFRAG)** ventilée par projet pour vos audits CSRD et rapports ESG.
