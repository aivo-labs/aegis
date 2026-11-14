---
title: Kubernetes (K8s) Deployment & Namespace Attribution
description: Secure a Kubernetes cluster and attribute electrical power consumption (Watts and gCO2e) by Namespace with Kepler eBPF.
---

Deploying Aegis on **Kubernetes** addresses a core challenge in containerized architectures: **how can you determine which application is consuming what share of energy when dozens of workloads share the same node pool?**

Through the native integration of **Kepler (CNCF)** and the official Aegis Helm Chart, you can track real-time power draw in Watts and carbon impact in gCO2e broken down by **Namespace** (e.g. `production`, `staging`, `data-pipeline`).

---

## 🏗️ Kubernetes Architecture Overview

```
                   [ Kubernetes Cluster ]
┌───────────────────────────────────────────────────────────┐
│                                                           │
│  [ Namespace: production ]        [ Namespace: staging ]  │
│  ┌───────────────────────┐       ┌───────────────────────┐│
│  │ Web & Microservices   │       │ Staging / CI Runners  ││
│  └───────────┬───────────┘       └───────────┬───────────┘│
│              │                               │            │
│              ▼                               ▼            │
│  ┌─────────────────────────────────────────────────────┐  │
│  │           Kepler eBPF Probe (K8s DaemonSet)         │  │
│  │ Attributes CPU cycles & Joules to each cgroup       │  │
│  └──────────────────────────┬──────────────────────────┘  │
│                             │                             │
│                             ▼                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │             Aegis Node Agent (DaemonSet)            │  │
│  │ Relays telemetry to Centralized Cockpit via mTLS   │  │
│  └──────────────────────────┬──────────────────────────┘  │
│                             │                             │
└─────────────────────────────┼─────────────────────────────┘
                              │ (HTTPS / mTLS)
                              ▼
        [ Centralized Aegis Cockpit: ESG Reporting ]
        - Namespace 'production' : 142 W (68% of total footprint)
        - Namespace 'staging'    : 38 W  (18% of total footprint)
```

---

## 🚀 Method 1: 1-Click Script Deployment (Recommended)

On your management machine with `kubectl` configured:

```bash
curl -sSL https://aegis.aivo.fr/install.sh | bash -s -- --profile k8s
```

The script verifies `kubectl` and `helm`, configures the chart, and deploys the Kepler DaemonSet and the Ingress gateway into the `aegis-system` namespace.

---

## 🛠️ Method 2: Manual Helm Deployment

### 1. Clone or add the Helm Chart

From your cloned repository:
```bash
helm upgrade --install aegis ./deploy/kubernetes/helm/aegis \
  --namespace aegis-system \
  --create-namespace
```

Or add the official Helm repository:
```bash
helm repo add aivo https://charts.aivo.fr
helm repo update
```

### 2. Configure your custom values file (`values.yaml`)

Create an `aegis-k8s-values.yaml` file to configure namespace attribution:

```yaml
# =============================================================================
# AEGIS KUBERNETES CONFIGURATION — NAMESPACE ATTRIBUTION
# =============================================================================
identity:
  tenantId: "00000000-0000-0000-0000-000000000001"
  clusterName: "k8s-production-eu-west"
  controlPlaneUrl: "https://aegis.your-company.com"
  enrollToken: "aegis_tok_live_your_token"

# 1. NAMESPACE ENERGY ATTRIBUTION (KEPLER eBPF)
energy:
  enabled: true
  kepler:
    installDaemonSet: true # Deploys Kepler eBPF probe onto every node
    scrapeInterval: "5s"
  
  # List of namespaces to monitor and allocate
  namespaces:
    - name: "production"
      slaThresholdWatts: 150.0
    - name: "staging"
      slaThresholdWatts: 50.0
    - name: "monitoring"
      slaThresholdWatts: 30.0

# 2. CLUSTER INGRESS & EGRESS ZERO-TRUST SECURITY
security:
  ingressWaf:
    enabled: true
    mode: "block" # "block" to mitigate OWASP exploits, "monitor_only" for audit
  egressCoreDns:
    enabled: true
    sinkholeC2: true
```

### 3. Apply the configuration
```bash
helm upgrade --install aegis aivo/aegis -f aegis-k8s-values.yaml -n aegis-system --create-namespace
```

---

## ⚡ How Namespace Attribution Works

In a multi-tenant cluster, a physical 64-core node runs pods originating from multiple distinct namespaces simultaneously.

1. **eBPF Hardware Performance Counter Tracing** :
   The Kepler probe injects eBPF programs into the Linux kernel of each worker node, tracking executed instructions per container control group (`cgroup`).
2. **Proportional Power Allocation** :
   If the physical host is drawing 180 Watts (measured directly via RAPL) and pods in namespace `production` consume 60% of CPU cycles, Kepler allocates precisely `180 x 0.60 = 108 Watts` to the `production` namespace.
3. **Real-Time Carbon Conversion** :
   Aegis combines these Watts with live grid carbon intensity to determine carbon emissions in grams of CO2e per hour:
   $$\text{gCO2e} = \text{Power (kW)} \times \text{Datacenter PUE} \times \text{Grid Emission Factor (gCO2e/kWh)}$$

---

## 📊 Cockpit Visualization

Once the Helm chart is deployed:
1. The configured **Namespaces** automatically appear under the **Aegis Green** section of the Cockpit.
2. A stacked live chart visualizes real-time distribution:
   * 🟢 `production` : 112.5 W (Compliant)
   * 🟡 `staging` : 45.0 W (Exceeding voluntary sobriety threshold)
3. Generate and export official **EFRAG VS audit certificates** by project for corporate ESG and CSRD filings.
