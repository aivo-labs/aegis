# ⎈ Aegis — Déploiement Kubernetes & Attribution Énergétique par Namespace

Ce dossier contient les ressources prêtes pour la production afin de déployer le **Bouclier Souverain Aegis** sur tout cluster Kubernetes (EKS, GKE, AKS, Scaleway Kapsule, OVHcloud Managed Kubernetes ou Bare-Metal k3s/RKE2).

---

## ⚡ Pourquoi Aegis sur Kubernetes ?

1. **Attribution Énergétique Granulaire par Namespace** : Grâce à eBPF et à la sonde Kepler (`quay.io/sustainable_computing_io/kepler`), Aegis mesure les Joules et Watts consommés individuellement par chaque pod et namespace (`production`, `staging`, `monitoring`), générant un audit ESG conforme à la norme **VS EFRAG**.
2. **Protection Zero-Trust Ingress (PEP WAF)** : Filtrage applicatif haute performance des scanners automatisés (Nuclei, Nikto, sqlmap), des injections SQL et des tentatives de RCE.
3. **Contrôle Egress & CoreDNS Sinkhole** : Blocage DNS instantané des tentatives d'exfiltration vers des C2 ou des serveurs de ransomware.

---

## 🚀 Option 1 : Déploiement Helm (Recommandé)

### 1. Prérequis
- Un cluster Kubernetes `>= 1.26` avec support eBPF (noyau Linux `>= 5.4`).
- `helm` v3 installé localement.

### 2. Configuration des valeurs
Éditez le fichier [`helm/aegis/values.yaml`](./helm/aegis/values.yaml) ou surchargez les variables via la ligne de commande :

```bash
# Déploiement avec Helm dans le namespace aegis-system
helm upgrade --install aegis ./deploy/kubernetes/helm/aegis \
  --namespace aegis-system \
  --create-namespace \
  --set global.tenantId="VOTRE_TENANT_UUID" \
  --set global.clusterName="mon-cluster-prod" \
  --set global.controlPlaneUrl="https://aegis.aivo.fr"
```

---

## 📦 Option 2 : Déploiement via Manifestes Bruts (kubectl)

Pour les équipes GitOps (ArgoCD, FluxCD) ou déploiements directs :

```bash
# 1. Création du Namespace
kubectl apply -f deploy/kubernetes/manifests/00-namespace.yaml

# 2. Configuration générale (Tenant ID, URL du Control Plane)
kubectl apply -f deploy/kubernetes/manifests/01-configmap.yaml

# 3. Sonde Énergétique Kepler eBPF & Attribution par Namespace
kubectl apply -f deploy/kubernetes/manifests/02-telemetry-kepler-daemonset.yaml

# 4. Passerelle Ingress PEP (WAF)
kubectl apply -f deploy/kubernetes/manifests/03-ingress-waf-service.yaml

# 5. Passerelle Egress (CoreDNS Sinkhole)
kubectl apply -f deploy/kubernetes/manifests/04-egress-sinkhole.yaml
```

---

## 🔍 Vérification & Télémétrie en Direct

### Vérifier l'état des Pods
```bash
kubectl get pods -n aegis-system -o wide
```
Vous devriez observer :
- Un pod `aegis-telemetry-kepler` par nœud (DaemonSet).
- Deux pods `aegis-gate-proxy` (Ingress PEP).
- Un pod `aegis-egress-forwarder` (CoreDNS Egress).

### Vérifier l'attribution énergétique par Namespace
Affichez les logs du collecteur Aegis sur un nœud :
```bash
kubectl logs -n aegis-system -l app.kubernetes.io/name=aegis-telemetry -c aegis-energy-forwarder --tail=20
```

Vous visualiserez l'agrégation en temps réel des Joules consommés par namespace, automatiquement transmise au Control Plane Aegis pour le Cockpit ESG.
