# Serveur Client de Référence sur Oracle Cloud (« Client Managed » connecté à `aegis.aivo.fr/app`)

Ce dossier contient l'environnement clé en main du **Niveau 1 de l'architecture de démonstration Aegis** : un serveur client externe multi-stack (**Nginx + PHP-FPM 8.3 + Node.js 20**) hébergé sur **Oracle Cloud Infrastructure (OCI)**, protégé en bordure par **Aegis Gate PEP** (`mode: edge`) et **Aegis Egress Gateway**, et remontant toute sa télémétrie en temps réel vers `https://aegis.aivo.fr/app`.

---

## 1. Architecture des 4 Conteneurs sur la VM Oracle Cloud

| Service Docker | Rôle dans la Démo Client / Vidéo | Port Exposé |
| :--- | :--- | :--- |
| `client-target-app` | Application cliente réaliste combinant **Nginx**, **PHP-FPM 8.3** (`/index.php`) et un microservice **Node.js 20** (`/api/node/*`). | Interne `:80` |
| `aegis-gate-edge` | Bouclier **Aegis Gate PEP** en mode `edge`. Intercepte les attaques (`CVE-2024-4577` PHP2Shell, SQLi, Overflow 413) en `< 1ms`, remonte les alertes vers `https://aegis.aivo.fr/api/v1/gate/telemetry/ingress` et synchronise l'état du bouclier toutes les **3 secondes** avec `https://aegis.aivo.fr/api/v1/protection/status`. | `:80` et `:8000` |
| `aegis-egress-edge` | Passerelle **Aegis Egress DNS/HTTP**. Bloque et journalise toute tentative de connexion sortante post-exploitation (C2 / Reverse Shell) vers `https://aegis.aivo.fr/api/v1/gate/telemetry/egress`. | `:5053/udp` & `:5053/tcp` |
| `aegis-telemetry-edge` | Sonde **RAPL & `/proc/stat`** lisant la charge CPU réelle de la VM Oracle Cloud toutes les 3 secondes et l'envoyant vers `https://aegis.aivo.fr/api/v1/gate/telemetry/energy` sous le nœud `oci-managed-client-01` (`Oracle Cloud (OCI)`). | — |

---

## 2. Prérequis Réseau Oracle Cloud (Console OCI)

Dans la console Oracle Cloud de votre instance VM :
1. Ouvrez **Virtual Cloud Networks (VCN)** → votre sous-réseau → **Security Lists** → **Ingress Rules**.
2. Ajoutez une règle autorisant **Source CIDR `0.0.0.0/0`**, protocole **TCP**, ports de destination **`80, 443, 8000`**.
*(Le pare-feu interne Ubuntu `iptables` de la VM est configuré automatiquement par le script `setup-oci-vm.sh`).*

---

## 3. Déploiement en 1 Commande sur la VM Oracle Cloud

Connectez-vous en SSH sur votre VM Oracle Cloud, clonez le dépôt (ou mettez-le à jour sur `develop`), puis lancez :

```bash
git clone -b develop https://github.com/aivo-labs/Aegis.git
cd Aegis/deploy/oci-managed-demo
sudo ./setup-oci-vm.sh
```

Vous pouvez également personnaliser le nom du serveur tel qu'il apparaît dans la modale **« + Enrôler un Serveur »** de `aegis.aivo.fr/app` :

```bash
sudo AEGIS_SERVER_ID="oci-managed-client-01" \
     AEGIS_ENROLL_TOKEN="ag_live_votre_token" \
     ./setup-oci-vm.sh
```

Dès le lancement :
- La modale d'enrôlement sur `https://aegis.aivo.fr/app` passe au vert : **`✓ Serveur connecté avec succès !`**.
- Le nœud **`oci-managed-client-01`** (`Oracle Cloud (OCI)`) apparaît dans le sélecteur de nœuds et dans l'onglet **RAPL Telemetry**.

---

## 4. Scénario de Démonstration Client & Vidéo Comparatif Charge CPU (Avec vs Sans Bouclier)

Depuis votre poste (ou directement depuis la VM Oracle Cloud), utilisez `run-live-attack-demo.sh` :

### A. Démo complète en rendez-vous client (PHP2Shell + SQLi + Overflow 413 + Rafale CPU)
```bash
./run-live-attack-demo.sh http://<IP_PUBLIQUE_ORACLE>:8000
```

### B. Vidéo Comparatif Charge CPU & Watts (« Avec Bouclier » vs « Sans Bouclier »)

1. **Phase 1 — Bouclier ACTIF (par défaut sur `aegis.aivo.fr/app`)** :
   Lancez une rafale soutenue de 180 attaques PHP2Shell (`CVE-2024-4577`) :
   ```bash
   ./run-live-attack-demo.sh http://<IP_PUBLIQUE_ORACLE>:8000 stress 30 6
   ```
   - **Résultat** : 100% des requêtes sont bloquées en bordure par `aegis-gate-edge` (`HTTP 403` en `< 1ms`).
   - PHP-FPM et Node.js ne sont jamais sollicités : la charge CPU de la VM Oracle reste stable autour de **3% à 5%** (~11W).

2. **Phase 2 — Bouclier DÉSACTIVÉ en direct depuis `aegis.aivo.fr/app`** :
   Dans le Cockpit `https://aegis.aivo.fr/app`, cliquez sur le bouton **Bouclier Actif → Désactiver** (la VM Oracle se synchronise automatiquement en moins de 3 secondes).
   Relancez exactement la même rafale :
   ```bash
   ./run-live-attack-demo.sh http://<IP_PUBLIQUE_ORACLE>:8000 stress 30 6
   ```
   - **Résultat** : Les requêtes traversent jusqu'à PHP-FPM 8.3 et Node.js (`HTTP 200`), déclenchent des alertes critiques `[NON BLOQUÉ]` + tentatives d'exfiltration DNS C2 (`c2-php2shell-beacon.evil-botnet.ru` dans l'onglet **Egress**), et font bondir la **charge CPU (60%–95%) et les Watts** en direct sur le graphique **RAPL Telemetry** de `aegis.aivo.fr/app` !
