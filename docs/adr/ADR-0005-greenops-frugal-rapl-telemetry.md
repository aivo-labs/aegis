# ADR-0005 : Télémétrie Frugale GreenOps & Nœud Souverain Consolidé (RAPL/Scaphandre)

* **Statut** : **Accepté**
* **Date** : 2026-11-09
* **Décideurs** : Équipe Architecture Aegis & Aivo Labs
* **Périmètre** : `apps/telemetry-agent`, `apps/backend`, Cockpit GreenOps

---

## 1. Contexte & Problématique

La directive européenne **CSRD (Corporate Sustainability Due Diligence)** et les exigences ESG imposent aux organisations de mesurer et justifier l'empreinte environnementale de leur système d'information (Scope 2 pour l'électricité, empreinte hydrique pour le refroidissement des centres de données).

La plupart des solutions de monitoring existantes reposent sur des calculs théoriques forfaitaires basés sur le nombre de vCPU alloués par les fournisseurs cloud. Ces estimations s'avèrent imprécises et décorrélées de l'activité réelle du processeur.

Par ailleurs, dans un environnement conteneurisé (Docker / Dokploy), l'agent de télémétrie s'exécute lui-même dans un conteneur éphémère doté d'un identifiant hexadécimal dynamique (ex: `ac86425634ac`). Si cet identifiant n'est pas consolidé, il fragmente l'historique et génère des nœuds dupliqués dans le tableau de bord SOC.

---

## 2. Décision Architecturale

Nous adoptons une **mesure physique directe et opposable** couplée à une **politique de consolidation sous un nœud souverain unique**.

### 2.1 Mesure Physique Directe Linux RAPL / MSR

L'agent Rust [`apps/telemetry-agent`](../../apps/telemetry-agent) (inspiré de Scaphandre) accède directement aux registres matériels du microprocesseur :
* `/sys/class/powercap/intel-rapl` : Mesure en microjoules de la puissance réelle absorbée par les cœurs CPU et les barrettes de mémoire vive (RAM).
* `/host/proc/stat` : Lecture précise des cycles CPU système et utilisateur pour calculer le pourcentage de charge réel.
* Périodicité d'échantillonnage : **5 secondes**.

### 2.2 Règle du Nœud Souverain Consolidé (`aegis-sovereign-node`)

Pour éviter toute fragmentation d'historique et garantir une continuité temporelle parfaite :
1. **Identité Immuable du Serveur** :
   Dans les configurations Docker Compose, le conteneur de télémétrie reçoit explicitement :
   ```yaml
   hostname: "aegis-sovereign-node"
   environment:
     AEGIS_SERVER_ID: "aegis-sovereign-node"
   ```
2. **Normalisation à l'Ingestion Backend** :
   L'API Go (`telemetry_handler.go`) vérifie chaque payload entrant. Tout hostname correspondant à un identifiant hexadécimal de conteneur Docker (12 caractères hexadécimaux) ou au nom générique `vps-main-01` est automatiquement réécrit en `aegis-sovereign-node`.
3. **Migration Automatique en Base de Données** :
   Au démarrage, le schéma SQL ([`schema.go`](../../apps/backend/internal/database/schema.go)) purge les nœuds éphémères orphelins et rattache l'ensemble des métriques d'énergie au nœud souverain unique (`00000000-0000-0000-0000-000000000002`).

### 2.3 Référentiels Écologiques Normalisés

* **Intensité Carbone Électrique** : `52.0 gCO₂eq / kWh` (mix électrique du réseau français, base ADEME / RTE).
* **Empreinte Hydrique des Datacenters (Water Footprint)** : `1.50 L / kWh` (norme Boavizta / ADEME combinant le refroidissement évaporatif et le cycle thermique des centrales électriques).
* **Indice d'Efficacité Énergétique (PUE)** : `1.15` (standard datacenter souverain optimisé OVHcloud / Scaleway).

---

## 3. Conséquences

### 3.1 Avantages (Positifs)
* **Chiffres RSE Incontestables & Opposables** : Les rapports d'export CSV (`Export RSE`) sont adossés à des mesures matérielles réelles et non à des extrapolations.
* **Historique Unique et Cohérent** : Fin des doublons de serveurs dans le Cockpit SOC ; les métriques cumulées (kWh, litres d'eau, gCO₂) s'incrémentent de façon stable sur 1h, 24h, 7j, 30j et 1 an.
* **Frugalité** : L'agent Rust consomme moins de 0.05% de CPU et moins de 15 Mo de RAM.

### 3.2 Prérequis Techniques
* Le conteneur Docker nécessite le montage en lecture seule `/proc` et `/sys` de l'hôte avec le flag `pid: "host"`.
