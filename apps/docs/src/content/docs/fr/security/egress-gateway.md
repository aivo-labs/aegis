---
title: Passerelle Egress (CoreDNS & Nimble 9B)
description: Filtrage sortant souverain, détection de C2, algorithmes DGA et client d'inférence System One.
---

La passerelle **Aegis Egress** (`apps/egress-gateway`) sécurise le flux sortant du système d'information. Elle empêche les malwares, ransomwares et agents IA compromis d'exfiltrer des données confidentielles vers l'extérieur.

## 🧠 Pipeline d'Évaluation en 2 Niveaux

Chaque requête DNS sortante traverse un double filtre d'analyse avant d'être résolue :

```
             [ Requête DNS Sortante (Port 5053) ]
                              │
                              ▼
        ┌───────────────────────────────────────────┐
        │   Niveau 1 : Cache CTI Local (< 2 ms)     │
        │   Listes CrowdSec & Flux CERT-FR Souverain │
        └─────────────────────┬─────────────────────┘
                 Match ?      │ Non
               ┌──────────────┴──────────────┐
             Oui                             │
               ▼                             ▼
        [ SINKHOLE 0.0.0.0 ]   ┌───────────────────────────┐
        (Blocage Immédiat)     │ Niveau 2 : IA System One  │
                               │ Entropie Shannon & Nimble │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               [ Verdict BLOCK / ALLOW ]
```

### 1. Niveau 1 : Cache CTI CrowdSec (< 2 ms)
Vérification ultra-rapide en mémoire vive contre une base de données locale d'adresses IP et de noms de domaine C2 (Command & Control) répertoriés par la Cyber Threat Intelligence souveraine.

### 2. Niveau 2 : Entropie de Shannon & Modèle System One (Nimble 9B)
Si le domaine est inconnu des listes noires :
* **Calcul d'Entropie de Shannon** : Les domaines générés par algorithmes (DGA - *Domain Generation Algorithms*) comme `a8f93bc01d9f4e2a.xyz` présentent une entropie mathématique anormalement élevée (> 3.8).
* **Inférence Probabiliste System One** : Le modèle local **Nimble 9B** (hébergé sur le serveur via Ollama sans dépendance américaine) évalue le vecteur d'état et prend une décision `BLOCK`, `QUARANTINE` ou `ALLOW` en moins de 50 ms.

---

## 💻 Test en Ligne de Commande

Vous pouvez tester immédiatement le comportement de la passerelle Egress via l'utilitaire `dig` :

```bash
# Test 1 : C2 connu (Niveau 1 CrowdSec) -> Bloqué
dig @localhost -p 5053 c2-beacon.random-domain.top

# Test 2 : Domaine DGA haute entropie (Niveau 2 Nimble 9B) -> Quarantaine / Bloqué
dig @localhost -p 5053 a8f93bc01d9f4e2a.xyz

# Test 3 : Domaine légitime certifié -> Autorisé
dig @localhost -p 5053 api.ecowatt.rte-france.com
```
