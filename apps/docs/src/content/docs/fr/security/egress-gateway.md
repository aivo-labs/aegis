---
title: Passerelle Egress (CoreDNS, Nimble 9B & Anti-Exfiltration)
description: Filtrage sortant souverain, neutralisation des flux C2, détection algorithmique DGA, protection des agents IA et client d'inférence System One.
---

La passerelle **Aegis Egress** (`apps/egress-gateway`) sécurise le périmètre sortant du système d'information. Alors que la majorité des architectures de sécurité se limitent à surveiller les entrées (Ingress), Aegis Egress empêche les malwares, ransomwares, implants malveillants et **agents IA autonomes compromis** d'exfiltrer des secrets industriels ou d'établir des canaux de commande et contrôle (C2) vers l'extérieur.

---

## 🧠 Schéma d'Architecture Egress & Pipeline en 2 Niveaux

```
    [ Conteneurs Applicatifs / Scripts / Agents IA Autonomes ]
                                │
                                ▼
    [ Requête DNS Sortante (Port 5053/udp & 5053/tcp) ]
                                │
                                ▼
    ┌───────────────────────────────────────────────────────────────┐
    │          NIVEAU 1 : CACHE CTI LOCAL EN RAM (< 2 ms)           │
    │                                                               │
    │  • Listes CTI Souveraines CERT-FR, ANSSI & CrowdSec           │
    │  • Base en mémoire vive de serveurs C2 & domaines malveillants│
    └───────────────────────────────┬───────────────────────────────┘
                                    │
               Match Blacklist ?    │ Non (Domaine Inconnu)
             ┌──────────────────────┴──────────────────────┐
             │ Oui                                         │
             ▼                                             ▼
    [ SINKHOLE 0.0.0.0 ]           ┌───────────────────────────────────────┐
    (Blocage Immédiat)             │ NIVEAU 2 : SYSTEM ONE (NIMBLE 9B)     │
    • Émission alerte critique     │                                       │
    • Zéro fuite de données        │ • Calcul d'Entropie de Shannon (H)    │
                                   │ • Détection DGA (Algorithmes Générés) │
                                   │ • Inférence locale SLM Nimble 9B      │
                                   │ • Analyse de réputation TLD suspect   │
                                   └───────────────────┬───────────────────┘
                                                       │
                                        ┌──────────────┴──────────────┐
                                        ▼                             ▼
                                [ VERDICT : BLOCK ]           [ VERDICT : ALLOW ]
                                • Résolution 0.0.0.0          • Résolveur Récursif
                                • Alerte Cockpit SOC          • Connexion Autorisée
```

---

## 🛡️ Les Vecteurs de Menaces Neutralisés

### 1. Canaux C2 & Reverse Shells
Lorsqu'un serveur ou un conteneur est compromis par un exploit, la première action de l'attaquant consiste à établir une liaison sortante (Reverse Shell) vers un serveur de commande et contrôle (C2). Aegis Egress intercepte la résolution de nom et la neutralise instantanément en renvoyant l'adresse `0.0.0.0` (*DNS Sinkholing*), privant l'attaquant de toute connectivité.

### 2. Algorithmes DGA (Domain Generation Algorithms)
Les souches avancées de rançongiciels génèrent dynamiquement des centaines de noms de domaine éphémères pseudo-aléatoires (ex: `xq89f72b91c0a1.biz`) pour échapper aux listes de blocage statiques :
* Le filtre d'**entropie de Shannon** calcule le désordre informationnel du nom de domaine.
* Une valeur supérieure à **3,80** combinée à une concentration inhabituelle de consonnes déclenche la mise en quarantaine immédiate du domaine.

### 3. Exfiltration de Données par Tunneling DNS
Les techniques de fuite par sous-domaines (ex: `BASE64_DATA.attacker-controlled-server.com`) exploitent le fait que les pare-feu autorisent généralement le port UDP 53. Aegis Egress inspecte la longueur des labels de sous-domaines, la fréquence des requêtes et l'entropie cumulée pour couper le canal avant la fin du transfert.

### 4. Protection Spécifique des Agents IA & Modèles LLM
L'émergence des agents d'intelligence artificielle autonomes (outils de code, agents d'automatisation, frameworks multi-agents) introduit de nouvelles vulnérabilités critiques :
* **Exfiltration par Injection Indirecte de Prompt** : Un pirate force un agent IA à lire une page web piégée qui lui ordonne d'exfiltrer les clés d'API vers un serveur tiers via une requête web ou une balise Markdown image.
* **Appels d'outils incontrôlés (*Rogue Tool Calls*)** : Aegis Egress restreint strictement les destinations sortantes des conteneurs d'agents aux seuls domaines d'API validés (Zero-Trust Egress Policy).

---

## ⚡ Inférence Frugale Locale : Modèle Nimble 9B

Pour analyser les domaines inconnus sans transférer les métadonnées de l'entreprise vers des API tierces étrangères, Aegis intègre le modèle compact **Nimble 9B** :
* **Auto-hébergement souverain** : Exécuté localement via le conteneur `ollama-nimble` inclus dans la composition Docker.
* **Aucune dépendance cloud** : Les requêtes ne sortent jamais du serveur hôte, garantissant la conformité stricte avec les exigences de souveraineté des données de l'ANSSI.
* **Inférence rapide** : Décision en moins de 50 ms grâce à un arbre de décision optimisé et un cache LRU en mémoire.

---

## 💻 Test en Ligne de Commande & Validation

Vous pouvez éprouver directement la passerelle Egress en interrogeant son port DNS local (`5053`) avec la commande `dig` :

```bash
# Test 1 : Domaine C2 connu (Niveau 1 CTI CrowdSec) -> Bloqué (0.0.0.0)
dig @localhost -p 5053 c2-beacon.random-domain.top

# Résultat attendu :
# ;; ANSWER SECTION:
# c2-beacon.random-domain.top. 60 IN A 0.0.0.0

# Test 2 : Domaine DGA haute entropie (Niveau 2 Nimble 9B) -> Quarantaine / Bloqué
dig @localhost -p 5053 a8f93bc01d9f4e2a.xyz

# Test 3 : Domaine légitime certifié -> Résolution normale
dig @localhost -p 5053 api.ecowatt.rte-france.com
```

Chaque blocage génère un événement de télémétrie consultable en direct dans l'onglet **Triage & Événements** du Cockpit Aegis.

---

## 📚 Articles & Références Techniques AIVO

Pour approfondir les mécanismes mathématiques et architecturaux du filtrage sortant :

* 📖 [**Entropie de Shannon & Décision Zero-Trust : L'IA Frugale au service du WAF**](https://aivo.fr/blog/entropie-shannon-decision-zero-trust-ia-frugale) — Explication détaillée des seuils mathématiques appliqués aux domaines DGA et aux vecteurs d'exfiltration.
* 📖 [**Anatomie d'un VPS sous assaut continu : Scanners, Énergie et Réponses Actives**](https://aivo.fr/blog/anatomie-vps-sous-assaut-continu-scanners-energie) — Mesures empiriques des tentatives de rebond et d'exfiltration sur nos infrastructures de test.
* 🔬 [**Étude de cas Aegis Sovereign Gate sur AIVO.fr**](https://aivo.fr/realisations/aegis-sovereign-gate) — Présentation de la vision globale de souveraineté numérique et de cyberdéfense pour les PME et ETI.
