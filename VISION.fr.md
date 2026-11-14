# 🧭 Aegis Sovereign Gate — Vision & Principes d'Ingénierie

<p align="center">
  <a href="VISION.md">English</a> | <strong>Français</strong>
</p>

## 1. Pourquoi Aegis Existe : Notre Mission

La cybersécurité moderne et la gouvernance de l'intelligence artificielle souffrent d'un triple paradoxe :
1. **Une complexité et un coût prohibitifs** : Les solutions de sécurité d'entreprise (WAF d'hyperscalers, SOC managés, guardrails IA sur clusters GPU, EDR lourds) sont conçues et tarifées pour les grands groupes disposant d'équipes SecOps dédiées. Les TPE, PME, ETI, éditeurs SaaS indépendants et collectivités subissent une double peine : payer une « taxe SaaS » punitive par utilisateur ou laisser leurs serveurs exposés.
2. **Une dépendance technologique et une opacité croissantes** : Confier le déchiffrement de son trafic, le stockage de ses jetons d'identité ou l'inspection de ses prompts IA à des clouds non souverains revient à céder le contrôle cryptographique de son patrimoine informationnel.
3. **Un gaspillage énergétique invisible** : Près de 40 % du trafic mondial provient de scanners de vulnérabilités automatisés, de bots de brute-force et de rafales d'exploits. Laisser ce trafic parasite atteindre les moteurs applicatifs (PHP-FPM, Node.js, Python, JVM) ou les serveurs d'inférence IA gaspille une énergie considérable — tandis que les bilans carbone classiques masquent cette réalité derrière des ratios monétaires fictifs basés sur les factures cloud.

**Aegis Sovereign Gate** a été conçu par **AIVO** pour briser cette impasse :
> **Notre mission est de rendre la cybersécurité Zero-Trust, la souveraineté numérique, le GreenOps vérifiable et la gouvernance de l'IA accessibles à toutes les organisations — déployables en 5 minutes sur un simple VPS ou un cluster Kubernetes, entièrement auditables en open source, et consommant moins de 15 Watts.**

---

## 2. Les 6 Principes Fondateurs d'Ingénierie

Chaque décision d'architecture (`ADR`), chaque Pull Request et chaque verrou de la feuille de route d'Aegis obéit à six principes non négociables :

### Principe n°1 — Les Mathématiques et le Déterminisme avant l'IA
L'intelligence artificielle ne doit jamais être la première ligne de défense lorsqu'une fonction mathématique déterministe résout 95 % du problème en quelques microsecondes.
* Aegis filtre les flux entrants et sortants par **l'entropie d'information de Shannon ($20\ \mu\text{s}$)**, la canonisation multi-passes et le *virtual patching* déterministe (`gate-proxy`) avant de solliciter le moindre modèle de langage.
* **Résultat mesuré** : Lors d'une rafale soutenue d'exploits `CVE-2024-4577` (`PHP2Shell`), Aegis bloque 100 % des requêtes en bordure tout en maintenant le conteneur applicatif cible à **`0 %` de charge CPU** et **`5,81 W` de puissance moyenne** (contre `743,4 %` CPU pic et `24,14 W` sans bouclier). Une attaque bloquée en bordure ne consomme ni cycle CPU applicatif, ni token LLM.

### Principe n°2 — La Physique du Silicium contre le Greenwashing Financier
On ne peut pas optimiser ce que l'on estime à partir d'une facture comptable.
* Aegis rejette les estimations carbone basées sur les dépenses monétaires (`€ dépensés × facteur générique`).
* Notre sonde Rust (`telemetry-agent`) interroge directement les registres matériels des processeurs **Intel/AMD RAPL** (`/sys/class/powercap`) et le noyau Linux via **eBPF (`Kepler`)**, générant des certificats **CSRD / EFRAG Scope 2** vérifiables en Joules, Watts et $\text{gCO}_2\text{eq}$.

### Principe n°3 — Architecture à « 2 Portes » & Zéro Secret Exposé
*« La gouvernance codée dans chaque application n'est de la gouvernance nulle part. »* La sécurité et l'encadrement des agents IA ne doivent pas reposer sur le code interne de chaque service, mais être imposés aux frontières réseau que chaque requête traverse :
```
[ Utilisateur / Webhook / Prompt ]
                │
                ▼
╔══════════════════════════════════════════════════════════╗
║ PORTE 1 — Ingress PEP (gate-proxy)                       ║
║ • Pure BFF OIDC (Zéro JWT dans le JS / AES-256-GCM)      ║
║ • WAF Déterministe, Entropie de Shannon & Guardrails IA  ║
╚══════════════════════════════════════════════════════════╝
                │
                ▼
┌──────────────────────────────────────────────────────────┐
│ Application Métier / Sandbox Agent IA (internal: true)   │
│ • Ne détient AUCUNE vraie clé API (Placeholders dédiés)  │
│ • Confinement noyau Linux éphémère (seccomp / eBPF)      │
└──────────────────────────────────────────────────────────┘
                │
                ▼
╔══════════════════════════════════════════════════════════╗
║ PORTE 2 — Egress Gate (egress-gateway)                   ║
║ • DNS Sinkhole (:5053), Anti-DGA & Blocklist C2          ║
║ • Filtrage d'Outils MCP par Identité & Masquage PII      ║
║ • Injection de Secrets à la volée & Journal AI Act signé ║
╚══════════════════════════════════════════════════════════╝
```
* **Côté Navigateur (Pure BFF)** : Le code JavaScript client ne voit jamais aucun `access_token` ni `refresh_token`.
* **Côté Agent IA (Zero-Secret Placeholders)** : Un agent autonome ne détient jamais les vraies clés d'API tierces ; `egress-gateway` substitue le *placeholder* à la sortie uniquement si l'identité, l'outil MCP et la destination sont autorisés.

### Principe n°4 — Agnosticisme Radical & Souveraineté Open-Core
La brique de sécurité doit s'adapter à l'infrastructure existante de l'entreprise, sans jamais l'enfermer (*Zero Vendor Lock-in*) :
* **Agnostique du Reverse Proxy** : S'intègre nativement derrière **Traefik** (`ForwardAuth`), **Nginx** (`auth_request`), **Caddy**, ou en frontal direct.
* **Agnostique du Fournisseur d'Identité (IdP)** : Compatible **Keycloak**, **Authelia**, **Okta**, **Microsoft Entra ID**, ou en mode autonome intégré.
* **Agnostique de l'Inférence & Air-Gapped** : Fonctionne à 100 % en circuit fermé sans clé API externe, avec support optionnel de modèles locaux via **Ollama** (`Nimble 9B` en v1, évoluant vers des micro-SLM `< 1B` sur CPU).

### Principe n°5 — Résilience Post-Quantique dès la Conception
Les attaquants pratiquent déjà le **« Harvest Now, Decrypt Later » (HNDL — *Récolter maintenant, déchiffrer plus tard*)** : ils enregistrent aujourd'hui les flux TLS chiffrés et les synchronisations `mTLS` pour les déchiffrer dès qu'un calculateur quantique sera disponible.
* Aegis adopte l'échange de clés hybride post-quantique **NIST FIPS 203 (`X25519MLKEM768`)** sur son Control Plane Go et ses sondes Rust, chiffre les sessions avec **`AES-256-GCM`** (résistant à l'algorithme de Grover), et audite la préparation Post-Quantique des domaines protégés.

### Principe n°6 — Pédagogie Actionnable plutôt que Fatigue d'Alertes
Une alerte qui nécessite un expert certifié pour être comprise est une alerte inutile pour une PME.
* Chaque anomalie détectée dans le Cockpit Aegis — en-tête HTTP manquant, certificat TLS vieillissant, version logicielle exposée ou absence d'hybridation Post-Quantique — est accompagnée d'une explication claire et d'un **snippet de configuration prêt à copier-coller** (Nginx, Traefik, PHP, Docker).

---

## 3. Ce qui est Délibérément Hors Périmètre (Non-Goals)

Pour préserver notre empreinte mémoire `< 200 Mo RAM`, notre déploiement en 5 minutes et l'auditabilité du code, Aegis **exclut** volontairement :
1. **L'orchestration et le découpage matériel de fermes GPU (NVIDIA MIG, SUSE AI Factory, vLLM distribué)** : Aegis gouverne et sécurise les flux ; ce n'est pas un ordonnanceur MLOps de clusters GPU.
2. **La virtualisation de machines virtuelles (`KubeVirt`) et les OS immuables propriétaires (`bootc`)** : Aegis reste 100 % agnostique de l'OS hôte Linux et s'exécute aussi bien sur un VPS à 5 €/mois (Docker Compose, Dokploy) que sur Kubernetes.
3. **Les portails développeurs internes type Backstage (`Developer Hub`)** : Le Cockpit Web (`apps/web`) est un **Centre de Contrôle SOC, Posture & GreenOps**, pas un catalogue de *scaffolding* logiciel.
4. **Les microservices de modération IA exigeant des GPU dédiés** : Mobiliser des gigaoctets de VRAM uniquement pour filtrer des requêtes contredit nos principes GreenOps. Aegis privilégie les mathématiques déterministes (`20 µs`) et les micro-modèles frugaux sur CPU (`< 1B`).
