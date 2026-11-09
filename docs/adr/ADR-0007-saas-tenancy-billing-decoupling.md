# ADR-0007 : Modèle de Tenancy & Découplage de la Facturation SaaS (Aegis Core vs Aegis Cloud)

* **Statut** : **Accepté**
* **Date** : 2026-11-09
* **Décideurs** : Équipe Architecture Aegis & Aivo Labs
* **Périmètre** : `Aegis` (Dépôt Open-Core), `aegis-cloud` (Dépôt Privé Commercial), Stripe, Multi-Tenancy

---

## 1. Contexte & Problématique

L'écosystème commercial d'Aivo doit répondre à deux besoins complémentaires :
1. **Un Moteur de Sécurité Souverain Opposable (`Aegis`)** : Doit pouvoir être déployé sur site (*On-Premise*) ou chez des acteurs sensibles (secteur public, santé, banques) qui exigent une indépendance technologique totale vis-à-vis des tiers américains ou des passerelles de paiement.
2. **Une Offre SaaS Managée (`aegis-cloud`)** : Proposant un onboarding en libre-service avec souscription par carte bancaire via Stripe, facturation récurrente, portail client et provisionnement automatique de comptes locataires (*tenants*).

Intégrer le SDK Stripe ou la logique de paiement directement au sein du moteur de sécurité [`Aegis`](file:///home/andjurka/Work/aivo/Sites/Aegis) violerait le principe de souveraineté, introduirait des dépendances externes inutiles dans le plan de contrôle de sécurité et compliquerait les audits de code ANSSI.

---

## 2. Décision Architecturale

Nous appliquons un **découplage strict entre le Moteur de Sécurité Multi-Tenant (`Aegis`) et le Plan de Contrôle Commercial SaaS (`aegis-cloud`)**.

```mermaid
flowchart TD
    Client["👤 Client / Prospect"] -->|1. Achat Forfait (Stripe Checkout)| Cloud["🏢 Aegis Cloud (SaaS Port 4000)<br/>Dépôt Privé Commercial"]
    Stripe["💳 Stripe Billing API"] -->|2. Webhook: invoice.paid| Cloud
    
    subgraph Découplage Étanche
        Cloud -->|3. Provisioning Tenant & Clé API| DB[("🗄️ Base Multi-Tenant TimescaleDB<br/>Table: tenants & infrastructure_nodes")]
        Cloud -->|4. Webhook Lead / Client| CC["📊 Aivo Control Center<br/>(internal.aivo.fr)"]
    end

    Client -->|5. Accès Cockpit SOC via Keycloak| Aegis["🛡️ Aegis Core (Cockpit & Gate)<br/>Filtrage par tenant_id"]
```

### 2.1 Responsabilités Respectives des Deux Briques

#### A. `Aegis` (Moteur Souverain Open-Core)
* **Agnostique de la facturation** : Ne contient aucune ligne de code relative à Stripe, aux cartes bancaires ou aux plans tarifaires.
* **Modèle Multi-Tenancy Natif** :
  * Chaque ressource (métriques, logs de sécurité, alertes WAF, nœuds) est strictement compartimentée par un champ `tenant_id UUID`.
  * La table `tenants` gère le nom de l'organisation, le statut du compte et les quotas sans s'immiscer dans la provenance du paiement.
* **Sécurité & Télémétrie** : Opérationnel 100% hors-ligne (*Air-Gapped*) ou autonome sur n'importe quel VPS européen.

#### B. `aegis-cloud` (Plan de Contrôle SaaS Privé)
* **Gestion du cycle de vie commercial** :
  * Intégration du SDK Stripe (`stripe.checkout.sessions.create`, `stripe.billingPortal.sessions.create`).
  * Réception et vérification cryptographique des webhooks Stripe (`stripe-signature`).
* **Provisionnement Automatisé** :
  * À la réception d'un événement `customer.subscription.created` ou `checkout.session.completed`, `aegis-cloud` génère un nouveau `tenant_id`, crée l'organisation en base et émet les clés d'API.
* **Synchronisation CRM / Centre de Contrôle Aivo** :
  * Envoi d'un webhook structuré vers `https://internal.aivo.fr/api/v1/aegis/leads` pour le suivi commercial et le support client.

---

## 3. Conséquences

### 3.1 Avantages (Positifs)
* **Souveraineté & Audits Préservés** : Le code du moteur de sécurité reste compact, auditable et exempt de traceurs ou SDKs tiers.
* **Résilience Maximale** : Une panne ou indisponibilité du service Stripe n'affecte en rien le filtrage WAF, le sinkhole DNS ni la collecte de télémétrie sur les serveurs déjà déployés.
* **Flexibilité Commerciale** : Les modèles de tarification (Starter, Pro, Enterprise, Annuel) peuvent évoluer dans `aegis-cloud` sans nécessiter de redéploiement du moteur de sécurité.

### 3.2 Points d'Attention
* La communication entre `aegis-cloud` et la base de données s'effectue via le réseau interne Docker sécurisé `dokploy-network`.
