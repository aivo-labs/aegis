---
title: Agent Client Seul (Script 1-Clic)
description: Comment enrôler un serveur externe existant (Ubuntu, Debian) sans déployer la suite complète.
---

Ce mode est idéal pour les clients qui disposent déjà d'un serveur applicatif (ex: LAMP, Node.js, conteneurs existants) et souhaitent simplement bénéficier de la **télémétrie énergétique souveraine** et du **contrôle des flux sortants** sans perturber leur infrastructure.

## ⚡ Procédure d'Enrôlement en 15 Secondes

### Étape 1 : Obtenir votre Jeton d'Enrôlement
1. Ouvrez votre Cockpit Aegis : `http://<IP_AEGIS>:4321/app`.
2. Cliquez sur le bouton en haut à droite : **`⚡ + Connecter un VPS`**.
3. Saisissez le nom de la machine (ex: `vps-client-prod`).
4. Le Cockpit génère instantanément la commande personnalisée avec votre jeton sécurisé.

### Étape 2 : Exécuter le Script sur le Serveur Client

Dans le terminal SSH de la machine distante, exécutez la commande avec les privilèges root :

```bash
curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- \
  --profile agent \
  --token aegis_tok_live_votre_token \
  --endpoint http://<IP_VOTRE_COCKPIT>:8080 \
  --server-id vps-client-prod
```

> [!NOTE]
> Vous pouvez également télécharger le script directement depuis votre passerelle Aegis locale :
> `curl -sSL http://<IP_VOTRE_COCKPIT>:8080/install.sh | sudo bash -s -- --profile agent ...`

### Étape 3 : Validation Instantanée

Le script :
1. Détecte le type d'infrastructure (registres matériels Intel/AMD RAPL ou VM Cloud KVM/QEMU).
2. Configure `/etc/aegis/agent.env`.
3. Installe et démarre le service systemd autonome `aegis-agent.service` (< 15 Mo de RAM, 0% CPU au repos).
4. Émet un premier ping vers votre Control Plane Aegis.

La modale sur votre écran bascule automatiquement au vert avec la mention :
> **✅ Serveur connecté avec succès ! (18.5 W • CPU 12.0%)**

---

## 🛠️ Gestion du Service sur le Client

```bash
# Vérifier l'état du démon de télémétrie
sudo systemctl status aegis-agent

# Consulter les logs de mesure en direct
sudo journalctl -u aegis-agent -f

# Stopper temporairement l'agent
sudo systemctl stop aegis-agent
```
