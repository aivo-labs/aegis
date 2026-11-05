---
title: Déploiement Mono-Serveur & VPS
description: Guide de déploiement d'Aegis sur une machine virtuelle Linux (Debian, Ubuntu) via le script 1-clic, Docker Compose ou Dokploy.
---

Ce guide s'adresse aux administrateurs systèmes, CTOs et équipes DevOps souhaitant déployer la suite souveraine Aegis sur un **VPS Cloud** (Scaleway, OVHcloud, Hetzner Cloud, AWS EC2, DigitalOcean).

## 🏗️ Architecture du Déploiement VPS

Sur un VPS, Aegis fonctionne sous forme d'une stack de conteneurs contigus et hautement optimisés :

* **Aegis Gate PEP (:8000)** : Passerelle Ingress Zero-Trust filtrant les attaques en coupure réseau (< 1.5 ms).
* **Aegis Egress Gateway (:5053/udp)** : Résolveur DNS filtrant les fuites de données et communications C2.
* **Aegis Web (:4321)** : Cockpit d'administration, Triage Kanban, radar ESG et cartes GeoIP.
* **Aegis Backend (:8080)** : Moteur d'évaluation Symfony 7 couplé à une base TimescaleDB.
* **Sonde Énergétique** : Analyse de la charge `/proc/stat` et estimation thermodynamique continue en Watts selon le profil processeur de la VM.

---

## ⚡ Méthode 1 : Déploiement 1-Clic via Script (Recommandé)

Sur votre VPS vierge (Debian 12, Ubuntu 22.04 / 24.04), exécutez la commande suivante :

```bash
curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- --profile vps
```

### Ce que fait le script :
1. Vérifie et installe Docker Engine et Docker Compose si nécessaires.
2. Déploie le monorepo dans `/opt/aegis`.
3. Lance l'ensemble des conteneurs via Docker Compose.
4. Active les sondes de surveillance et configure les réseaux isolés.

---

## 🛠️ Méthode 2 : Déploiement Manuel avec Git & Docker Compose

Si vous préférez orchestrer le déploiement manuellement :

```bash
# 1. Cloner le dépôt dans /opt/aegis
sudo git clone https://github.com/aivo-labs/aegis.git /opt/aegis
cd /opt/aegis

# 2. Démarrer la composition complète
sudo docker compose up -d --build
```

Vérifiez le statut des conteneurs :
```bash
sudo docker compose ps
```

---

## 🌐 Configuration du Reverse Proxy & Certificat SSL (HTTPS)

Pour exposer vos services sur vos propres noms de domaine avec chiffrement TLS Let's Encrypt :

### Exemple avec Caddy Server
```nginx
# Cockpit d'administration SOC & ESG (Exemple Caddy / Nginx)
soc.votre-entreprise.fr {
    reverse_proxy localhost:4321
}

# Passerelle WAF Ingress (pour protéger vos APIs)
waf.votre-entreprise.fr {
    reverse_proxy localhost:8000
}
```

### Exemple avec Nginx
```nginx
server {
    server_name soc.votre-entreprise.fr;
    listen 80;

    location / {
        proxy_pass http://127.0.0.1:4321;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## ⚙️ Déploiement via Dokploy / Coolify

Si vous gérez vos VPS avec des interfaces de PaaS open-source comme **Dokploy** ou **Coolify** :

1. Créez un nouveau projet *"Aegis Production"*.
2. Ajoutez un service de type **Docker Compose**.
3. Renseignez la source Git : `https://github.com/aivo-labs/aegis.git` (branche `main`).
4. Indiquez le chemin du fichier : `docker-compose.yml`.
5. Mappez les domaines publics sur le port `4321` (Cockpit) et `8000` (WAF Ingress).

---

## 🧪 Éprouver l'Installation avec le Banc d'Essai

Dès la fin de l'installation, validez que le WAF et le Kanban de triage réagissent correctement :

```bash
cd /opt/aegis
./scripts/run-pentest-demo.sh
```

Consultez [`http://votre-ip:4321/app/triage`](http://votre-ip:4321/app/triage) pour observer le traitement en direct des requêtes suspectes.
