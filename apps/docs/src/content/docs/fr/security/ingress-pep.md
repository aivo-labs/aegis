---
title: Passerelle Ingress PEP (WAF & Scanners)
description: Fonctionnement de l'interception in-line des attaques web, de la détection OWASP Top 10 et du blocage des scanners.
---

La passerelle **Aegis Gate PEP (Policy Enforcement Point)** est le bouclier réseau frontal d'Aegis (`apps/gate-proxy`). Déployée en coupure réseau sur le port `8000`, elle inspecte chaque paquet entrant avant qu'il n'atteigne vos serveurs applicatifs.

## 🛡️ Règles d'Interception In-Line (< 1.5 ms)

Aegis Gate évalue instantanément chaque requête HTTP/HTTPS contre une série de filtres durcis :

### 1. Scanners de Vulnérabilités & Outils de Pentest
Les attaques automatisées sont immédiatement démasquées par l'analyse des signatures d'outils de cartographie offensive :
* **Outils bloqués** : `Nikto`, `SQLmap`, `Nuclei`, `Gobuster`, `Dirbuster`, `Nmap`, `Masscan`, `WPScan`, `Acunetix`, `Nessus`, `Hydra`.
* **Action** : Code `HTTP 403 Forbidden` immédiat sans transmission à l'application.

### 2. Injections SQL (SQLi)
* Détection de tentatives d'exfiltration de base de données : `UNION SELECT`, `' OR 1=1`, `benchmark()`, `sleep()`, exploration de la table `information_schema`.
* **Sévérité** : `CRITICAL` (Score de risque : 98/100).

### 3. Path Traversal & Inclusion Locale (LFI)
* Détection de tentatives de fuite de fichiers système : `../../../../etc/passwd`, `/etc/shadow`, `.env`, `.git/HEAD`.
* **Sévérité** : `HIGH` (Score de risque : 90/100).

### 4. Injection de Commandes Système (RCE)
* Détection de chaînes d'exécution shell non sollicitées : `; cat`, `| id`, `$(whoami)`, `curl http`, `/bin/sh`.
* **Sévérité** : `CRITICAL` (Score de risque : 99/100).

### 5. Cross-Site Scripting (XSS)
* Détection de balises malicieuses et de gestionnaires d'événements : `<script>`, `javascript:`, `onerror=`, `onload=`, `alert()`.
* **Sévérité** : `MEDIUM` (Score de risque : 75/100).

---

## 📡 Télémétrie d'Audit Ingress

Dès qu'une attaque est bloquée ou qu'un flux sain est validé, Aegis Gate transmet une charge utile au format JSON vers le backend Symfony (`/api/v1/gate/telemetry/ingress`) :

```json
{
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "client_ip": "185.220.101.5",
  "user_agent": "Mozilla/5.00 (Nikto/2.1.6)",
  "http_method": "GET",
  "request_uri": "/admin/setup.php",
  "decision": "BLOCK",
  "http_status_returned": 403,
  "latency_ms": 1.2,
  "metadata": {
    "threat_type": "PENTEST_SCANNER_DETECTED",
    "severity": "HIGH",
    "risk_score": 92,
    "engine": "Aegis Gate PEP (OWASP CRS)"
  }
}
```

L'événement apparaît instantanément dans la colonne correspondante du **Triage Kanban** du Cockpit.
