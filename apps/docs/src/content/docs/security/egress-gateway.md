---
title: Egress Gateway (CoreDNS, Nimble 9B & Anti-Exfiltration)
description: Sovereign outbound filtering, C2 command-and-control neutralization, algorithmic DGA detection, AI agent exfiltration protection, and System One inference engine.
---

The **Aegis Egress** gateway (`apps/egress-gateway`) secures the outbound boundary of the information system. While traditional security postures exclusively guard incoming traffic (Ingress), Aegis Egress prevents malwares, ransomware implants, and **compromised autonomous AI agents** from exfiltrating proprietary data or establishing outbound Command & Control (C2) communication channels.

---

## 🧠 Egress Architecture Diagram & 2-Tier Pipeline

```
    [ Application Containers / Shell Scripts / Autonomous AI Agents ]
                                │
                                ▼
    [ Outbound DNS Query (Port 5053/udp & 5053/tcp) ]
                                │
                                ▼
    ┌───────────────────────────────────────────────────────────────┐
    │          TIER 1 : IN-MEMORY CTI LOCAL CACHE (< 2 ms)          │
    │                                                               │
    │  • Sovereign Threat Intelligence feeds (CrowdSec, CERT-FR)    │
    │  • High-speed in-RAM cache of known C2 servers & bad actors   │
    └───────────────────────────────┬───────────────────────────────┘
                                    │
               Blacklist Match ?    │ No (Unknown Domain)
             ┌──────────────────────┴──────────────────────┐
             │ Yes                                         │
             ▼                                             ▼
    [ SINKHOLE 0.0.0.0 ]           ┌───────────────────────────────────────┐
    (Immediate Block)              │ TIER 2 : SYSTEM ONE (NIMBLE 9B)       │
    • Critical alert emitted       │                                       │
    • Zero data exfiltration       │ • Shannon Information Entropy (H)     │
                                   │ • DGA (Domain Generation Algorithms)  │
                                   │ • Local SLM Nimble 9B inference       │
                                   │ • Suspicious TLD reputation scoring   │
                                   └───────────────────┬───────────────────┘
                                                       │
                                        ┌──────────────┴──────────────┐
                                        ▼                             ▼
                                [ VERDICT : BLOCK ]           [ VERDICT : ALLOW ]
                                • Resolved to 0.0.0.0         • Recursive Resolver
                                • Real-time SOC Alert         • Authorized Outbound
```

---

## 🛡️ Neutralized Outbound Threat Vectors

### 1. C2 Beacons & Reverse Shells
When an attacker exploits a server or microservice, their initial move is almost invariably to trigger an outbound connection (Reverse Shell) to an external Command and Control (C2) endpoint. Aegis Egress intercepts the DNS lookup and returns `0.0.0.0` (*DNS Sinkholing*), instantly neutralizing the remote control channel.

### 2. Domain Generation Algorithms (DGA)
Advanced ransomware strains dynamically generate hundreds of pseudo-random, ephemeral domains (e.g., `xq89f72b91c0a1.biz`) to bypass static blacklists:
* The **Shannon entropy filter** computes the informational disorder of the candidate domain string.
* A score exceeding **3.80**, coupled with abnormal consonant clustering, triggers immediate domain quarantine and blocking.

### 3. Data Exfiltration via DNS Tunneling
Attackers frequently bypass perimeter firewalls by encoding secrets into DNS subdomains (e.g., `BASE64_SECRET.attacker-c2.net`), exploiting open UDP port 53. Aegis Egress inspects subdomain label lengths, request frequencies, and cumulative entropy to cut the exfiltration channel before the transfer completes.

### 4. Guardrails for Autonomous AI Agents & LLM Tools
Autonomous AI systems (code agents, multi-agent frameworks, task runners) introduce new attack surfaces:
* **Exfiltration via Indirect Prompt Injection**: Malicious instructions embedded in untrusted web pages can trick an AI agent into transmitting confidential API keys or source code snippets to external URLs.
* **Rogue Tool Calls**: Aegis Egress restricts outbound container traffic strictly to whitelisted APIs, providing a bulletproof sandbox for experimental AI agents.

---

## ⚡ Sovereign Local Inference: Nimble 9B Model

To evaluate unknown domains without leaking proprietary DNS telemetry to foreign cloud providers, Aegis embeds the compact **Nimble 9B** small language model:
* **Fully sovereign & self-hosted**: Runs on-premise or in your private cloud via the bundled `ollama-nimble` container.
* **Zero US cloud dependency**: Data never leaves the host server, maintaining strict compliance with sovereign European data protection standards.
* **Low-latency execution**: Yields verdicts in under 50 ms backed by an in-memory LRU cache.

---

## 💻 Command-Line Verification & Testing

You can verify the Egress gateway's behavior using the `dig` utility targeting the local listener on port `5053`:

```bash
# Test 1: Known C2 domain (Tier 1 CTI Cache) -> Blocked (0.0.0.0)
dig @localhost -p 5053 c2-beacon.random-domain.top

# Expected output:
# ;; ANSWER SECTION:
# c2-beacon.random-domain.top. 60 IN A 0.0.0.0

# Test 2: High-entropy DGA domain (Tier 2 Nimble 9B) -> Quarantined / Blocked
dig @localhost -p 5053 a8f93bc01d9f4e2a.xyz

# Test 3: Legitimate verified service -> Clean recursive resolution
dig @localhost -p 5053 api.ecowatt.rte-france.com
```

All block actions stream real-time events to the Aegis Cockpit **Triage & Incidents** view.

---

## 📚 Articles & Technical References

Explore in-depth articles on outbound filtering and frugal AI on AIVO:

* 📖 [**Shannon Entropy & Zero-Trust Decisions: Frugal AI Powering the WAF**](https://aivo.fr/en/blog/entropie-shannon-decision-zero-trust-ia-frugale) — Mathematical deep-dive into entropy thresholds for DGA and exfiltration detection.
* 📖 [**Anatomy of a VPS Under Continuous Attack: Scanners, Energy, and Active Responses**](https://aivo.fr/en/blog/anatomie-vps-sous-assaut-continu-scanners-energie) — Field observations of botnet scans and outbound exfiltration attempts.
* 🔬 [**Aegis Sovereign Gate Case Study on AIVO.fr**](https://aivo.fr/en/realisations/aegis-sovereign-gate) — Project overview, sovereign compliance roadmap, and AI threat mitigation strategies.
