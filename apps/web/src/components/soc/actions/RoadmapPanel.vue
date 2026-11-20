<template>
  <div class="space-y-5 text-xs">
    <div class="p-5 rounded-lg bg-slate-900/75 border border-slate-800/90">
      <div class="flex items-center gap-2 text-[11px] font-mono text-emerald-400 font-semibold uppercase tracking-wider mb-1">
        <AegisIcon name="layers" size="xs" />
        <span>{{ isEn ? 'AGPLv3 TECHNICAL ARCHITECTURE & ROADMAP STATUS' : 'ÉTAT TECHNIQUE DE L’ARCHITECTURE & FEUILLE DE ROUTE AGPLv3' }}</span>
      </div>
      <h2 class="text-base sm:text-lg font-bold text-white tracking-tight">
        {{ isEn
          ? 'Production Modules (v1.2.0 — All P0/P1 Security Locks Delivered) vs Next Milestones (P2/P3)'
          : 'Modules en Production (v1.2.0 — Tous les Verrous P0/P1 Livrés) vs Prochains Jalons (P2/P3)' }}
      </h2>
      <p class="text-slate-400 text-xs mt-1">
        {{ isEn
          ? 'Complete auditability of delivered defense-in-depth capabilities and upcoming enterprise milestones.'
          : 'Traçabilité technique des verrous de défense en profondeur actifs dans ce dépôt et des jalons planifiés.' }}
      </p>

      <div class="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <!-- Colonne 1 : En Production v1.2.0 (Fondations + Verrous P0/P1 Livrés) -->
        <div class="p-4 rounded-lg bg-slate-950/90 border border-slate-800 space-y-3">
          <div class="flex items-center justify-between pb-2.5 border-b border-slate-800">
            <span class="text-emerald-400 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <AegisIcon name="check" size="xs" />
              <span>{{ isEn ? 'ACTIVE IN PRODUCTION (v1.2.0 — P0 & P1 DELIVERED)' : 'ACTIF EN PRODUCTION (v1.2.0 — VERROUS P0 & P1 LIVRÉS)' }}</span>
            </span>
            <span class="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 font-mono text-[10px] text-emerald-300">
              v1.2.0
            </span>
          </div>

          <ul class="space-y-2.5 text-slate-300 leading-relaxed">
            <li>
              <strong class="text-white">{{ isEn ? 'Lock #1 (P0) — Egress Confinement & DNS-to-IP Allowlist:' : 'Verrou n°1 (P0) — Confinement Réseau Egress & Allowlist DNS-to-IP :' }}</strong>
              {{ isEn
                ? 'Segmented Docker internal network, nftables host enforcement, and direct-IP reverse shell rejection (:5053).'
                : 'Segmentation réseau Docker interne, règles nftables hôte et rejet des Reverse Shells sur IP directe sans résolution DNS (:5053).' }}
            </li>
            <li>
              <strong class="text-white">{{ isEn ? 'Lock #2 (P1) — Multi-Encoding Canonicalization:' : 'Verrou n°2 (P1) — Canonisation Multi-Encodage Anti-Évasion :' }}</strong>
              {{ isEn
                ? '3-pass URL decoding, HTML entities, Hex/Unicode escapes, path normalization, and automatic Base64 payload inspection.'
                : 'Décodage URL récursif 3 passes, entités HTML, séquences Hex/Unicode, normalisation de chemin et décodage Base64 automatique.' }}
            </li>
            <li>
              <strong class="text-white">{{ isEn ? 'Lock #3 (P1) — Volumetric Rate-Limiting & Auto-Jail:' : 'Verrou n°3 (P1) — Rate-Limiting Volumétrique (HTTP 429) & Auto-Jail :' }}</strong>
              {{ isEn
                ? 'Sliding-window limiter (60 req/10s) and automatic 15-minute IP quarantine after 3 critical offenses.'
                : 'Limiteur à fenêtre glissante (60 req/10s) et mise en quarantaine automatique de 15 minutes après 3 offenses critiques.' }}
            </li>
            <li>
              <strong class="text-white">{{ isEn ? 'Lock #4 (P1) — HTTP Protocol Hardening & Anti-Spawn Shell:' : 'Verrou n°4 (P1) — Durcissement Protocole HTTP (431) & Anti-Spawn Shell :' }}</strong>
              {{ isEn
                ? '8 KB header enforcement (HTTP 431), RFC multipart boundary validation, and Rust procfs web-worker shell spawn monitor.'
                : 'Plafond 8 Ko des en-têtes (HTTP 431), validation RFC multipart et surveillance Rust procfs des processus shells enfants.' }}
            </li>
            <li>
              <strong class="text-white">{{ isEn ? 'Lock #5 (P1) — Continuous Posture Audits & Guided Remediation:' : 'Verrou n°5 (P1) — Audits de Posture Continus & Remédiation Guidée :' }}</strong>
              {{ isEn
                ? 'Scheduled passive audits (6h/12h/24h), posture drift detection, and ready-to-deploy Traefik/Nginx/Caddy/PHP hardening snippets.'
                : 'Planification périodique (6h/12h/24h), détection de dérive de score et extraits de configuration Traefik/Nginx/Caddy/PHP.' }}
            </li>
          </ul>
        </div>

        <!-- Colonne 2 : Prochains Jalons P2 / P3 -->
        <div class="p-4 rounded-lg bg-slate-950/90 border border-slate-800 space-y-3">
          <div class="flex items-center justify-between pb-2.5 border-b border-slate-800">
            <span class="text-slate-200 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <AegisIcon name="layers" size="xs" class="text-emerald-400" />
              <span>{{ isEn ? 'UPCOMING MILESTONES (P2 & P3 ENTERPRISE ROADMAP)' : 'PROCHAINS JALONS (ROADMAP ENTREPRISE P2 & P3)' }}</span>
            </span>
            <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 font-mono text-[10px] text-slate-300">
              P2 · P3
            </span>
          </div>

          <ul class="space-y-2.5 text-slate-300 leading-relaxed">
            <li>
              <strong class="text-white">{{ isEn ? 'P2 — Automated CTI Feed Sync (50,000+ C2 Domains):' : 'P2 — Synchronisation Automatisée des Flux CTI (50 000+ Domaines C2) :' }}</strong>
              {{ isEn
                ? 'Hourly in-memory O(1) synchronization with Abuse.ch ThreatFox, URLhaus, and CrowdSec CTI feeds.'
                : 'Synchronisation horaire en mémoire O(1) des listes Abuse.ch ThreatFox, URLhaus et CrowdSec CTI.' }}
            </li>
            <li>
              <strong class="text-white">{{ isEn ? 'P2 — Webhook Alerting & SIEM Syslog Export:' : 'P2 — Alerting Temps Réel Webhooks & Export SIEM (CEF/Syslog) :' }}</strong>
              {{ isEn
                ? 'Instant incident notifications to Slack, Microsoft Teams, Mattermost, PagerDuty, and Wazuh/QRadar.'
                : 'Notifications instantanées sur incident critique vers Slack, Microsoft Teams, Mattermost et SIEM Wazuh/QRadar.' }}
            </li>
            <li>
              <strong class="text-white">{{ isEn ? 'P2 — Multi-Tenant OIDC / Keycloak SSO & RBAC:' : 'P2 — Authentification Multi-Tenant OIDC / Keycloak & RBAC :' }}</strong>
              {{ isEn
                ? 'Centralized SSO authentication with Read-Only, SOC Analyst, and Admin role separation.'
                : 'Délégation SSO centralisée avec séparation des rôles Lecture Seule, Analyste SOC et Administrateur.' }}
            </li>
            <li>
              <strong class="text-white">{{ isEn ? 'P3 — OpenSCAP Host Hardening & Kubernetes Helm Chart:' : 'P3 — Connecteur OpenSCAP CIS/ANSSI & Helm Chart Kubernetes :' }}</strong>
              {{ isEn
                ? 'Automated Linux host sysctl/SSH compliance checks and Kubernetes DaemonSet/Sidecar deployment.'
                : 'Vérification automatisée de conformité SSH/Sysctl du serveur hôte Linux et déploiement Kubernetes.' }}
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import AegisIcon from '../AegisIcon.vue';
import { useI18n } from '../../../composables/useI18n';

const { locale } = useI18n();
const isEn = computed(() => locale.value === 'en');
</script>
