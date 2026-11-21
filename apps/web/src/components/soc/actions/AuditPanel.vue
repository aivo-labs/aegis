<template>
  <div class="space-y-5">
    <!-- Barre de lancement du Scan Passif & Planificateur d'Audit Continu (Verrou n°5 P1) -->
    <div class="p-5 rounded-lg bg-slate-900/75 border border-slate-800/90 space-y-4">
      <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div class="flex items-center gap-2 text-[11px] font-mono text-emerald-400 font-semibold uppercase tracking-wider mb-1">
            <AegisIcon name="search" size="xs" />
            <span>{{ isEn ? 'NON-INTRUSIVE PASSIVE SCANNER (CONCURRENT GO ENGINE — 5 PAGES MAX)' : 'SCANNER PASSIF NON-INTRUSIF (MOTEUR CONCURRENT GO — 5 PAGES MAX)' }}</span>
          </div>
          <h2 class="text-base sm:text-lg font-bold text-white tracking-tight">
            {{ isEn ? 'Audit CVE surface exposure (PHP, CMS, Web Server, Headers) and EcoIndex v3 footprint' : "Audit d'exposition CVE (PHP, CMS, Serveur, En-têtes HTTP) et empreinte EcoIndex v3" }}
          </h2>
          <p class="text-xs text-slate-400 mt-0.5">
            {{ isEn ? 'Non-intrusive assessment aligned with ANSSI security guidelines and EcoIndex v3 methodology.' : "Analyse externe non-intrusive conforme aux recommandations de l'ANSSI et au référentiel EcoIndex v3." }}
          </p>
        </div>

        <form @submit.prevent="handleScan" class="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 w-full lg:w-auto">
          <div class="relative flex items-center min-w-[270px]">
            <span class="absolute left-3 text-slate-500 font-mono text-xs">https://</span>
            <input
              v-model="scanDomain"
              type="text"
              required
              :placeholder="isEn ? 'company.com or localhost' : 'mon-entreprise.fr ou localhost'"
              class="w-full pl-17 pr-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono text-xs focus:outline-none focus:border-emerald-500/70"
            />
          </div>
          <button
            type="submit"
            :disabled="isScanning"
            class="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-sans text-xs font-semibold cursor-pointer transition-colors shrink-0 flex items-center justify-center gap-1.5"
          >
            <AegisIcon :name="isScanning ? 'refresh' : 'zap'" size="xs" :class="isScanning ? 'animate-spin' : ''" />
            <span>{{ isScanning ? (isEn ? 'Scanning 5 pages...' : 'Analyse des 5 pages...') : (isEn ? 'Run Assessment (5 Pages)' : 'Lancer le Diagnostic (5 Pages)') }}</span>
          </button>
        </form>
      </div>

      <!-- Verrou n°5 P1 : Planification d'Audit Continu & Détection de Dérive (Posture Drift) -->
      <div class="pt-3.5 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div class="flex flex-wrap items-center gap-2">
          <span class="inline-flex items-center gap-1.5 text-slate-300 font-medium">
            <AegisIcon name="refresh" size="xs" class="text-emerald-400" />
            <span>{{ isEn ? 'Continuous Posture Monitoring (Verrou #5):' : 'Surveillance Continue de Posture (Verrou n°5) :' }}</span>
          </span>
          <span v-if="activeDomainSchedule" class="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-mono text-[11px] tabular-nums">
            {{ isEn ? `Active every ${activeDomainSchedule.interval_hours}h` : `Actif toutes les ${activeDomainSchedule.interval_hours}h` }}
          </span>
          <span v-if="auditResult?.posture_drift?.has_drift" class="px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 font-mono text-[11px] tabular-nums">
            {{ isEn ? `Drift detected (${auditResult.posture_drift.delta} pts)` : `Dérive détectée (${auditResult.posture_drift.delta} pts)` }}
          </span>
        </div>

        <div class="flex items-center gap-2 font-mono text-xs">
          <span class="text-slate-400 font-sans">{{ isEn ? 'Interval:' : 'Fréquence :' }}</span>
          <div class="inline-flex rounded-md bg-slate-950 border border-slate-800 p-0.5">
            <button
              v-for="hrs in [6, 12, 24]"
              :key="hrs"
              type="button"
              @click="handleSaveSchedule(hrs)"
              :disabled="isSavingSchedule"
              :class="[
                'px-2.5 py-1 rounded text-[11px] font-semibold cursor-pointer transition-colors tabular-nums',
                scheduleIntervalHours === hrs ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
              ]"
            >
              {{ hrs }}h
            </button>
          </div>
          <button
            type="button"
            @click="handleSaveSchedule()"
            :disabled="isSavingSchedule"
            class="px-3 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-sans text-xs font-medium cursor-pointer transition-colors"
          >
            {{ isSavingSchedule ? (isEn ? 'Saving...' : 'Activation...') : (isEn ? 'Enable Continuous Audit' : 'Activer Audit Continu') }}
          </button>
        </div>
      </div>
    </div>

    <!-- RÉSULTAT DU DIAGNOSTIC PASSIF -->
    <div v-if="auditResult" class="space-y-5">
      <!-- 4 Cartes de Synthèse Réelles du Domaine Scanné -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div class="p-4 rounded-lg bg-slate-900/75 border border-slate-800/90">
          <div class="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
            {{ isEn ? `Audited Domain (${auditResult.pages_scanned} pages)` : `Domaine Audité (${auditResult.pages_scanned} pages)` }}
          </div>
          <div class="text-xl font-bold text-white font-mono truncate">{{ auditResult.domain }}</div>
          <div class="text-[11px] text-slate-400 font-mono tabular-nums mt-1.5">
            {{ isEn ? `Completed in ${auditResult.scan_duration_ms || 120} ms` : `Exécuté en ${auditResult.scan_duration_ms || 120} ms` }}
          </div>
        </div>

        <div class="p-4 rounded-lg bg-slate-900/75 border border-slate-800/90">
          <div class="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
            {{ isEn ? 'Weighted Security Score (Headers & CVE)' : 'Score Sécurité Pondéré (Headers & CVE)' }}
          </div>
          <div class="flex items-baseline gap-2 font-mono tabular-nums">
            <span :class="['text-2xl font-bold', auditResult.security_score >= 75 ? 'text-emerald-400' : (auditResult.security_score >= 50 ? 'text-amber-400' : 'text-rose-400')]">
              {{ auditResult.security_score }} / 100
            </span>
            <span class="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 text-xs font-semibold">
              Grade {{ auditResult.security_grade }}
            </span>
          </div>
          <div :class="['text-[11px] mt-1.5 font-mono tabular-nums', (auditResult.cve_warnings || []).length > 0 ? 'text-rose-400' : 'text-emerald-400']">
            {{ (auditResult.cve_warnings || []).length }} {{ isEn ? 'CVE / surface finding(s)' : 'alerte(s) CVE / exposition' }}
          </div>
        </div>

        <div class="p-4 rounded-lg bg-slate-900/75 border border-slate-800/90">
          <div class="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
            {{ isEn ? `EcoIndex v3 Score (${auditResult.pages_scanned} pages)` : `Score EcoIndex v3 (${auditResult.pages_scanned} pages)` }}
          </div>
          <div class="flex items-baseline gap-2 font-mono tabular-nums">
            <span class="text-2xl font-bold text-emerald-400">{{ (auditResult as any).overall_eco_score ?? auditResult.eco_index_score }} / 100</span>
            <span class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 text-xs font-semibold">
              Grade {{ (auditResult as any).overall_eco_grade ?? auditResult.eco_index_grade }}
            </span>
          </div>
          <div class="text-[11px] text-slate-400 font-mono tabular-nums mt-1.5">
            ~{{ (auditResult as any).avg_gco2e_per_visit ?? auditResult.avg_gco2_grams ?? 1.35 }} gCO2e / {{ isEn ? 'page view' : 'page vue' }}
          </div>
        </div>

        <div class="p-4 rounded-lg bg-slate-900/75 border border-slate-800/90">
          <div class="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
            {{ isEn ? 'Domain Ownership & Level 2' : 'Homologation DNS & Niveau 2' }}
          </div>
          <div v-if="(auditResult as any).is_verified_owner || auditResult.ownership_verified" class="text-sm font-bold text-emerald-400 flex items-center gap-1.5 mt-1">
            <AegisIcon name="check" size="xs" />
            <span>{{ isEn ? 'Verified Owner (Signed Mandate)' : 'Domaine Homologué (Mandat Signé)' }}</span>
          </div>
          <div v-else class="text-sm font-bold text-amber-400 flex items-center gap-1.5 mt-1">
            <AegisIcon name="lock" size="xs" />
            <span>{{ isEn ? 'Level 1 (Passive Surface)' : 'Niveau 1 (Surface Passive)' }}</span>
          </div>
          <div class="text-[11px] text-slate-400 mt-1.5">
            {{ ((auditResult as any).is_verified_owner || auditResult.ownership_verified)
              ? (isEn ? 'Full export & Level 2 probes unlocked' : 'Export certifié & sondes Niveau 2 actifs')
              : (isEn ? 'Verify DNS TXT record below for Level 2 probes' : 'Validez le jeton DNS TXT ci-dessous pour le Niveau 2') }}
          </div>
        </div>
      </div>

      <!-- SECTION WARNINGS CVE & EMPREINTE TECHNOLOGIQUE -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <!-- Colonne Gauche (8 cols) : Alertes CVE & Vulnérabilités Détectées -->
        <div class="lg:col-span-8 bg-slate-900/75 border border-slate-800/90 rounded-lg p-5">
          <div class="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <div class="flex items-center gap-2">
              <AegisIcon name="shield-alert" size="sm" class="text-rose-400" />
              <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-200">
                {{ isEn ? 'EXPOSED VERSIONS, THREAT WARNINGS & ASSOCIATED CVEs' : 'ALERTES DE SURFACE, VERSIONS EXPOSÉES & CVE ASSOCIÉES' }}
                <span class="font-mono tabular-nums text-slate-400">({{ (auditResult.cve_warnings || []).length }})</span>
              </h3>
            </div>
            <span
              :class="[
                'text-[10px] font-mono px-2 py-0.5 rounded border',
                (auditResult.cve_warnings || []).length > 0
                  ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                  : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
              ]"
            >
              {{ (auditResult.cve_warnings || []).length > 0 ? (isEn ? 'Remediation Required' : 'Remédiation Requise') : (isEn ? 'Clean Surface' : 'Surface Conforme') }}
            </span>
          </div>

          <div v-if="(auditResult.cve_warnings || []).length === 0" class="py-8 text-center text-slate-400 text-xs">
            {{ isEn ? 'No exposed CVE or critical server misconfiguration detected on the sampled pages.' : 'Aucune vulnérabilité CVE ou fuite de configuration critique détectée sur les pages échantillonnées.' }}
          </div>

          <div v-else class="space-y-3 text-xs">
            <div
              v-for="(cve, idx) in auditResult.cve_warnings"
              :key="idx"
              class="p-4 rounded-lg bg-slate-950/90 border border-slate-800 space-y-1.5"
            >
              <div class="flex flex-wrap items-center justify-between gap-2 font-mono tabular-nums">
                <div class="flex items-center gap-2">
                  <span
                    :class="[
                      'px-2 py-0.5 rounded text-[10px] font-bold',
                      (cve as any).severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                    ]"
                  >
                    {{ (cve as any).severity }} · CVSS {{ (cve as any).cvss ?? cve.score }}
                  </span>
                  <span class="text-white font-bold">{{ (cve as any).id ?? cve.cve_id }}</span>
                  <span class="text-slate-400">({{ (cve as any).component ?? '' }})</span>
                </div>
                <span v-if="(cve as any).blocked_by_aegis" class="text-[10px] px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 inline-flex items-center gap-1">
                  <AegisIcon name="shield" size="xs" />
                  <span>{{ isEn ? 'Mitigated at Edge (Virtual Patch)' : 'Mitigé en Bordure (Virtual Patch)' }}</span>
                </span>
              </div>
              <div class="text-white font-semibold text-sm pt-0.5">{{ cve.title }}</div>
              <p class="text-slate-400 text-xs leading-relaxed">{{ (cve as any).description }}</p>
              <div class="pt-1 text-xs text-slate-300">
                <strong class="text-emerald-400">{{ isEn ? 'Host Remediation:' : 'Remédiation Hôte :' }}</strong> {{ (cve as any).remediation }}
              </div>
            </div>
          </div>
        </div>

        <!-- Colonne Droite (4 cols) : Stack Détectée & En-têtes HTTP / DNS -->
        <div class="lg:col-span-4 bg-slate-900/75 border border-slate-800/90 rounded-lg p-5 space-y-5 text-xs">
          <div>
            <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-200 pb-2.5 mb-3 border-b border-slate-800 flex items-center gap-2">
              <AegisIcon name="server" size="xs" class="text-emerald-400" />
              <span>{{ isEn ? 'Detected Stack & Versions' : 'Stack & Versions Détectées' }}</span>
            </h3>
            <div class="space-y-2">
              <div
                v-for="(tech, idx) in ((auditResult as any).tech_stack ?? auditResult.detected_tech)"
                :key="idx"
                class="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
              >
                <div>
                  <div class="text-white font-semibold">{{ tech.name }}</div>
                  <div class="text-[11px] text-slate-400">{{ tech.category }} · {{ (tech as any).source ?? '' }}</div>
                </div>
                <span class="px-2 py-0.5 rounded bg-slate-900 text-slate-200 border border-slate-700 font-mono tabular-nums text-[11px]">
                  {{ tech.version }}
                </span>
              </div>
            </div>
          </div>

          <div>
            <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-200 pb-2.5 mb-3 border-b border-slate-800 flex items-center gap-2">
              <AegisIcon name="lock" size="xs" class="text-emerald-400" />
              <span>{{ isEn ? 'HTTP Security Headers & DNS' : 'En-têtes HTTP & DNS (SPF/DMARC)' }}</span>
            </h3>
            <div class="space-y-1.5 font-mono">
              <div
                v-for="(hdr, idx) in auditResult.headers_analysis"
                :key="idx"
                class="flex items-center justify-between p-2 rounded-md bg-slate-950 border border-slate-800/80"
              >
                <span class="text-slate-300 text-[11px]">{{ (hdr as any).header ?? hdr.name }}</span>
                <span :class="['text-[10px] font-semibold px-1.5 py-0.5 rounded', ((hdr as any).present || hdr.status === 'present') ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/15 text-rose-300']">
                  {{ ((hdr as any).present || hdr.status === 'present') ? (isEn ? 'Present' : 'Actif') : (isEn ? 'Missing' : 'Manquant') }}
                </span>
              </div>
              <div class="flex items-center justify-between p-2 rounded-md bg-slate-950 border border-slate-800/80">
                <span class="text-slate-300 text-[11px]">DNS SPF / DMARC</span>
                <span :class="['text-[10px] font-semibold px-1.5 py-0.5 rounded', (auditResult.dns_analysis?.has_spf || auditResult.dns_checks?.has_spf) ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300']">
                  SPF: {{ (auditResult.dns_analysis?.has_spf || auditResult.dns_checks?.has_spf) ? 'OK' : 'Absent' }} · DMARC: {{ (auditResult.dns_analysis?.has_dmarc || auditResult.dns_checks?.has_dmarc) ? 'OK' : 'Absent' }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- VERROU N°5 P1 : ASSISTANT DE REMÉDIATION GUIDÉE (SNIPPETS TRAEFIK, NGINX, CADDY, APACHE/PHP) -->
      <div class="bg-slate-900/75 border border-slate-800/90 rounded-lg p-5">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-800">
          <div>
            <div class="flex items-center gap-2">
              <AegisIcon name="terminal" size="sm" class="text-emerald-400" />
              <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-200">
                {{ isEn ? 'GUIDED HOST REMEDIATION ASSISTANT (VERROU #5 — READY-TO-DEPLOY CONFIGS)' : 'ASSISTANT DE REMÉDIATION HÔTE GUIDÉE (VERROU N°5 — CONFIGURATIONS PRÊTES À DÉPLOYER)' }}
              </h3>
            </div>
            <p class="text-xs text-slate-400 mt-0.5">
              {{ isEn
                ? 'Hardening snippets generated for missing HTTP headers, TLS 1.3 Post-Quantum hybrid key exchange (X25519MLKEM768), and PHP SAPI isolation.'
                : 'Extraits de durcissement générés selon les en-têtes manquants, TLS 1.3 Post-Quantique hybride (X25519MLKEM768) et confinement PHP.' }}
            </p>
          </div>

          <div class="flex flex-wrap items-center gap-1.5 font-mono text-xs">
            <button
              v-for="tab in remediationTabs"
              :key="tab.id"
              type="button"
              @click="selectedRemediationTab = tab.id"
              :class="[
                'px-2.5 py-1 rounded-md border text-[11px] font-semibold cursor-pointer transition-colors',
                selectedRemediationTab === tab.id
                  ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
              ]"
            >
              {{ tab.label }}
            </button>
            <button
              type="button"
              @click="copyRemediationSnippet"
              class="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-[11px] font-sans font-medium cursor-pointer flex items-center gap-1"
            >
              <AegisIcon :name="copiedSnippet ? 'check' : 'copy'" size="xs" />
              <span>{{ copiedSnippet ? (isEn ? 'Copied' : 'Copié') : (isEn ? 'Copy' : 'Copier') }}</span>
            </button>
          </div>
        </div>

        <pre class="p-3.5 rounded-lg bg-slate-950 border border-slate-800/90 font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed select-all">{{ activeRemediationSnippet }}</pre>
      </div>

      <!-- TABLEAU DÉTAILLÉ DES PAGES SCANNÉES (ECOINDEX V3 RÉEL) -->
      <div class="bg-slate-900/75 border border-slate-800/90 rounded-lg p-5">
        <div class="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
          <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-200">
            {{ isEn ? `EcoIndex v3 Breakdown Across ${auditResult.pages_scanned} Sampled Pages` : `Détail Éco-Conception (EcoIndex v3) sur les ${auditResult.pages_scanned} pages analysées` }}
          </h3>
          <span class="text-xs font-mono tabular-nums text-emerald-400 font-semibold">
            {{ isEn ? 'Average:' : 'Moyenne :' }} {{ (auditResult as any).overall_eco_score ?? auditResult.eco_index_score }}/100 (Grade {{ (auditResult as any).overall_eco_grade ?? auditResult.eco_index_grade }})
          </span>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead>
              <tr class="text-slate-400 border-b border-slate-800 bg-slate-950/60 font-sans text-[11px] uppercase tracking-wider">
                <th class="py-2.5 px-3">{{ isEn ? 'Page URL' : 'URL de la Page' }}</th>
                <th class="py-2.5 px-3">{{ isEn ? 'HTTP Status' : 'Statut HTTP' }}</th>
                <th class="py-2.5 px-3">{{ isEn ? 'TTFB' : 'Temps (TTFB)' }}</th>
                <th class="py-2.5 px-3">{{ isEn ? 'Weight' : 'Poids Estimé' }}</th>
                <th class="py-2.5 px-3">{{ isEn ? 'DOM Nodes' : 'Nœuds DOM' }}</th>
                <th class="py-2.5 px-3">{{ isEn ? 'Requests' : 'Requêtes HTTP' }}</th>
                <th class="py-2.5 px-3">EcoIndex</th>
                <th class="py-2.5 px-3">{{ isEn ? 'Footprint / Visit' : 'Empreinte / Visite' }}</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60 font-mono tabular-nums">
              <tr v-for="(pg, idx) in ((auditResult as any).pages_detail ?? auditResult.pages)" :key="idx" class="hover:bg-slate-800/30">
                <td class="py-2.5 px-3 text-white font-medium">{{ pg.url }}</td>
                <td class="py-2.5 px-3 text-emerald-400">{{ pg.status_code }} OK</td>
                <td class="py-2.5 px-3 text-slate-300">{{ (pg as any).response_time_ms ?? 0 }} ms</td>
                <td class="py-2.5 px-3 text-slate-200">{{ pg.weight_kb }} KB</td>
                <td class="py-2.5 px-3 text-slate-300">{{ pg.dom_elements }}</td>
                <td class="py-2.5 px-3 text-slate-300">{{ pg.http_requests }}</td>
                <td class="py-2.5 px-3">
                  <span class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold">
                    Grade {{ pg.eco_grade }} ({{ pg.eco_score }}/100)
                  </span>
                </td>
                <td class="py-2.5 px-3 text-slate-400">{{ (pg as any).gco2e_per_visit ?? pg.gco2 }} gCO2e · {{ pg.water_cl }} cl</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- NIVEAU 2 : CONTRAT D'HOMOLOGATION DNS & DÉBLOCAGE DU RAPPORT COMPLET -->
      <div class="p-5 rounded-lg bg-slate-900/75 border border-slate-800/90">
        <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div class="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-emerald-400 font-mono text-[11px] font-semibold mb-2">
              <AegisIcon name="shield" size="xs" />
              <span>{{ isEn ? 'LEVEL 2 — DNS OWNERSHIP VERIFICATION & AUDIT MANDATE' : 'NIVEAU 2 — HOMOLOGATION DNS PROPRIÉTAIRE & MANDAT LÉGAL' }}</span>
            </div>
            <h3 class="text-base font-bold text-white">
              {{ isEn
                ? 'Unlock Deep Surface Probes (/.env, /.git, /xmlrpc.php) & Certified Audit Export'
                : "Débloquer l'Audit Approfondi (Sondes /.env, /.git, /xmlrpc.php) & le Rapport Certifié" }}
            </h3>
            <p class="text-xs text-slate-400 mt-1">
              {{ isEn
                ? 'In compliance with computer misuse regulations (French Penal Code Art. 323-1), active surface probes require cryptographic DNS TXT ownership verification.'
                : "Conformément à l'Article 323-1 du Code pénal, l'exécution des sondes de surface Niveau 2 requiert la validation de propriété du domaine par jeton DNS TXT." }}
            </p>
          </div>

          <button
            v-if="(auditResult as any).is_verified_owner || auditResult.ownership_verified"
            @click="scanner.downloadAuditReport"
            class="px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-sans text-xs font-semibold cursor-pointer shrink-0 flex items-center gap-2"
          >
            <AegisIcon name="download" size="xs" />
            <span>{{ isEn ? 'Download Certified Report (JSON)' : 'Télécharger le Rapport Certifié (JSON)' }}</span>
          </button>
        </div>

        <!-- Étape 1 & 2 du formulaire d'homologation -->
        <div v-if="!((auditResult as any).is_verified_owner || auditResult.ownership_verified)" class="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-5 text-xs">
          <div class="space-y-3">
            <div class="text-slate-200 font-semibold">
              {{ isEn ? '1. Administrator Contact & DNS TXT Challenge' : '1. Identification & Génération du Jeton DNS TXT' }}
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <input
                v-model="verifyEmail"
                type="email"
                :placeholder="isEn ? 'security@company.com' : 'securite@mon-entreprise.fr'"
                class="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono text-xs focus:outline-none focus:border-emerald-500/70"
              />
              <input
                v-model="verifyCompany"
                type="text"
                :placeholder="isEn ? 'Organization (Optional)' : 'Organisation (Optionnel)'"
                class="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs focus:outline-none focus:border-emerald-500/70"
              />
            </div>
            <button
              type="button"
              @click="handleRequestDns"
              class="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold cursor-pointer transition-colors"
            >
              {{ isEn ? 'Generate DNS TXT Challenge Record' : 'Générer le Jeton DNS TXT de Vérification' }}
            </button>

            <div v-if="dnsChallenge" class="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
              <div class="text-[11px] text-slate-400">
                {{ isEn ? 'Add this TXT record to the DNS zone of' : 'Ajoutez cet enregistrement TXT dans la zone DNS de' }}
                <strong class="text-white font-mono">{{ auditResult.domain }}</strong> :
              </div>
              <div class="p-2 rounded bg-slate-900 border border-slate-800 text-emerald-300 font-mono font-semibold select-all break-all">
                {{ (dnsChallenge as any).dns_record_value ?? dnsChallenge.expected_value }}
              </div>
            </div>
          </div>

          <div class="space-y-3">
            <div class="text-slate-200 font-semibold">
              {{ isEn ? '2. Electronic Signature of Audit Mandate' : "2. Signature du Mandat d'Autorisation d'Audit" }}
            </div>
            <label class="flex items-start gap-3 p-3 rounded-lg bg-slate-950 border border-slate-800 cursor-pointer hover:border-slate-700">
              <input v-model="contractAccepted" type="checkbox" class="mt-0.5 w-4 h-4 accent-emerald-500" />
              <span class="text-xs text-slate-300 leading-relaxed">
                <strong>{{ isEn ? 'Audit Mandate:' : "Mandat d'Audit :" }}</strong>
                {{ isEn
                  ? `I certify that I am the authorized administrator of ${auditResult.domain} and authorize Aegis to execute Level 2 security and EcoIndex verification probes.`
                  : `Je certifie être l'administrateur dûment habilité du domaine ${auditResult.domain} et autorise Aegis à exécuter les sondes de vérification Niveau 2 (Conformité Art. 323-1 du Code pénal).` }}
              </span>
            </label>

            <button
              type="button"
              @click="handleVerifyDns"
              :disabled="isVerifyingDns"
              class="w-full py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-semibold cursor-pointer transition-colors"
            >
              {{ isVerifyingDns
                ? (isEn ? 'Verifying DNS TXT & Running Level 2 Probes...' : 'Vérification DNS & Sondes Niveau 2...')
                : (isEn ? 'Verify DNS TXT & Unlock Level 2 Report' : 'Vérifier le DNS, Signer le Mandat & Débloquer le Niveau 2') }}
            </button>
          </div>
        </div>

        <!-- Résultats Approfondis Niveau 2 une fois débloqué -->
        <div v-if="deepFindings.length > 0" class="mt-5 pt-4 border-t border-slate-800 text-xs">
          <div class="flex items-center justify-between mb-3">
            <span class="text-emerald-400 font-semibold uppercase tracking-wider">
              {{ isEn ? 'LEVEL 2 DEEP AUDIT FINDINGS (CRITICAL SURFACE PROBES)' : "RÉSULTATS DE L'AUDIT APPROFONDI NIVEAU 2 (SONDES DE SURFACE)" }}
            </span>
            <span v-if="contractSha256" class="text-[11px] font-mono text-slate-400">
              SHA-256: {{ contractSha256.slice(0, 20) }}...
            </span>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            <div
              v-for="(df, idx) in deepFindings"
              :key="idx"
              class="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono"
            >
              <div class="text-white font-semibold">{{ df.path }}</div>
              <div class="text-[10px] font-sans text-slate-400 mt-0.5">{{ df.check_name }}</div>
              <div class="mt-2 text-[11px] font-semibold text-emerald-400">{{ df.verdict }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import AegisIcon from '../AegisIcon.vue';
import { usePassiveScanner } from '../../../composables/usePassiveScanner';
import { useI18n } from '../../../composables/useI18n';

const { locale } = useI18n();
const isEn = computed(() => locale.value === 'en');

const props = defineProps<{
  initialDomain?: string;
}>();

const emit = defineEmits<{
  (e: 'toast', message: string): void;
  (e: 'scan-completed'): void;
}>();

const scanner = usePassiveScanner(props.initialDomain);
const {
  scanDomain,
  isScanning,
  auditResult,
  verifyEmail,
  verifyCompany,
  dnsChallenge,
  contractAccepted,
  isVerifyingDns,
  deepFindings,
  contractSha256,
  postureSchedules,
  scheduleIntervalHours,
  isSavingSchedule,
} = scanner;

const selectedRemediationTab = ref<'traefik' | 'nginx' | 'caddy' | 'apache_php'>('traefik');
const copiedSnippet = ref(false);

const remediationTabs = [
  { id: 'traefik' as const, label: 'Traefik' },
  { id: 'nginx' as const, label: 'Nginx' },
  { id: 'caddy' as const, label: 'Caddy' },
  { id: 'apache_php' as const, label: 'Apache / php.ini' },
];

const activeDomainSchedule = computed(() => {
  const dom = auditResult.value?.domain || scanDomain.value;
  return postureSchedules.value.find(s => s.domain === dom && s.enabled);
});

const defaultSnippets = computed<Record<string, string>>(() => {
  const dom = auditResult.value?.domain || scanDomain.value || 'example.com';
  return {
    traefik: `# Traefik v3 — Security Headers & TLS 1.3 Post-Quantum (${dom})
http:
  middlewares:
    aegis-security-headers:
      headers:
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
        contentTypeNosniff: true
        frameDeny: true
        referrerPolicy: "strict-origin-when-cross-origin"
        customResponseHeaders:
          X-Powered-By: ""
          Server: ""`,
    nginx: `# Nginx — Hardening, Security Headers & TLS 1.3 Hybrid PQC (${dom})
server_tokens off;
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
    caddy: `# Caddyfile — Sovereign Hardening (${dom})
${dom} {
  header {
    Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    Referrer-Policy "strict-origin-when-cross-origin"
    -Server
    -X-Powered-By
  }
}`,
    apache_php: `; /etc/php/8.3/fpm/php.ini — Anti-RCE & SAPI Confinement (CVE-2024-4577 / CVE-2026-109618)
expose_php = Off
allow_url_include = Off
allow_url_fopen = Off
post_max_size = 32K
disable_functions = exec,passthru,shell_exec,system,proc_open,popen`,
  };
});

const activeRemediationSnippet = computed(() => {
  const fromBackend = auditResult.value?.guided_remediation_snippets;
  if (fromBackend && fromBackend[selectedRemediationTab.value]) {
    return fromBackend[selectedRemediationTab.value];
  }
  return defaultSnippets.value[selectedRemediationTab.value] || defaultSnippets.value.traefik;
});

function copyRemediationSnippet() {
  navigator.clipboard?.writeText(activeRemediationSnippet.value);
  copiedSnippet.value = true;
  setTimeout(() => {
    copiedSnippet.value = false;
  }, 2000);
}

async function handleScan() {
  const msg = await scanner.runPassiveScan();
  if (msg) emit('toast', msg);
  emit('scan-completed');
}

async function handleSaveSchedule(hrs?: number) {
  const msg = await scanner.saveSchedule(hrs);
  if (msg) emit('toast', msg);
}

async function handleRequestDns() {
  const msg = await scanner.requestDnsToken();
  if (msg) emit('toast', msg);
}

async function handleVerifyDns() {
  const msg = await scanner.verifyAndUnlockDeepAudit();
  if (msg) emit('toast', msg);
}

if (props.initialDomain) {
  scanner.fetchLatestAudit(props.initialDomain);
} else {
  scanner.fetchSchedules();
}
</script>
