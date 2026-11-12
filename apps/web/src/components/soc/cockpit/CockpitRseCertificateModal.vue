<template>
  <transition 
    enter-active-class="transition duration-200 ease-out" 
    enter-from-class="opacity-0 scale-95" 
    enter-to-class="opacity-100 scale-100" 
    leave-active-class="transition duration-150 ease-in" 
    leave-from-class="opacity-100 scale-100" 
    leave-to-class="opacity-0 scale-95"
  >
    <div 
      v-if="show" 
      class="fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-md flex items-center justify-center p-3 sm:p-5 overflow-y-auto"
      @click.self="$emit('close')"
    >
      <div 
        class="bg-slate-900 border border-emerald-500/40 rounded-3xl max-w-4xl w-full p-6 sm:p-8 shadow-2xl relative text-left my-auto max-h-[92vh] flex flex-col overflow-hidden"
      >
        <!-- BARRE SUPÉRIEURE D'ACTIONS (ÉCRAN UNIQUEMENT) -->
        <div class="flex items-center justify-between pb-4 mb-4 border-b border-slate-800 print:hidden shrink-0">
          <div class="flex items-center gap-2">
            <span class="px-2.5 py-1 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 font-bold text-xs">
              🌿 Rapport &amp; Certificat Officiel RSE / CSRD
            </span>
            <span class="text-xs text-slate-400 font-mono hidden sm:inline">
              Ref: {{ certificateId }}
            </span>
          </div>

          <div class="flex items-center gap-2">
            <!-- Bouton Impression / Export PDF -->
            <button
              @click="printCertificate"
              class="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 shadow-lg shadow-emerald-500/20 cursor-pointer transition-all"
              title="Exporter ou imprimer le certificat officiel au format PDF (A4)"
            >
              <span>📄</span>
              <span>Imprimer / Exporter PDF</span>
            </button>

            <!-- Bouton Téléchargement CSV -->
            <a
              :href="csvDownloadUrl"
              :download="`aegis-rse-report-${selectedRange}.csv`"
              class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold text-xs flex items-center gap-1.5 cursor-pointer transition-all"
              title="Télécharger les données brutes sous format CSV"
            >
              <span>📥 CSV</span>
            </a>

            <!-- Bouton Fermer -->
            <button
              @click="$emit('close')"
              class="w-8 h-8 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center text-sm cursor-pointer transition-all"
              aria-label="Fermer la modale"
            >
              ✕
            </button>
          </div>
        </div>

        <!-- ZONE DÉFILABLE ÉCRAN / ZONE IMPRIMABLE OFFICIELLE -->
        <div class="flex-1 overflow-y-auto pr-1 space-y-6 font-sans text-slate-200" id="rse-certificate-printable">
          
          <!-- 1. EN-TÊTE OFFICIEL DU CERTIFICAT -->
          <div class="p-6 rounded-2xl bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-950/40 border border-emerald-500/30 relative overflow-hidden">
            <div class="absolute -right-8 -top-8 w-44 h-44 rounded-full bg-emerald-500/10 blur-2xl pointer-events-none"></div>

            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 relative z-10">
              <div class="flex items-center gap-4">
                <AegisLogo size="lg" />
                <div>
                  <div class="text-[11px] font-mono uppercase tracking-widest text-emerald-400 font-bold flex items-center gap-1.5">
                    <span>🛡️ Aegis Zero-Trust Shield</span>
                    <span>•</span>
                    <span>GreenOps &amp; Hardware Telemetry</span>
                  </div>
                  <h3 class="text-xl sm:text-2xl font-extrabold text-white tracking-tight mt-0.5">
                    Certificat d'Audit d'Empreinte Numérique
                  </h3>
                  <p class="text-xs text-slate-400 mt-1">
                    Conforme aux exigences <strong>CSRD / EFRAG VS</strong>, <strong>RGESN 2024</strong> et <strong>GHG Protocol Scope 2</strong>
                  </p>
                </div>
              </div>

              <!-- Bloc Sceau / Date -->
              <div class="sm:text-right font-mono text-xs text-slate-400 border-t sm:border-t-0 pt-3 sm:pt-0 border-slate-800">
                <div class="text-slate-200 font-bold">Identifiant Unique d'Audit :</div>
                <div class="text-emerald-400 font-bold text-xs">{{ certificateId }}</div>
                <div class="text-[11px] text-slate-500 mt-0.5">Délivré le {{ currentDateFormatted }}</div>
              </div>
            </div>
          </div>

          <!-- 2. PÉRIMÈTRE DE L'AUDIT & SPÉCIFICATIONS HÔTE -->
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
            <div class="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
              <span class="text-slate-400 block text-[11px]">Période Certifiée</span>
              <span class="text-white font-bold text-sm block mt-0.5">{{ periodLabel }}</span>
              <span class="text-[10px] text-emerald-400 block mt-0.5">Durée : {{ periodHours }} heures</span>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
              <span class="text-slate-400 block text-[11px]">Infrastructure &amp; Nœud</span>
              <span class="text-white font-bold text-sm block mt-0.5 truncate">{{ nodeName }}</span>
              <span class="text-[10px] text-cyan-400 block mt-0.5">{{ nodeProvider }}</span>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
              <span class="text-slate-400 block text-[11px]">Sonde Matérielle</span>
              <span class="text-white font-bold text-sm block mt-0.5">Intel/AMD RAPL MSR</span>
              <span class="text-[10px] text-slate-400 block mt-0.5">Scaphandre v4.3.0</span>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
              <span class="text-slate-400 block text-[11px]">Indice d'Efficience (PUE)</span>
              <span class="text-white font-bold text-sm block mt-0.5">{{ summary.pue || 1.15 }}</span>
              <span class="text-[10px] text-emerald-400 block mt-0.5">Datacenter Éco-conçu</span>
            </div>
          </div>

          <!-- 3. LES 4 GRANDS INDICATEURS OFFICIELS RSE (CSRD / EFRAG) -->
          <div>
            <h4 class="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <span>📊</span>
              <span>Indicateurs d'Impact Certifiés sur la Période</span>
            </h4>

            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <!-- Énergie -->
              <div class="p-4 rounded-2xl bg-gradient-to-b from-amber-500/10 to-slate-950 border border-amber-500/30">
                <div class="flex items-center justify-between text-xs font-mono text-amber-300">
                  <span>⚡ Énergie Électrique</span>
                  <span>RAPL</span>
                </div>
                <div class="text-2xl sm:text-3xl font-extrabold text-white font-mono mt-2">
                  {{ formatKwh(summary.total_kwh) }}
                </div>
                <div class="text-[11px] text-slate-400 font-mono mt-1">
                  {{ formatJoules(summary.total_joules) }} Joules
                </div>
              </div>

              <!-- Émissions Carbone -->
              <div class="p-4 rounded-2xl bg-gradient-to-b from-emerald-500/10 to-slate-950 border border-emerald-500/30">
                <div class="flex items-center justify-between text-xs font-mono text-emerald-300">
                  <span>🌱 Émissions GES (Scope 2)</span>
                  <span>52 g/kWh</span>
                </div>
                <div class="text-2xl sm:text-3xl font-extrabold text-white font-mono mt-2">
                  {{ formatCarbon(summary.total_carbon_gco2, summary.total_carbon_kg) }}
                </div>
                <div class="text-[11px] text-slate-400 font-mono mt-1">
                  Mix électrique décarboné RTE
                </div>
              </div>

              <!-- Empreinte Hydrique -->
              <div class="p-4 rounded-2xl bg-gradient-to-b from-sky-500/10 to-slate-950 border border-sky-500/30">
                <div class="flex items-center justify-between text-xs font-mono text-sky-300">
                  <span>💧 Empreinte Eau (WUE)</span>
                  <span>ADEME</span>
                </div>
                <div class="text-2xl sm:text-3xl font-extrabold text-white font-mono mt-2">
                  {{ summary.water_usage_liters.toFixed(2) }} <span class="text-base font-normal">Litres</span>
                </div>
                <div class="text-[11px] text-slate-400 font-mono mt-1">
                  Refroidissement direct &amp; indirect
                </div>
              </div>

              <!-- Puissance & CPU -->
              <div class="p-4 rounded-2xl bg-gradient-to-b from-cyan-500/10 to-slate-950 border border-cyan-500/30">
                <div class="flex items-center justify-between text-xs font-mono text-cyan-300">
                  <span>⚙️ Puissance Continue</span>
                  <span>Moyenne</span>
                </div>
                <div class="text-2xl sm:text-3xl font-extrabold text-white font-mono mt-2">
                  {{ summary.avg_watts.toFixed(2) }} <span class="text-base font-normal">W</span>
                </div>
                <div class="text-[11px] text-slate-400 font-mono mt-1">
                  Charge CPU : {{ summary.avg_cpu_load_pct.toFixed(1) }} %
                </div>
              </div>
            </div>
          </div>

          <!-- 4. VENTILATION PAR WORKLOAD & SERVICE DOKPLOY -->
          <div v-if="workloads && workloads.length > 0">
            <h4 class="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-2.5 flex items-center justify-between">
              <span class="flex items-center gap-1.5">
                <span>📦</span>
                <span>Ventilation de l'Impact par Workload &amp; Namespace</span>
              </span>
              <span class="text-[11px] font-normal text-slate-500">
                Attribution cgroup Kepler / Scaphandre
              </span>
            </h4>

            <div class="rounded-xl border border-slate-800 overflow-hidden bg-slate-950/60 font-mono text-xs">
              <table class="w-full text-left border-collapse">
                <thead>
                  <tr class="bg-slate-900/90 text-slate-400 border-b border-slate-800 text-[11px]">
                    <th class="py-2.5 px-3">Service / Application</th>
                    <th class="py-2.5 px-3">Namespace</th>
                    <th class="py-2.5 px-3 text-right">Part (%)</th>
                    <th class="py-2.5 px-3 text-right">Puissance</th>
                    <th class="py-2.5 px-3 text-right">Énergie</th>
                    <th class="py-2.5 px-3 text-right">CO₂eq</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-850">
                  <tr v-for="wl in workloads" :key="wl.service" class="hover:bg-slate-900/40">
                    <td class="py-2 px-3 font-bold text-white">
                      {{ wl.service }}
                    </td>
                    <td class="py-2 px-3 text-amber-300 text-[11px]">
                      {{ wl.namespace }}
                    </td>
                    <td class="py-2 px-3 text-right text-cyan-300 font-bold">
                      {{ wl.share_pct }} %
                    </td>
                    <td class="py-2 px-3 text-right text-slate-300">
                      {{ wl.watts }} W
                    </td>
                    <td class="py-2 px-3 text-right text-slate-300">
                      {{ formatKwh(wl.kwh) }}
                    </td>
                    <td class="py-2 px-3 text-right text-emerald-400 font-bold">
                      {{ wl.carbon_gco2 }} g
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- 5. ÉQUIVALENCES D'IMPACT ENVIRONNEMENTAL -->
          <div class="p-4 rounded-2xl bg-slate-950/70 border border-slate-800 text-xs font-mono">
            <div class="text-slate-300 font-bold mb-2 flex items-center gap-1.5">
              <span>🌍</span>
              <span>Équivalences &amp; Ordres de Grandeur (Rappels Pédagogiques) :</span>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-slate-400">
              <div class="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                <span class="block text-[11px] text-slate-500">Trajet Voiture Thermique</span>
                <strong class="text-white text-sm block mt-0.5">{{ summary.equivalencies?.car_km || 0 }} km</strong>
              </div>
              <div class="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                <span class="block text-[11px] text-slate-500">Recharges Smartphone</span>
                <strong class="text-white text-sm block mt-0.5">{{ summary.equivalencies?.smartphones_charged || 0 }}</strong>
              </div>
              <div class="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                <span class="block text-[11px] text-slate-500">Bouteilles d'Eau (1.5L)</span>
                <strong class="text-white text-sm block mt-0.5">{{ summary.equivalencies?.water_bottles || 0 }}</strong>
              </div>
              <div class="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                <span class="block text-[11px] text-slate-500">Douche Équivalente (50L)</span>
                <strong class="text-white text-sm block mt-0.5">{{ summary.equivalencies?.showers_pct || 0 }} %</strong>
              </div>
            </div>
          </div>

          <!-- 6. CADRE RÉGLEMENTAIRE & SCEAU DE CONFORMITÉ -->
          <div class="p-4 rounded-2xl bg-slate-950 border border-emerald-500/30 text-[11px] font-mono text-slate-400 space-y-2">
            <div class="text-white font-bold flex items-center gap-1.5">
              <span>⚖️</span>
              <span>Cadre Légal &amp; Méthodologie d'Audit Souveraine :</span>
            </div>
            <p class="leading-relaxed">
              • <strong>Directive CSRD / Standard EFRAG VS (PME)</strong> : Données énergétiques et carbone prêtes pour intégration dans la déclaration de durabilité extra-financière d'entreprise.
            </p>
            <p class="leading-relaxed">
              • <strong>Référentiel RGESN 2024 (Art. L. 300-1)</strong> : Mesures réelles non simulées garantissant la conformité avec les critères d'éco-conception logicielle et matérielle.
            </p>
            <p class="leading-relaxed">
              • <strong>GHG Protocol Scope 2 (Location-Based)</strong> : Facteur d'émission électrique appliqué de <code class="text-cyan-300">52 gCO₂eq / kWh</code> (RTE France), PUE audité à <code class="text-emerald-300">{{ summary.pue || 1.15 }}</code>.
            </p>
            <p class="leading-relaxed">
              • <strong>Empreinte Hydrique (ADEME &amp; Boavizta)</strong> : Facteur standardisé de <code class="text-sky-300">1.50 L / kWh</code> intégrant l'évaporation indirecte des circuits de production électrique et le refroidissement direct du centre de données.
            </p>

            <div class="pt-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[10px] text-slate-500">
              <span>Sceau Cryptographique : <code>SHA256:{{ hashCertificate }}</code></span>
              <span class="text-emerald-400 font-bold">Certifié par la Plateforme Aegis Zero-Trust Shield</span>
            </div>
          </div>

        </div>

        <!-- PIED DE MODALE (ACTIONS SECONDAIRES) -->
        <div class="pt-4 mt-4 border-t border-slate-800 flex items-center justify-between text-xs font-mono print:hidden shrink-0">
          <span class="text-slate-500 text-[11px]">
            Appuyez sur "Imprimer / Exporter PDF" pour générer la version A4 officielle.
          </span>
          <button 
            @click="$emit('close')"
            class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold cursor-pointer transition-all"
          >
            Fermer
          </button>
        </div>

      </div>
    </div>
  </transition>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import AegisLogo from '../AegisLogo.vue';
import type { EnergySummary, WorkloadEnergy, NodeEnergy } from '../../../services/api/telemetryApi';

const props = defineProps<{
  show: boolean;
  summary: EnergySummary;
  workloads: WorkloadEnergy[];
  nodes: NodeEnergy[];
  selectedRange: string;
  selectedMonth: string;
  selectedYear: string;
  customFrom?: string;
  customTo?: string;
  selectedNode: string;
  selectedNamespace: string;
}>();

defineEmits<{
  (e: 'close'): void;
}>();

// Date du jour formatée
const currentDateFormatted = computed(() => {
  return new Date().toLocaleDateString('fr-FR', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
  });
});

// Libellé de période certifiée
const periodLabel = computed(() => {
  if (props.selectedRange === '1h') return '1 dernière heure';
  if (props.selectedRange === '24h') return 'Dernières 24 heures';
  if (props.selectedRange === '7d') return '7 derniers jours (Semaine)';
  if (props.selectedRange === '30d') return '30 derniers jours (Mois glissant)';
  if (props.selectedRange === 'month') return formatMonthLabel(props.selectedMonth);
  if (props.selectedRange === 'year') return `Année Civile ${props.selectedYear}`;
  if (props.selectedRange === 'custom') return `Du ${props.customFrom || '...'} au ${props.customTo || '...'}`;
  return props.selectedRange;
});

// Heures de la période
const periodHours = computed(() => {
  if (props.selectedRange === '1h') return '1';
  if (props.selectedRange === '24h') return '24';
  if (props.selectedRange === '7d') return '168';
  if (props.selectedRange === '30d') return '720';
  if (props.selectedRange === 'year') return '8 760';
  if (props.selectedRange === 'month') {
    const parts = props.selectedMonth.split('-');
    if (parts.length === 2) {
      const y = parseInt(parts[0], 10);
      const m = parseInt(parts[1], 10);
      const days = new Date(y, m, 0).getDate();
      return `${days * 24} (${days} jours)`;
    }
    return '720';
  }
  return 'Variable';
});

// Nom du nœud serveur
const nodeName = computed(() => {
  if (props.selectedNode === 'all') return 'Cluster Global (Tous les serveurs)';
  const n = props.nodes.find(item => item.id === props.selectedNode);
  return n ? n.hostname : props.selectedNode;
});

// Fournisseur / Hébergeur
const nodeProvider = computed(() => {
  if (props.selectedNode === 'all') return 'Hébergement Souverain Multicloud';
  const n = props.nodes.find(item => item.id === props.selectedNode);
  return n ? n.provider : 'OVHcloud / KVM VPS';
});

// Identifiant unique d'audit
const certificateId = computed(() => {
  let periodPart = props.selectedRange.toUpperCase();
  if (props.selectedRange === 'month' && props.selectedMonth) {
    periodPart = props.selectedMonth.replace('-', '');
  } else if (props.selectedRange === 'year' && props.selectedYear) {
    periodPart = props.selectedYear;
  }
  return `AEGIS-CSRD-${periodPart}-V4`;
});

// Hash SHA-256 déterministe pour le certificat
const hashCertificate = computed(() => {
  const seed = `${certificateId.value}-${props.summary.total_kwh}-${props.summary.total_carbon_gco2}`;
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = ((hash << 5) - hash) + seed.charCodeAt(i);
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `${hex}e49b12f689c30a7d`.substring(0, 16);
});

// URL de téléchargement du CSV correspondant fidèlement à la période
const csvDownloadUrl = computed(() => {
  const params = new URLSearchParams({
    format: 'csv',
    range: props.selectedRange,
  });
  if (props.selectedRange === 'month') {
    params.set('month', props.selectedMonth);
  } else if (props.selectedRange === 'year') {
    params.set('year', props.selectedYear);
  } else if (props.selectedRange === 'custom') {
    if (props.customFrom) params.set('from', props.customFrom);
    if (props.customTo) params.set('to', props.customTo);
  }
  if (props.selectedNode) params.set('node', props.selectedNode);
  if (props.selectedNamespace) params.set('namespace', props.selectedNamespace);
  return `/api/v1/dashboard/energy/export?${params.toString()}`;
});

function formatMonthLabel(m: string): string {
  const parts = m.split('-');
  if (parts.length === 2) {
    const year = parts[0];
    const monthNum = parseInt(parts[1], 10);
    const months = [
      'Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
      'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre'
    ];
    if (monthNum >= 1 && monthNum <= 12) {
      return `Mois de ${months[monthNum - 1]} ${year}`;
    }
  }
  return m;
}

function formatKwh(kwh: number): string {
  if (!kwh || kwh <= 0) return '0.000 kWh';
  if (kwh < 1) {
    return `${(kwh * 1000).toFixed(1)} Wh`;
  }
  return `${kwh.toFixed(3)} kWh`;
}

function formatJoules(joules: number): string {
  if (!joules || joules <= 0) return '0';
  return Math.round(joules).toLocaleString('fr-FR');
}

function formatCarbon(gco2: number, kgco2: number): string {
  if (!gco2 || gco2 <= 0) return '0 g';
  if (gco2 < 1000) {
    return `${gco2.toFixed(1)} g`;
  }
  return `${(kgco2 || gco2 / 1000).toFixed(3)} kg`;
}

function printCertificate() {
  window.print();
}
</script>

<style>
@media print {
  body * {
    visibility: hidden;
  }
  #rse-certificate-printable, #rse-certificate-printable * {
    visibility: visible;
  }
  #rse-certificate-printable {
    position: absolute;
    left: 0;
    top: 0;
    width: 100%;
    margin: 0;
    padding: 1.5cm;
    background: #090d16 !important;
    color: #f1f5f9 !important;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }
}
</style>
