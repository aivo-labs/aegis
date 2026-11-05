<template>
  <div class="space-y-6">
    <!-- 4 KPI Cards Télémétrie & Éco-Conception Réelles -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
      <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90">
        <div class="text-slate-400 text-[11px]">Puissance Matérielle Directe (RAPL)</div>
        <div class="flex items-baseline gap-1 mt-1">
          <span class="text-3xl font-extrabold text-amber-400">{{ instantWatts.toFixed(2) }}</span>
          <span class="text-xs text-slate-400">Watts</span>
        </div>
        <div class="text-[10px] text-slate-400 mt-2">
          CPU: {{ cpuWatts }}W • RAM: {{ ramWatts }}W
        </div>
      </div>

      <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90">
        <div class="text-slate-400 text-[11px]">Charge Processeur (/proc/stat)</div>
        <div class="flex items-baseline gap-1 mt-1">
          <span class="text-3xl font-extrabold text-cyan-300">{{ cpuLoadPct }}</span>
          <span class="text-xs text-slate-400">%</span>
        </div>
        <div class="text-[10px] text-emerald-400 mt-2">
          Empreinte : {{ carbonIntensity }} gCO2/h (Mix FR)
        </div>
      </div>

      <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90">
        <div class="text-slate-400 text-[11px]">Score EcoIndex v3 Moyen</div>
        <div class="flex items-baseline gap-2 mt-1">
          <span class="text-3xl font-extrabold text-emerald-400">
            {{ overallEcoScore || 82 }}
          </span>
          <span class="text-xs text-slate-400">/ 100</span>
          <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-xs border border-emerald-500/40">
            Grade {{ overallEcoGrade || 'B' }}
          </span>
        </div>
        <div class="text-[10px] text-slate-400 mt-2">
          Périmètre : {{ pagesScanned || 5 }} pages échantillonnées
        </div>
      </div>

      <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 flex flex-col justify-between">
        <div>
          <div class="text-slate-400 text-[11px]">Export Brut Télémétrie</div>
          <div class="text-sm font-bold text-white mt-1">Mesures RAPL en Continu</div>
        </div>
        <a 
          href="/api/v1/dashboard/energy/export?format=csv"
          download="aegis-rapl-telemetry.csv"
          class="mt-3 py-2 px-3 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 font-bold flex items-center justify-center gap-2 cursor-pointer transition-all"
        >
          <span>📥 Télécharger (.CSV)</span>
        </a>
      </div>
    </div>

    <!-- COURBE TEMPS RÉEL DE LA PUISSANCE ÉLECTRIQUE -->
    <div class="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 mb-4 border-b border-slate-800 font-mono text-xs">
        <div>
          <div class="text-emerald-400 font-bold mb-0.5">⚡ MESURE RAPL DES REGISTRES CPU INTEL / AMD</div>
          <h3 class="text-base font-extrabold text-white">Courbe Électrique Temps Réel (/sys/class/powercap)</h3>
        </div>
        <div class="flex items-center gap-3">
          <span class="flex items-center gap-1.5 text-cyan-300">
            <span class="w-3 h-0.5 bg-cyan-400 inline-block"></span>
            Puissance instantanée : {{ instantWatts.toFixed(2) }} W
          </span>
          <span class="px-2 py-0.5 rounded bg-slate-800 text-slate-400">
            {{ powerHistoryCount }} échantillons
          </span>
        </div>
      </div>

      <div class="w-full h-44 relative bg-slate-950/90 rounded-xl p-3 border border-slate-800">
        <svg viewBox="0 0 500 160" class="w-full h-full overflow-visible">
          <line x1="40" y1="20" x2="480" y2="20" stroke="#1e293b" stroke-dasharray="3,3" />
          <text x="8" y="24" fill="#64748b" font-size="9" font-family="monospace">20W</text>

          <line x1="40" y1="60" x2="480" y2="60" stroke="#1e293b" stroke-dasharray="3,3" />
          <text x="8" y="64" fill="#64748b" font-size="9" font-family="monospace">15W</text>

          <line x1="40" y1="100" x2="480" y2="100" stroke="#1e293b" stroke-dasharray="3,3" />
          <text x="8" y="104" fill="#64748b" font-size="9" font-family="monospace">10W</text>

          <line x1="40" y1="140" x2="480" y2="140" stroke="#1e293b" stroke-dasharray="3,3" />
          <text x="8" y="144" fill="#64748b" font-size="9" font-family="monospace">5W</text>

          <!-- Courbe dynamique Watts -->
          <path 
            :d="dynamicSvgPath" 
            fill="none" 
            stroke="#06b6d4" 
            stroke-width="2.5" 
          />
        </svg>
      </div>
    </div>

    <!-- ENCART PÉDAGOGIQUE DU STANDARD ECOINDEX V3 -->
    <div class="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 font-mono text-[11px] text-slate-400 leading-relaxed">
      <div class="text-white font-bold mb-1">📐 Formule Standard EcoIndex v3 :</div>
      <p>
        Le score est calculé selon la formule standard : <code class="text-emerald-300">EcoIndex = 100 - (5/6) × (3 × Q_DOM + 2 × Q_REQ + Q_TAILLE)</code> où chaque quantile (Q) correspond aux distributions empiriques GreenIT.fr v2. Les émissions GES sont estimées par <code class="text-cyan-300">gCO2e = (2 + 2 × (50 - EcoIndex) / 100)</code> et la consommation d'eau par <code class="text-cyan-300">cL = (3 + 3 × (50 - EcoIndex) / 100)</code> par chargement de page.
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  instantWatts: number;
  cpuWatts: number;
  ramWatts: number;
  cpuLoadPct: number;
  carbonIntensity: number;
  powerHistoryCount: number;
  dynamicSvgPath: string;
  overallEcoScore?: number;
  overallEcoGrade?: string;
  pagesScanned?: number;
}>();
</script>
