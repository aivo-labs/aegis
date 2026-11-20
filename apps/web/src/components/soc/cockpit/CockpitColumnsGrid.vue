<template>
  <section class="grid grid-cols-1 lg:grid-cols-12 gap-4 mt-5 items-stretch">
    <!-- COLONNE 1 : FLUX INGRESS/EGRESS & NŒUDS ACTIFS (4 COLS) -->
    <div class="lg:col-span-4 bg-slate-900/75 border border-slate-800/90 rounded-lg p-4 flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div class="flex items-center gap-2">
            <AegisIcon name="shield" size="sm" class="text-emerald-400" />
            <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-200">{{ t.cockpit.columns.supervisionTitle }}</h2>
          </div>
          <button
            type="button"
            @click="$emit('switch-nav', 'streams')"
            class="text-xs font-medium text-emerald-400 hover:text-emerald-300 cursor-pointer"
          >
            {{ t.cockpit.columns.dualStreamBtn }}
          </button>
        </div>

        <div class="mt-3.5 grid grid-cols-2 gap-2.5 font-mono tabular-nums">
          <div class="p-3 rounded-lg bg-slate-950/90 border border-slate-800/80">
            <div class="text-[10px] font-sans font-semibold text-slate-400 uppercase tracking-wider">{{ t.cockpit.columns.ingressIn }}</div>
            <div class="text-xl font-bold text-white mt-1">{{ traffic.ingress_total || 0 }}</div>
            <div class="text-[11px] text-slate-400 mt-1">
              <span class="text-rose-400 font-semibold">{{ traffic.ingress_blocked || 0 }}</span> {{ t.cockpit.columns.ingressBlocked }}
            </div>
          </div>

          <div class="p-3 rounded-lg bg-slate-950/90 border border-slate-800/80">
            <div class="text-[10px] font-sans font-semibold text-slate-400 uppercase tracking-wider">{{ t.cockpit.columns.egressOut }}</div>
            <div class="text-xl font-bold text-white mt-1">{{ traffic.egress_total || 0 }}</div>
            <div class="text-[11px] text-slate-400 mt-1">
              <span class="text-rose-400 font-semibold">{{ traffic.egress_blocked || 0 }}</span> {{ t.cockpit.columns.egressCut }}
            </div>
          </div>
        </div>

        <div class="mt-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-center justify-between gap-3">
          <div class="text-xs text-slate-300 leading-relaxed">
            {{ t.cockpit.columns.kanbanNotice }}
          </div>
          <button
            type="button"
            @click="$emit('switch-nav', 'streams')"
            class="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100 text-xs font-semibold shrink-0 cursor-pointer transition-colors"
          >
            {{ t.cockpit.columns.openBtn }}
          </button>
        </div>

        <!-- Nœuds Surveillés -->
        <div class="mt-3.5 bg-slate-950/70 border border-slate-800/80 rounded-lg p-3">
          <div class="flex items-center justify-between text-xs mb-2">
            <span class="text-slate-300 font-semibold flex items-center gap-1.5">
              <AegisIcon name="server" size="xs" class="text-slate-400" />
              <span>{{ t.cockpit.columns.monitoredServices }}</span>
            </span>
            <span class="text-[10px] font-mono tabular-nums px-2 py-0.5 rounded bg-slate-900 text-emerald-400 border border-slate-800">
              {{ (monitoredNodes || []).length }} {{ t.cockpit.columns.activeCount }}
            </span>
          </div>

          <div v-if="monitoredNodes && monitoredNodes.length > 0" class="divide-y divide-slate-800/60 max-h-40 overflow-y-auto">
            <div
              v-for="(node, idx) in monitoredNodes"
              :key="idx"
              class="flex items-center justify-between text-xs font-mono tabular-nums py-1.5 px-1"
            >
              <div class="flex items-center gap-2 min-w-0">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0"></span>
                <span class="text-slate-200 text-[11px] truncate">{{ node.service_name || node.hostname || node.service || node.name || 'aegis-node' }}</span>
              </div>
              <div class="flex items-center gap-2.5 shrink-0">
                <span class="text-slate-200 text-[11px] font-semibold">{{ Number(node.watts || node.avg_watts || 0).toFixed(2) }} W</span>
                <span class="text-emerald-400 text-[10px]">{{ node.status || 'RAPL' }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="mt-4 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span>{{ t.cockpit.columns.architecture }}</span>
        <span class="text-slate-200">Gate PEP (:8000) · Sinkhole (:5053)</span>
      </div>
    </div>

    <!-- COLONNE 2 : TÉLÉMÉTRIE MATÉRIELLE & DIAGNOSTIC RAPIDE (5 COLS) -->
    <div class="lg:col-span-5 bg-slate-900/75 border border-slate-800/90 rounded-lg p-4 flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div class="flex items-center gap-2">
            <AegisIcon name="cpu" size="sm" class="text-emerald-400" />
            <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-200">{{ t.cockpit.columns.greenTitle }}</h2>
          </div>
          <button
            type="button"
            @click="$emit('switch-nav', 'telemetry')"
            class="text-xs font-medium text-emerald-400 hover:text-emerald-300 cursor-pointer"
          >
            {{ t.cockpit.columns.greenDetailsBtn }}
          </button>
        </div>

        <div class="mt-3 flex items-center justify-between text-[11px] font-mono tabular-nums">
          <span class="flex items-center gap-1.5 text-slate-300">
            <span class="w-2.5 h-0.5 bg-emerald-400 inline-block"></span>
            {{ t.cockpit.columns.measuredPower }}
          </span>
          <span class="text-slate-400">
            {{ powerHistoryCount }} {{ t.cockpit.columns.pts }}
          </span>
        </div>

        <!-- REALTIME HARDWARE WATTS SVG CHART -->
        <div class="mt-2 bg-slate-950/90 border border-slate-800/90 rounded-lg p-3 relative">
          <div class="w-full h-40 relative">
            <svg viewBox="0 0 500 180" class="w-full h-full overflow-visible">
              <defs>
                <linearGradient id="powerLineFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#10b981" stop-opacity="0.18" />
                  <stop offset="100%" stop-color="#10b981" stop-opacity="0.0" />
                </linearGradient>
              </defs>

              <line x1="40" y1="25" x2="480" y2="25" stroke="#1e293b" stroke-dasharray="2,2" />
              <text x="6" y="29" fill="#64748b" font-size="9" font-family="monospace">25W</text>

              <line x1="40" y1="70" x2="480" y2="70" stroke="#1e293b" stroke-dasharray="2,2" />
              <text x="6" y="74" fill="#64748b" font-size="9" font-family="monospace">18W</text>

              <line x1="40" y1="115" x2="480" y2="115" stroke="#1e293b" stroke-dasharray="2,2" />
              <text x="6" y="119" fill="#64748b" font-size="9" font-family="monospace">12W</text>

              <line x1="40" y1="155" x2="480" y2="155" stroke="#1e293b" stroke-dasharray="2,2" />
              <text x="6" y="159" fill="#64748b" font-size="9" font-family="monospace">5W</text>

              <path
                v-if="areaPowerPath"
                :d="areaPowerPath"
                fill="url(#powerLineFill)"
              />

              <path
                :d="dynamicPowerPath"
                fill="none"
                stroke="#10b981"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>

            <div class="absolute right-2.5 top-2 px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono tabular-nums text-emerald-400">
              {{ t.cockpit.columns.liveDirect }} {{ instantWatts.toFixed(2) }} W
            </div>
          </div>
        </div>

        <!-- CARTE DE SYNTHÈSE DIAGNOSTIC 5 PAGES -->
        <div class="mt-3.5 bg-slate-950/70 border border-slate-800/80 rounded-lg p-3.5">
          <div class="flex items-center justify-between gap-3">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center shrink-0 text-emerald-400">
                <AegisIcon name="search" size="md" />
              </div>
              <div>
                <div class="text-xs font-semibold text-white">{{ t.cockpit.columns.diagTitle }}</div>
                <div class="text-[11px] text-slate-400 mt-0.5">
                  {{ t.cockpit.columns.diagDesc }}
                </div>
              </div>
            </div>

            <button
              type="button"
              @click="$emit('switch-nav', 'audit')"
              class="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100 text-xs font-semibold shrink-0 cursor-pointer transition-colors"
            >
              {{ t.cockpit.columns.openDiagBtn }}
            </button>
          </div>
        </div>
      </div>

      <div class="mt-4 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span>{{ t.cockpit.columns.measureLabel }}</span>
        <span class="text-slate-200">{{ t.cockpit.columns.measureValue }}</span>
      </div>
    </div>

    <!-- COLONNE 3 : GOUVERNANCE & RÉTENTION ANSSI / RGPD (3 COLS) -->
    <div class="lg:col-span-3 bg-slate-900/75 border border-slate-800/90 rounded-lg p-4 flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div class="flex items-center gap-2">
            <AegisIcon name="scale" size="sm" class="text-emerald-400" />
            <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-200">{{ t.cockpit.columns.governanceTitle }}</h2>
          </div>
          <button
            type="button"
            @click="$emit('switch-nav', 'controls')"
            class="text-xs font-medium text-emerald-400 hover:text-emerald-300 cursor-pointer"
          >
            {{ t.cockpit.columns.controlsBtn }}
          </button>
        </div>

        <div class="mt-3.5 space-y-3">
          <div class="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div class="flex items-center justify-between">
              <span class="text-xs font-semibold text-white">{{ t.cockpit.columns.retentionTitle }}</span>
              <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">ANSSI · RGPD</span>
            </div>
            <div class="mt-2.5 space-y-1.5 text-[11px] font-mono tabular-nums text-slate-300">
              <div class="flex justify-between">
                <span class="text-slate-400 font-sans">{{ t.cockpit.columns.hotWindow }}</span>
                <span class="text-slate-200 font-semibold">{{ retention?.hot_window_days || 30 }} {{ t.cockpit.columns.days }}</span>
              </div>
              <div class="flex justify-between">
                <span class="text-slate-400 font-sans">{{ t.cockpit.columns.forensicAnssi }}</span>
                <span class="text-slate-200 font-semibold">{{ retention?.anssi_forensic_days || 180 }} {{ t.cockpit.columns.days }}</span>
              </div>
              <div class="flex justify-between">
                <span class="text-slate-400 font-sans">{{ t.cockpit.columns.purgeRgpd }}</span>
                <span class="text-emerald-400 font-semibold">{{ retention?.rgpd_clean_ip_days || 7 }} {{ t.cockpit.columns.days }}</span>
              </div>
            </div>
          </div>

          <div class="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div class="flex items-center justify-between">
              <span class="text-xs font-semibold text-white">{{ t.cockpit.columns.virtualPatching }}</span>
              <span class="text-emerald-400 text-[11px] font-mono font-semibold">{{ t.cockpit.columns.rulesCount }}</span>
            </div>
            <ul class="mt-2 space-y-1 text-[11px] text-slate-400 leading-relaxed">
              <li>· {{ t.cockpit.columns.rule1 }}</li>
              <li>· {{ t.cockpit.columns.rule2 }}</li>
              <li>· {{ t.cockpit.columns.rule3 }}</li>
            </ul>
          </div>
        </div>
      </div>

      <!-- Export JSON Brut -->
      <div class="mt-4 pt-2.5 border-t border-slate-800/80">
        <button
          type="button"
          @click="$emit('export-report')"
          class="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100 font-semibold text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
        >
          <AegisIcon name="download" size="xs" />
          <span>{{ t.cockpit.columns.exportReportBtn }}</span>
        </button>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import AegisIcon from '../AegisIcon.vue';
import { useI18n } from '../../../composables/useI18n';

const { t } = useI18n();

const props = defineProps<{
  traffic: any;
  monitoredNodes: any[];
  powerHistoryCount: number;
  dynamicPowerPath: string;
  instantWatts: number;
  retention: any;
}>();

defineEmits<{
  (e: 'switch-nav', nav: string): void;
  (e: 'export-report'): void;
}>();

const areaPowerPath = computed(() => {
  if (!props.dynamicPowerPath || !props.dynamicPowerPath.startsWith('M ')) return '';
  return `${props.dynamicPowerPath} L 480,155 L 40,155 Z`;
});
</script>
