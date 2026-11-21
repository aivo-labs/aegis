<template>
  <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 mt-5">
    <!-- CARD 1: FLUX RÉSEAU GLOBAL -->
    <div class="bg-slate-900/75 border border-slate-800/90 hover:border-slate-700 rounded-lg p-4 transition-colors">
      <div class="flex items-center justify-between text-[11px] text-slate-400 font-semibold uppercase tracking-wider mb-1.5">
        <span>{{ t.cockpit.kpi.trafficObserved }}</span>
        <span class="text-[10px] font-mono font-normal lowercase text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">{{ t.cockpit.kpi.livePostgres }}</span>
      </div>
      <div class="flex items-baseline gap-1.5 mt-1">
        <span class="text-2xl sm:text-3xl font-bold text-white tracking-tight font-mono tabular-nums">{{ formatNumber(traffic.total_requests_24h) }}</span>
        <span class="text-xs text-slate-400">{{ t.cockpit.kpi.events }}</span>
      </div>
      <div class="mt-3 pt-2.5 border-t border-slate-800/70 flex items-center justify-between text-[11px] font-mono tabular-nums">
        <span class="text-emerald-400 font-semibold">
          {{ traffic.clean_traffic_pct ?? 100 }}% {{ t.cockpit.kpi.clean }}
        </span>
        <span class="text-slate-400">In: {{ traffic.ingress_total || 0 }} · Out: {{ traffic.egress_total || 0 }}</span>
        <span class="text-slate-500">{{ traffic.avg_latency_ms || 0 }} ms</span>
      </div>
    </div>

    <!-- CARD 2: TAUX D'INTERCEPTION -->
    <div class="bg-slate-900/75 border border-slate-800/90 hover:border-slate-700 rounded-lg p-4 transition-colors">
      <div class="flex items-center justify-between text-[11px] text-slate-400 font-semibold uppercase tracking-wider mb-1.5">
        <span>{{ t.cockpit.kpi.interceptionRate }}</span>
        <span class="text-[10px] font-mono font-normal lowercase text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">{{ t.cockpit.kpi.blockedOverTotal }}</span>
      </div>
      <div class="flex items-baseline gap-1 mt-1">
        <span class="text-2xl sm:text-3xl font-bold text-white tracking-tight font-mono tabular-nums">{{ interceptionRate }}</span>
        <span class="text-xs text-slate-400 font-mono">%</span>
      </div>
      <div class="mt-3 pt-2.5 border-t border-slate-800/70 flex items-center justify-between text-[11px] font-mono tabular-nums">
        <span class="text-slate-300">{{ t.cockpit.kpi.blocked }} <strong class="text-emerald-400">{{ traffic.blocked_threats_total || 0 }}</strong></span>
        <span :class="(traffic.compromised_bypass_total || 0) > 0 ? 'text-rose-400 font-semibold' : 'text-slate-500'">
          {{ t.cockpit.kpi.bypassed }} {{ traffic.compromised_bypass_total || 0 }}
        </span>
      </div>
    </div>

    <!-- CARD 3: PUISSANCE MATÉRIELLE (RAPL) -->
    <div class="bg-slate-900/75 border border-slate-800/90 hover:border-slate-700 rounded-lg p-4 transition-colors">
      <div class="flex items-center justify-between text-[11px] text-slate-400 font-semibold uppercase tracking-wider mb-1.5">
        <span>{{ t.cockpit.kpi.hardwarePower }}</span>
        <span class="text-[10px] font-mono font-normal lowercase text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">{{ t.cockpit.kpi.linuxProbe }}</span>
      </div>
      <div class="flex items-baseline justify-between mt-1">
        <div class="flex items-baseline gap-1">
          <span class="text-2xl sm:text-3xl font-bold text-white tracking-tight font-mono tabular-nums">{{ (instantWatts || 0).toFixed(2) }}</span>
          <span class="text-xs text-slate-400 font-mono">W</span>
        </div>
        <span class="text-xs font-mono tabular-nums text-emerald-400 font-semibold">{{ green.carbon_intensity_gco2_h || 0 }} gCO2/h</span>
      </div>
      <div class="mt-3 pt-2.5 border-t border-slate-800/70 flex items-center justify-between text-[11px] font-mono tabular-nums text-slate-400">
        <span>CPU: {{ green.cpu_watts || 0 }} W · RAM: {{ green.ram_watts || 0 }} W</span>
        <span class="text-slate-500">{{ t.cockpit.kpi.mixFr }}</span>
      </div>
    </div>

    <!-- CARD 4: MENACES & SCANS BOTS NEUTRALISÉS -->
    <div class="bg-slate-900/75 border border-slate-800/90 hover:border-slate-700 rounded-lg p-4 transition-colors">
      <div class="flex items-center justify-between text-[11px] text-slate-400 font-semibold uppercase tracking-wider mb-1.5">
        <span>{{ t.cockpit.kpi.threatsNeutralized }}</span>
        <span class="text-[10px] font-mono font-normal lowercase text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">{{ t.cockpit.kpi.gateEgress }}</span>
      </div>
      <div class="flex items-baseline gap-1.5 mt-1">
        <span class="text-2xl sm:text-3xl font-bold text-white tracking-tight font-mono tabular-nums">{{ formatNumber(traffic.blocked_threats_total) }}</span>
        <span class="text-xs text-slate-400">{{ t.cockpit.kpi.neutralized }}</span>
      </div>
      <div class="mt-3 pt-2.5 border-t border-slate-800/70 flex items-center justify-between text-[11px] font-mono tabular-nums text-slate-400">
        <span>{{ t.cockpit.kpi.waf }} <strong class="text-slate-200">{{ traffic.ingress_blocked || 0 }}</strong></span>
        <span>{{ t.cockpit.kpi.cmsBots }} <strong class="text-amber-400">{{ traffic.bot_probes_total || 0 }}</strong></span>
        <span>{{ t.cockpit.kpi.c2 }} <strong class="text-rose-400">{{ traffic.egress_blocked || 0 }}</strong></span>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { useI18n } from '../../../composables/useI18n';

const { t, locale } = useI18n();

withDefaults(defineProps<{
  traffic: {
    total_requests_24h: number;
    clean_traffic_pct: number;
    ingress_total: number;
    egress_total: number;
    avg_latency_ms: number;
    blocked_threats_total: number;
    compromised_bypass_total: number;
    ingress_blocked?: number;
    bot_probes_total?: number;
    egress_blocked?: number;
  };
  green: {
    cpu_watts: number;
    ram_watts: number;
    carbon_intensity_gco2_h: number;
  };
  instantWatts: number;
  interceptionRate: number;
  isLoading?: boolean;
}>(), {
  isLoading: false,
});

function formatNumber(n: number) {
  return new Intl.NumberFormat(locale.value === 'fr' ? 'fr-FR' : 'en-US').format(n || 0);
}
</script>
