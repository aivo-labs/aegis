<template>
  <div class="flex-1 flex flex-col min-w-0 p-4 sm:p-6 lg:p-7 max-w-[1720px] mx-auto w-full text-slate-100 font-sans">
    
    <!-- TOP HEADER -->
    <ActionCenterHeader
      :icon="headerIcon"
      :title="headerTitle"
      :subtitle="headerSubtitle"
      :isLightMode="isLightMode"
      @toggle-theme="toggleTheme"
      @logout="emitLogout"
    />

    <!-- TOAST DE CONFIRMATION D'ACTION RÉELLE -->
    <transition enter-active-class="transition duration-200" enter-from-class="opacity-0 -translate-y-2" enter-to-class="opacity-100 translate-y-0" leave-active-class="transition duration-150" leave-from-class="opacity-100 translate-y-0" leave-to-class="opacity-0 -translate-y-2">
      <div v-if="actionToast" class="mt-4 p-3.5 rounded-xl bg-emerald-950/90 border border-emerald-500/40 text-emerald-300 text-xs font-mono flex items-center justify-between shadow-lg">
        <div class="flex items-center gap-2.5">
          <span class="text-base font-bold">✓</span>
          <span>{{ actionToast }}</span>
        </div>
        <button @click="actionToast = ''" class="text-emerald-400 hover:text-white font-bold cursor-pointer">✕</button>
      </div>
    </transition>

    <!-- PANELS SELON L'ONGLET ACTIF -->
    <div class="mt-6">
      <AuditPanel 
        v-if="activeTab === 'audit'"
        :initialDomain="initialDomain"
        @toast="showToast"
        @scan-completed="fetchCveFeed"
      />

      <StreamsPanel 
        v-else-if="activeTab === 'streams'"
        :ingressStream="ingressStream"
        :egressStream="egressStream"
        :filteredIngressStream="filteredIngressStream"
        :probeEventsCount="probeEventsCount"
        :exploitEventsCount="exploitEventsCount"
        :cleanEventsCount="cleanEventsCount"
        :mapEvents="mapEvents"
        :isSimulatingProbes="isSimulatingProbes"
        @simulate="handleSimulateProbes"
        @quick-ban="handleQuickBan"
      />

      <TelemetryPanel 
        v-else-if="activeTab === 'telemetry'"
        :instantWatts="instantWatts"
        :cpuWatts="cpuWatts"
        :ramWatts="ramWatts"
        :cpuLoadPct="cpuLoadPct"
        :carbonIntensity="carbonIntensity"
        :powerHistoryCount="powerHistory.length"
        :dynamicSvgPath="dynamicSvgPath"
      />

      <CveFeedPanel 
        v-else-if="activeTab === 'cve'"
        :activeRulesCount="activeRulesCount"
        :blockedByPatchCount="blockedByPatchCount"
        :exposedCves="exposedCves"
        :catalogCves="catalogCves"
      />

      <ControlsPanel 
        v-else-if="activeTab === 'controls'"
        :bannedIps="bannedIps"
        :maxPayloadBytes="maxPayloadBytes"
        :retention="retention"
        @add-ban="handleAddBan"
        @remove-ban="handleRemoveBan"
        @update-payload-limit="handleUpdatePayloadLimit"
        @save-retention="handleSaveRetention"
        @purge-clean="handlePurgeClean"
      />

      <RoadmapPanel v-else />
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import ActionCenterHeader from './actions/ActionCenterHeader.vue';
import AuditPanel from './actions/AuditPanel.vue';
import StreamsPanel from './actions/StreamsPanel.vue';
import TelemetryPanel from './actions/TelemetryPanel.vue';
import CveFeedPanel from './actions/CveFeedPanel.vue';
import ControlsPanel from './actions/ControlsPanel.vue';
import RoadmapPanel from './actions/RoadmapPanel.vue';

import { useAegisTheme } from '../../composables/useAegisTheme';
import { useLiveStreams } from '../../composables/useLiveStreams';
import { useTelemetry } from '../../composables/useTelemetry';
import { useCveFeed } from '../../composables/useCveFeed';
import { useControls } from '../../composables/useControls';

const props = withDefaults(defineProps<{
  initialTab?: string;
  initialDomain?: string;
}>(), {
  initialTab: 'audit',
  initialDomain: '',
});

const emit = defineEmits<{
  (e: 'logout'): void;
}>();

const actionToast = ref('');
function showToast(msg: string) {
  actionToast.value = msg;
  setTimeout(() => {
    if (actionToast.value === msg) actionToast.value = '';
  }, 4500);
}

// Composables
const { isLightMode, toggleTheme } = useAegisTheme();
const { 
  ingressStream, egressStream, filteredIngressStream, 
  probeEventsCount, exploitEventsCount, cleanEventsCount, 
  mapEvents, isSimulatingProbes, fetchLiveStreams, simulateBotProbes 
} = useLiveStreams();

const { 
  instantWatts, cpuWatts, ramWatts, cpuLoadPct, carbonIntensity, 
  powerHistory, dynamicSvgPath, fetchTelemetry 
} = useTelemetry();

const { 
  activeRulesCount, blockedByPatchCount, exposedCves, catalogCves, fetchCveFeed 
} = useCveFeed();

const { 
  bannedIps, maxPayloadBytes, retention, fetchControls, 
  addBan, removeBan, updatePayloadLimit, saveRetention, purgeCleanLogs 
} = useControls();

// Navigation Tabs
const activeTab = ref(
  ['audit', 'streams', 'telemetry', 'cve', 'controls', 'roadmap', 'security', 'green', 'compliance'].includes(props.initialTab)
    ? (props.initialTab === 'security' ? 'streams' : props.initialTab === 'green' ? 'telemetry' : props.initialTab === 'compliance' ? 'controls' : props.initialTab)
    : 'audit'
);

const headerIcon = computed(() => {
  if (activeTab.value === 'audit') return '🔍';
  if (activeTab.value === 'streams') return '📡';
  if (activeTab.value === 'telemetry') return '🌿';
  if (activeTab.value === 'cve') return '🛡️';
  if (activeTab.value === 'controls') return '⚙️';
  return '🗺️';
});

const headerTitle = computed(() => {
  if (activeTab.value === 'audit') return 'Diagnostic Passif (5 Pages), CVE & Homologation DNS';
  if (activeTab.value === 'streams') return 'Flux Ingress ⇄ Egress (Direct & Kanban)';
  if (activeTab.value === 'telemetry') return 'Télémétrie RAPL & Éco-Conception EcoIndex v3';
  if (activeTab.value === 'cve') return 'Intelligence Vulnérabilités & CVE Feed';
  if (activeTab.value === 'controls') return 'Contrôles Edge, Ban IP & Rétention ANSSI / RGPD';
  return 'Roadmap Publique & Architecture Open-Core';
});

const headerSubtitle = computed(() => {
  if (activeTab.value === 'audit') return "Analyse réelle par Goroutines : versions exposées, alertes CVE, EcoIndex v3 et contrat d'autorisation DNS TXT";
  if (activeTab.value === 'streams') return 'Visibilité complète sur les requêtes entrantes (scans wp-login, .env, exploits) et sortantes (DNS C2 / Sockets)';
  if (activeTab.value === 'telemetry') return 'Mesures en temps réel de puissance matérielle (/sys/class/powercap) et registres CPU Linux';
  if (activeTab.value === 'cve') return 'Surveillance continue des failles exposées sur votre périmètre et des règles actives en production';
  if (activeTab.value === 'controls') return 'Actions réelles synchronisées avec Aegis Gate Proxy (:8000) et PostgreSQL / TimescaleDB';
  return 'État transparent des fonctionnalités en production (v1.5) et des chantiers communautaires (v2.0)';
});

const emitLogout = async () => {
  emit('logout');
  if (typeof window !== 'undefined') {
    try {
      const res = await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        if (data && data.logout_url) {
          window.location.href = data.logout_url;
          return;
        }
      }
    } catch {}
    window.location.href = '/login/';
  }
};

async function handleSimulateProbes() {
  await simulateBotProbes();
  showToast('6 sondes bots (wp-login.php, wp-content, xmlrpc.php, .env, phpmyadmin, SQLi) envoyées et interceptées par Aegis Gate !');
}

async function handleQuickBan(ip: string, category: string) {
  const msg = await addBan(ip, `Blocage SOC suite à : ${category}`);
  if (msg) showToast(msg);
}

async function handleAddBan(ip: string, reason: string) {
  const msg = await addBan(ip, reason);
  if (msg) showToast(msg);
}

async function handleRemoveBan(ip: string) {
  const msg = await removeBan(ip);
  if (msg) showToast(msg);
}

async function handleUpdatePayloadLimit(limit: number) {
  const msg = await updatePayloadLimit(limit);
  if (msg) showToast(msg);
}

async function handleSaveRetention() {
  const msg = await saveRetention();
  if (msg) showToast(msg);
}

async function handlePurgeClean() {
  const msg = await purgeCleanLogs();
  if (msg) {
    showToast(msg);
    fetchLiveStreams();
  }
}

let pollTimer: any = null;

onMounted(() => {
  fetchLiveStreams();
  fetchTelemetry();
  fetchCveFeed();
  fetchControls();

  pollTimer = setInterval(() => {
    fetchLiveStreams();
    if (activeTab.value === 'telemetry') fetchTelemetry();
    if (activeTab.value === 'cve') fetchCveFeed();
  }, 3000);
});

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});
</script>
