<template>
  <div class="space-y-5">
    <!-- Sélecteur de Mode en haut : Double Flux Direct vs Mode Kanban SOC -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-2xl bg-slate-900/80 border border-slate-800">
      <div class="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800 font-mono text-xs gap-1">
        <button 
          @click="streamMode = 'streams'"
          :class="[
            'px-4 py-2 rounded-lg transition-all cursor-pointer font-bold flex items-center gap-2',
            streamMode === 'streams' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm' : 'text-slate-400 hover:text-slate-200'
          ]"
        >
          <span>📋 Double Flux Direct (Entrant ⇄ Sortant)</span>
        </button>
        
        <button 
          @click="streamMode = 'kanban'"
          :class="[
            'px-4 py-2 rounded-lg transition-all cursor-pointer font-bold flex items-center gap-2',
            streamMode === 'kanban' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm' : 'text-slate-400 hover:text-slate-200'
          ]"
        >
          <span>🗂️ Mode Kanban SOC (Triage Menaces)</span>
        </button>
      </div>

      <div class="text-xs font-mono text-slate-400 flex items-center gap-2">
        <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
        <span>Flux actif : Aegis Gate (:8000) &amp; Sinkhole (:5053)</span>
      </div>
    </div>

    <!-- SOUS-VUE A : MODE KANBAN INTÉGRÉ DIRECTEMENT -->
    <div v-if="streamMode === 'kanban'">
      <AegisTriageKanban />
    </div>

    <!-- SOUS-VUE B : DOUBLE FLUX DIRECT (INGRESS vs EGRESS + GEOIP À LA DEMANDE) -->
    <div v-else class="space-y-5">
      <!-- Barre d'outils & Filtres des Flux -->
      <div class="p-4 rounded-2xl bg-slate-900/70 border border-slate-800/90 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div class="flex flex-wrap items-center gap-2 font-mono text-xs">
          <span class="text-slate-400 mr-1">Filtrer Ingress :</span>
          <button 
            @click="streamFilter = 'all'"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all', streamFilter === 'all' ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-bold' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            Tous ({{ ingressStream.length }})
          </button>
          <button 
            @click="streamFilter = 'probes'"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all', streamFilter === 'probes' ? 'bg-amber-500/20 border-amber-500/50 text-amber-300 font-bold' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            🤖 Scans Bots PHP/WP ({{ probeEventsCount }})
          </button>
          <button 
            @click="streamFilter = 'exploits'"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all', streamFilter === 'exploits' ? 'bg-rose-500/20 border-rose-500/50 text-rose-300 font-bold' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            💥 Exploits Critiques ({{ exploitEventsCount }})
          </button>
          <button 
            @click="streamFilter = 'clean'"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all', streamFilter === 'clean' ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300 font-bold' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            ✓ Trafic Légitime ({{ cleanEventsCount }})
          </button>
        </div>

        <div class="flex flex-wrap items-center gap-2.5 font-mono text-xs">
          <button 
            @click="handleSimulate"
            :disabled="isSimulatingProbes"
            class="px-3.5 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 font-bold transition-all cursor-pointer flex items-center gap-1.5"
            title="Envoyer de vraies requêtes de scan (wp-login.php, wp-content, xmlrpc.php, .env) sur Aegis Gate (:8000)"
          >
            <span>⚡ {{ isSimulatingProbes ? 'Envoi en cours...' : 'Simuler Scans Bots (wp-login / .env)' }}</span>
          </button>

          <button 
            @click="showGeoMap = !showGeoMap"
            :class="[
              'px-3.5 py-2 rounded-xl border font-bold transition-all cursor-pointer flex items-center gap-1.5',
              showGeoMap ? 'bg-cyan-500/25 border-cyan-400 text-cyan-200' : 'bg-slate-950 border-slate-700 text-slate-300 hover:text-white'
            ]"
          >
            <span>🗺️ {{ showGeoMap ? 'Masquer Carte GeoIP' : 'Voir Carte GeoIP des Requêtes' }}</span>
          </button>
        </div>
      </div>

      <!-- CARTE GEOIP À LA DEMANDE -->
      <div v-if="showGeoMap" class="p-4 rounded-2xl bg-slate-900/70 border border-cyan-500/30 shadow-xl">
        <div class="flex items-center justify-between mb-3 font-mono text-xs">
          <span class="text-cyan-300 font-bold">🗺️ Cartographie GeoIP Temps Réel des Requêtes Interceptées</span>
          <span class="text-slate-400">{{ mapEvents.length }} points géolocalisés</span>
        </div>
        <AegisOsmMap :events="mapEvents" />
      </div>

      <!-- DOUBLE LISTE CÔTE À CÔTE : INGRESS (GAUCHE) vs EGRESS (DROITE) -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
        
        <!-- COLONNE GAUCHE : REQUÊTES ENTRANTES (INGRESS :8000) -->
        <div class="bg-slate-900/60 border border-slate-800/90 rounded-2xl p-5 flex flex-col">
          <div class="flex items-center justify-between pb-3.5 mb-3 border-b border-slate-800">
            <div>
              <h2 class="text-sm font-bold text-white flex items-center gap-2 font-mono">
                <span class="text-cyan-400">⬇️</span>
                <span>FLUX ENTRANT (INGRESS — Aegis Gate :8000)</span>
              </h2>
              <p class="text-[11px] text-slate-400 mt-0.5">
                Détection des scans bots (WordPress/PHP), OWASP Top 10 &amp; Buffer Overflows (413)
              </p>
            </div>
            <span class="px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono text-xs font-bold">
              {{ filteredIngressStream.length }} req
            </span>
          </div>

          <div v-if="filteredIngressStream.length === 0" class="py-12 text-center text-slate-500 font-mono text-xs">
            Aucune requête entrante dans ce filtre. Cliquez sur « ⚡ Simuler Scans Bots » ou lancez <code class="text-cyan-400">./scripts/run-pentest-demo.sh</code>.
          </div>

          <div v-else class="space-y-2.5 max-h-[560px] overflow-y-auto pr-1 font-mono text-xs">
            <div 
              v-for="item in filteredIngressStream" 
              :key="item.id"
              class="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 hover:border-slate-700 transition-all"
            >
              <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-2 min-w-0">
                  <span 
                    :class="[
                      'px-2 py-0.5 rounded text-[10px] font-extrabold shrink-0',
                      item.decision === 'BLOCK' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      item.decision === 'BYPASS' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                      'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    ]"
                  >
                    {{ item.decision === 'BLOCK' ? `BLOQUÉ (${(item as any).http_status ?? item.status_code})` : item.decision === 'BYPASS' ? `COMPROMIS (${(item as any).http_status ?? item.status_code})` : `OK (${(item as any).http_status ?? item.status_code})` }}
                  </span>
                  <span class="text-white font-bold truncate" :title="item.target">
                    {{ item.method }} {{ item.target }}
                  </span>
                </div>
                <span class="text-[10px] text-slate-500 shrink-0">{{ formatTime(item.timestamp) }}</span>
              </div>

              <div class="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px]">
                <div class="flex items-center gap-2">
                  <span class="text-slate-400">IP: <strong class="text-slate-200">{{ item.client_ip }}</strong></span>
                  <span class="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 text-[10px]">
                    {{ item.category || 'TRAFFIC' }}
                  </span>
                </div>

                <div class="flex items-center gap-2">
                  <span 
                    :class="[
                      'text-[10px] font-bold px-1.5 py-0.5 rounded',
                      ((item as any).hack_probability ?? 95) >= 85 ? 'bg-rose-950 text-rose-300 border border-rose-500/30' : 'bg-slate-900 text-emerald-400'
                    ]"
                  >
                    Prob. Scan/Hack : {{ (item as any).hack_probability ?? (item.decision === 'ALLOW' ? 5 : 95) }}%
                  </span>

                  <button 
                    v-if="item.decision !== 'ALLOW'"
                    @click="$emit('quick-ban', item.client_ip, item.category || 'Exploit')"
                    class="px-2 py-0.5 rounded bg-rose-500/15 hover:bg-rose-500/30 text-rose-300 border border-rose-500/30 text-[10px] font-bold cursor-pointer"
                    title="Bannir immédiatement cette IP sur Aegis Gate Proxy"
                  >
                    🚫 Bannir IP
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- COLONNE DROITE : REQUÊTES SORTANTES (EGRESS DNS & SOCKET :5053) -->
        <div class="bg-slate-900/60 border border-slate-800/90 rounded-2xl p-5 flex flex-col">
          <div class="flex items-center justify-between pb-3.5 mb-3 border-b border-slate-800">
            <div>
              <h2 class="text-sm font-bold text-white flex items-center gap-2 font-mono">
                <span class="text-amber-400">⬆️</span>
                <span>FLUX SORTANT (EGRESS — DNS Sinkhole &amp; Sockets :5053)</span>
              </h2>
              <p class="text-[11px] text-slate-400 mt-0.5">
                Interception des callbacks C2, Reverse Shells (/bin/sh) et tunnels DNS par Entropie de Shannon
              </p>
            </div>
            <span class="px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300 font-mono text-xs font-bold">
              {{ egressStream.length }} req
            </span>
          </div>

          <div v-if="egressStream.length === 0" class="py-12 text-center text-slate-500 font-mono text-xs">
            Aucun flux sortant enregistré. Lancez la batterie de pentest pour observer le blocage Sinkhole C2 (0.0.0.0).
          </div>

          <div v-else class="space-y-2.5 max-h-[560px] overflow-y-auto pr-1 font-mono text-xs">
            <div 
              v-for="eg in egressStream" 
              :key="eg.id"
              class="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 hover:border-slate-700 transition-all"
            >
              <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-2 min-w-0">
                  <span 
                    :class="[
                      'px-2 py-0.5 rounded text-[10px] font-extrabold shrink-0',
                      eg.decision === 'BLOCK' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      eg.decision === 'BYPASS' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                      'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    ]"
                  >
                    {{ eg.decision === 'BLOCK' ? 'SINKHOLE 0.0.0.0' : eg.decision === 'BYPASS' ? 'EXFILTRÉ (BYPASS)' : eg.decision }}
                  </span>
                  <span class="text-white font-bold truncate" :title="eg.domain || eg.target_ip">
                    DNS/TCP ➔ {{ eg.domain || eg.target_ip }}
                  </span>
                </div>
                <span class="text-[10px] text-slate-500 shrink-0">{{ formatTime(eg.timestamp) }}</span>
              </div>

              <div class="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px]">
                <div class="flex items-center gap-2">
                  <span class="text-slate-400">Entropie Shannon : <strong class="text-cyan-300">H = {{ eg.entropy || 0 }}</strong></span>
                  <span class="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-amber-300 text-[10px]">
                    {{ eg.threat_type || 'NORMAL' }}
                  </span>
                </div>

                <div class="flex items-center gap-2">
                  <span 
                    :class="[
                      'text-[10px] font-bold px-1.5 py-0.5 rounded',
                      ((eg as any).exfil_probability ?? 90) >= 80 ? 'bg-rose-950 text-rose-300 border border-rose-500/30' : 'bg-slate-900 text-emerald-400'
                    ]"
                  >
                    Prob. Exfiltration : {{ (eg as any).exfil_probability ?? (eg.decision === 'ALLOW' ? 5 : 95) }}%
                  </span>
                  <span class="text-slate-500 text-[10px]">{{ (eg as any).latency_ms ?? 4 }} ms</span>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import AegisOsmMap from '../AegisOsmMap.vue';
import AegisTriageKanban from '../AegisTriageKanban.vue';
import { type IngressEvent, type EgressEvent } from '../../../services/api/streamsApi';

defineProps<{
  ingressStream: IngressEvent[];
  egressStream: EgressEvent[];
  filteredIngressStream: IngressEvent[];
  probeEventsCount: number;
  exploitEventsCount: number;
  cleanEventsCount: number;
  mapEvents: any[];
  isSimulatingProbes: boolean;
}>();

const emit = defineEmits<{
  (e: 'simulate'): void;
  (e: 'quick-ban', ip: string, category: string): void;
}>();

const streamMode = ref<'streams' | 'kanban'>('streams');
const streamFilter = ref<'all' | 'probes' | 'exploits' | 'clean'>('all');
const showGeoMap = ref(false);

function formatTime(ts: string) {
  if (!ts) return '';
  const d = new Date(ts.replace(' ', 'T'));
  if (isNaN(d.getTime())) return ts.slice(11, 19);
  return d.toLocaleTimeString('fr-FR');
}

function handleSimulate() {
  emit('simulate');
}
</script>
