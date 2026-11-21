<template>
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs">
    <!-- 1. BANNISSEMENT IP TEMPS RÉEL & AUTO-JAIL (VERROU N°3 P1) -->
    <div class="p-5 rounded-lg bg-slate-900/75 border border-slate-800/90 flex flex-col justify-between space-y-4">
      <div>
        <div class="flex items-center justify-between gap-2 mb-1.5">
          <div class="flex items-center gap-1.5 text-rose-400 font-semibold uppercase tracking-wider text-[11px]">
            <AegisIcon name="shield-alert" size="xs" />
            <span>{{ isEn ? 'ACTIVE IP QUARANTINE (:8000)' : 'QUARANTAINE IP ACTIVE (:8000)' }}</span>
          </div>
          <span class="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] text-emerald-400">
            {{ isEn ? 'Auto-Jail 15m · 60 req/10s' : 'Auto-Jail 15m · 60 req/10s' }}
          </span>
        </div>
        <h3 class="text-base font-bold text-white mb-1.5">
          {{ isEn ? 'Real-Time IP Ban & Volumetric Auto-Jail' : 'Bannissement IP & Auto-Jail Volumétrique' }}
        </h3>
        <p class="text-slate-400 text-xs leading-relaxed mb-4">
          {{ isEn
            ? 'IPs banned manually or triggered by Verrou #3 Auto-Jail (3 critical offenses in 5 min) are synchronized in memory on gate-proxy (HTTP 403 / 429).'
            : 'Les adresses IP bannies manuellement ou par Auto-Jail Verrou n°3 (3 offenses critiques en 5 min) sont synchronisées en mémoire sur gate-proxy (HTTP 403 / 429).' }}
        </p>

        <form @submit.prevent="handleAddBan" class="space-y-2.5 mb-4">
          <input
            v-model="newBanIp"
            type="text"
            required
            placeholder="Ex: 185.220.101.99"
            class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono text-xs focus:outline-none focus:border-emerald-500/70"
          />
          <input
            v-model="newBanReason"
            type="text"
            :placeholder="isEn ? 'Reason (e.g. WordPress scan / Brute-force)' : 'Motif (ex: Scan WordPress / Brute-force)'"
            class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs focus:outline-none focus:border-emerald-500/70"
          />
          <button
            type="submit"
            class="w-full py-2 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/35 text-rose-300 font-semibold cursor-pointer transition-colors"
          >
            {{ isEn ? '+ Add to Edge Quarantine List' : '+ Ajouter à la Quarantaine Edge' }}
          </button>
        </form>

        <div class="space-y-2 max-h-48 overflow-y-auto">
          <div v-if="bannedIps.length === 0" class="text-slate-500 text-center py-3 font-mono">
            {{ isEn ? 'No quarantined IP address (0 entry).' : 'Aucune IP en quarantaine actuellement (0 entrée).' }}
          </div>
          <div
            v-for="b in bannedIps"
            :key="(b as any).ip_address ?? b.ip"
            class="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-2"
          >
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="text-white font-mono font-bold tabular-nums">{{ (b as any).ip_address ?? b.ip }}</span>
                <span
                  :class="[
                    'px-1.5 py-0.2 rounded text-[10px] font-mono border',
                    isAutoJailReason(b.reason)
                      ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                      : 'bg-slate-900 text-slate-400 border-slate-800'
                  ]"
                >
                  {{ isAutoJailReason(b.reason) ? 'AUTO-JAIL 15m' : 'SOC MANUAL' }}
                </span>
              </div>
              <div class="text-[11px] text-slate-400 truncate mt-0.5">{{ b.reason }}</div>
            </div>
            <button
              type="button"
              @click="$emit('remove-ban', (b as any).ip_address ?? b.ip)"
              class="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-[11px] font-medium cursor-pointer shrink-0 transition-colors"
            >
              {{ isEn ? 'Unban' : 'Lever' }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 2. CALIBRAGE DU COUPE-CIRCUIT VOLUMÉTRIQUE (413 BUFFER OVERFLOW & 431 HEADERS) -->
    <div class="p-5 rounded-lg bg-slate-900/75 border border-slate-800/90 flex flex-col justify-between space-y-4">
      <div>
        <div class="flex items-center gap-1.5 text-emerald-400 font-semibold uppercase tracking-wider text-[11px] mb-1.5">
          <AegisIcon name="shield" size="xs" />
          <span>{{ isEn ? 'VOLUMETRIC & PROTOCOL GUARD (HTTP 413 / 431)' : 'COUPE-CIRCUIT VOLUMÉTRIQUE & PROTOCOLE (HTTP 413 / 431)' }}</span>
        </div>
        <h3 class="text-base font-bold text-white mb-1.5">
          {{ isEn ? 'Anti-Buffer Overflow & Header Hardening' : 'Seuil Anti-Buffer Overflow & En-têtes RFC' }}
        </h3>
        <p class="text-slate-400 text-xs leading-relaxed mb-4">
          {{ isEn
            ? 'Sets the maximum inbound payload size on gate-proxy before immediate TCP stream termination (CVE-2026-109618), paired with 8 KB HTTP header limits (HTTP 431).'
            : 'Définit la taille maximale autorisée par requête entrante sur gate-proxy avant coupure immédiate du flux TCP (CVE-2026-109618), couplée à la limite 8 Ko des en-têtes (HTTP 431).' }}
        </p>

        <div class="p-3.5 rounded-lg bg-slate-950 border border-slate-800 mb-4">
          <div class="text-slate-400 text-[11px]">
            {{ isEn ? 'Active threshold in Aegis Gate Proxy:' : 'Seuil actif dans Aegis Gate Proxy :' }}
          </div>
          <div class="text-2xl font-bold text-white font-mono tabular-nums mt-1">
            {{ (maxPayloadBytes / 1024).toFixed(0) }} {{ isEn ? 'KB' : 'Ko' }}
            <span class="text-xs text-slate-400 font-normal">({{ maxPayloadBytes }} {{ isEn ? 'bytes' : 'octets' }})</span>
          </div>
        </div>

        <div class="grid grid-cols-3 gap-2 mb-4 font-mono tabular-nums">
          <button
            type="button"
            @click="$emit('update-payload-limit', 16384)"
            :class="[
              'py-2 rounded-lg border font-semibold cursor-pointer transition-colors',
              maxPayloadBytes === 16384 ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            ]"
          >
            16 {{ isEn ? 'KB (Strict)' : 'Ko (Strict)' }}
          </button>
          <button
            type="button"
            @click="$emit('update-payload-limit', 32768)"
            :class="[
              'py-2 rounded-lg border font-semibold cursor-pointer transition-colors',
              maxPayloadBytes === 32768 ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            ]"
          >
            32 {{ isEn ? 'KB (Default)' : 'Ko (Défaut)' }}
          </button>
          <button
            type="button"
            @click="$emit('update-payload-limit', 65536)"
            :class="[
              'py-2 rounded-lg border font-semibold cursor-pointer transition-colors',
              maxPayloadBytes === 65536 ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            ]"
          >
            64 {{ isEn ? 'KB (Relaxed)' : 'Ko (Souple)' }}
          </button>
        </div>
      </div>

      <div class="pt-4 border-t border-slate-800">
        <div class="flex items-center gap-1.5 text-slate-300 font-semibold text-xs mb-2">
          <AegisIcon name="cpu" size="xs" class="text-emerald-400" />
          <span>{{ isEn ? 'RAPL HARDWARE TELEMETRY EXPORT' : 'EXPORT TÉLÉMÉTRIE ÉNERGÉTIQUE RAPL' }}</span>
        </div>
        <a
          href="/api/v1/dashboard/energy/export?format=csv"
          download="aegis-rapl-telemetry.csv"
          class="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100 font-semibold flex items-center justify-center gap-2 cursor-pointer transition-colors"
        >
          <AegisIcon name="download" size="xs" />
          <span>{{ isEn ? 'Download Raw RAPL Measurements (.CSV)' : 'Télécharger les Mesures RAPL Brutes (.CSV)' }}</span>
        </a>
      </div>
    </div>

    <!-- 3. POLITIQUE DE RÉTENTION DES LOGS (ANSSI / CROWDSEC / CNIL RGPD) -->
    <div class="p-5 rounded-lg bg-slate-900/75 border border-slate-800/90 flex flex-col justify-between space-y-4">
      <div>
        <div class="flex items-center gap-1.5 text-emerald-400 font-semibold uppercase tracking-wider text-[11px] mb-1.5">
          <AegisIcon name="scale" size="xs" />
          <span>{{ isEn ? 'LOG RETENTION POLICY (ANSSI & GDPR)' : 'RÉTENTION DES JOURNAUX (ANSSI & CNIL)' }}</span>
        </div>
        <h3 class="text-base font-bold text-white mb-1.5">
          {{ isEn ? 'Lifecycle & GDPR Data Minimization' : 'Cycle de Vie & Minimisation RGPD' }}
        </h3>
        <p class="text-slate-400 text-xs leading-relaxed mb-4">
          {{ isEn
            ? 'Aligned with ANSSI guidelines (6-month forensic archiving for blocked attacks), CrowdSec (30-day active window), and GDPR (fast IP purge on legitimate traffic).'
            : "Conforme aux référentiels de l'ANSSI (6 mois d'archivage forensique des attaques), de CrowdSec (30 jours opérationnels) et de la CNIL (purge rapide des IP sur trafic légitime)." }}
        </p>

        <div class="space-y-2.5 mb-4">
          <div class="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800">
            <span class="text-slate-300">{{ isEn ? 'SOC Hot Window (Days)' : 'Fenêtre Chaude SOC (Jours)' }}</span>
            <input
              v-model.number="retention.hot_window_days"
              type="number"
              class="w-20 text-right bg-slate-900 border border-slate-700 rounded-md px-2 py-1 text-white font-mono tabular-nums font-semibold"
            />
          </div>
          <div class="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800">
            <span class="text-slate-300">{{ isEn ? 'ANSSI Forensic Archive (Days)' : 'Conservation Forensique ANSSI (Jours)' }}</span>
            <input
              v-model.number="retention.anssi_forensic_days"
              type="number"
              class="w-20 text-right bg-slate-900 border border-slate-700 rounded-md px-2 py-1 text-white font-mono tabular-nums font-semibold"
            />
          </div>
          <div class="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800">
            <span class="text-slate-300">{{ isEn ? 'GDPR Clean IP Purge (Days)' : 'Purge IP Trafic Sain RGPD (Jours)' }}</span>
            <input
              v-model.number="retention.rgpd_clean_ip_days"
              type="number"
              class="w-20 text-right bg-slate-900 border border-slate-700 rounded-md px-2 py-1 text-emerald-400 font-mono tabular-nums font-semibold"
            />
          </div>
        </div>

        <button
          type="button"
          @click="$emit('save-retention')"
          class="w-full py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold cursor-pointer transition-colors mb-2"
        >
          {{ isEn ? 'Save & Apply Retention Policy' : 'Enregistrer & Appliquer la Rétention' }}
        </button>
      </div>

      <button
        type="button"
        @click="$emit('purge-clean')"
        class="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold cursor-pointer transition-colors"
      >
        {{ isEn ? 'Purge Legitimate Traffic Logs Immediately (ALLOW)' : 'Purger Immédiatement les Journaux Légitimes (ALLOW)' }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import AegisIcon from '../AegisIcon.vue';
import { type BannedIp, type RetentionPolicy } from '../../../services/api/controlsApi';
import { useI18n } from '../../../composables/useI18n';

const { locale } = useI18n();
const isEn = computed(() => locale.value === 'en');

defineProps<{
  bannedIps: BannedIp[];
  maxPayloadBytes: number;
  retention: RetentionPolicy;
}>();

const emit = defineEmits<{
  (e: 'add-ban', ip: string, reason: string): void;
  (e: 'remove-ban', ip: string): void;
  (e: 'update-payload-limit', limit: number): void;
  (e: 'save-retention'): void;
  (e: 'purge-clean'): void;
}>();

const newBanIp = ref('');
const newBanReason = ref('');

function isAutoJailReason(reason?: string): boolean {
  if (!reason) return false;
  return /auto-jail|rate-limit|429|offenses/i.test(reason);
}

function handleAddBan() {
  if (!newBanIp.value) return;
  emit('add-ban', newBanIp.value, newBanReason.value);
  newBanIp.value = '';
  newBanReason.value = '';
}
</script>
