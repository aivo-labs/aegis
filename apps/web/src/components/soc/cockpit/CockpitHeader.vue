<template>
  <div>
    <!-- BARRE D'EN-TÊTE COCKPIT SOC -->
    <header class="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
      <!-- Titre & Statut Opérationnel -->
      <div class="flex items-center flex-wrap gap-3">
        <h1 class="text-xl sm:text-2xl font-bold tracking-tight text-white">
          {{ t.cockpit.header.title }}
        </h1>

        <div
          :class="[
            'inline-flex items-center gap-2 px-2.5 py-1 rounded-md font-mono text-[11px] font-semibold border transition-colors',
            protectionEnabled
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-rose-500/15 border-rose-500/40 text-rose-300'
          ]"
        >
          <span :class="['w-1.5 h-1.5 rounded-full', protectionEnabled ? 'bg-emerald-400' : 'bg-rose-400']"></span>
          <span>{{ protectionEnabled ? t.cockpit.header.shieldActive : t.cockpit.header.shieldDisabled }}</span>
        </div>

        <div class="hidden sm:flex items-center gap-1.5 text-xs text-slate-400 font-mono pl-2.5 border-l border-slate-800">
          <span>{{ t.cockpit.header.activeEngines }}</span>
          <span class="text-slate-200 font-medium">{{ t.cockpit.header.enginesList }}</span>
        </div>
      </div>

      <!-- Contrôles d'Action -->
      <div class="flex items-center flex-wrap gap-2">
        <!-- 1. Toggle Protection Shield ON / OFF -->
        <button
          type="button"
          @click="$emit('toggle-protection')"
          :disabled="isTogglingProtection"
          :class="[
            'px-3 py-1.5 rounded-lg font-sans text-xs font-semibold transition-colors border flex items-center gap-2 cursor-pointer',
            protectionEnabled
              ? 'bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border-emerald-500/40'
              : 'bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 border-rose-500/50'
          ]"
          :title="t.cockpit.header.shieldTooltip"
        >
          <AegisIcon :name="protectionEnabled ? 'shield' : 'shield-alert'" size="xs" />
          <span>{{ protectionEnabled ? t.cockpit.header.shieldBtnActive : t.cockpit.header.shieldBtnDisabled }}</span>
        </button>

        <!-- 2. Enrôlement Nœud VPS -->
        <button
          type="button"
          @click="$emit('enroll-vps')"
          class="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-200 font-sans text-xs font-medium transition-colors flex items-center gap-2 cursor-pointer"
          :title="t.cockpit.header.connectVpsTooltip"
        >
          <AegisIcon name="server" size="xs" class="text-slate-400" />
          <span>{{ t.cockpit.header.connectVps }}</span>
        </button>

        <!-- 3. Dépôt GitHub -->
        <a
          href="https://github.com/aivo-labs/aegis"
          target="_blank"
          rel="noopener noreferrer"
          class="w-8 h-8 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 flex items-center justify-center text-slate-400 hover:text-white transition-colors"
          :title="t.cockpit.header.githubTooltip"
        >
          <svg class="w-4 h-4 fill-current" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
          </svg>
        </a>

        <!-- 4. Sélecteur de Langue (FR / EN) -->
        <CockpitLanguageSelector />

        <!-- 5. Thème Sombre / Clair + Info Sobriété RGESN -->
        <div class="relative flex items-center bg-slate-900 border border-slate-800 rounded-lg p-0.5">
          <button
            type="button"
            @click="$emit('toggle-theme')"
            class="w-7 h-7 rounded-md text-slate-400 hover:text-white flex items-center justify-center transition-colors cursor-pointer"
            :title="isLightMode ? t.cockpit.header.themeDarkTooltip : t.cockpit.header.themeLightTooltip"
            aria-label="Toggle theme"
          >
            <AegisIcon :name="isLightMode ? 'sun' : 'moon'" size="xs" />
          </button>

          <div class="relative group/tooltip">
            <button
              type="button"
              class="w-5 h-5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-200 font-mono text-[10px] font-semibold flex items-center justify-center transition-colors cursor-help mr-0.5"
              aria-label="RGESN info"
            >
              ?
            </button>

            <div class="absolute right-0 top-full mt-2 w-72 p-3 rounded-lg bg-slate-900 border border-slate-700 shadow-xl text-left opacity-0 invisible group-hover/tooltip:opacity-100 group-hover/tooltip:visible transition-all duration-150 z-50 pointer-events-none font-sans">
              <div class="flex items-center gap-1.5 text-xs font-semibold text-emerald-400 mb-1">
                <AegisIcon name="cpu" size="xs" />
                <span>{{ t.cockpit.header.rgesnTooltipTitle }}</span>
              </div>
              <p class="text-[11px] text-slate-300 leading-relaxed">
                {{ t.cockpit.header.rgesnTooltipDesc }}
              </p>
            </div>
          </div>
        </div>

        <!-- 6. Déconnexion -->
        <button
          type="button"
          @click="$emit('logout')"
          class="w-8 h-8 rounded-lg bg-slate-900 hover:bg-rose-500/15 border border-slate-800 hover:border-rose-500/40 text-slate-400 hover:text-rose-300 transition-colors cursor-pointer flex items-center justify-center"
          :title="t.cockpit.header.logoutTooltip"
          aria-label="Déconnexion"
        >
          <AegisIcon name="log-out" size="xs" />
        </button>
      </div>
    </header>

    <!-- BANNIÈRE D'ALERTE LORSQUE LE BOUCLIER EST DÉSACTIVÉ -->
    <div
      v-if="!protectionEnabled"
      class="mt-4 p-3.5 rounded-lg bg-rose-950/70 border border-rose-500/60 text-rose-200 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3"
    >
      <div class="flex items-center gap-3">
        <AegisIcon name="shield-alert" size="md" class="text-rose-400 shrink-0" />
        <div>
          <div class="font-semibold text-white">{{ t.cockpit.header.warningBannerTitle }}</div>
          <div class="text-[11px] text-rose-300 mt-0.5">
            {{ t.cockpit.header.warningBannerDesc }}
          </div>
        </div>
      </div>
      <button
        type="button"
        @click="$emit('toggle-protection')"
        class="px-3.5 py-1.5 rounded-lg bg-rose-500 hover:bg-rose-400 text-slate-950 font-semibold text-xs shrink-0 cursor-pointer transition-colors"
      >
        {{ t.cockpit.header.reactivateShield }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import CockpitLanguageSelector from './CockpitLanguageSelector.vue';
import AegisIcon from '../AegisIcon.vue';
import { useI18n } from '../../../composables/useI18n';

const { t } = useI18n();

defineProps<{
  protectionEnabled: boolean;
  isTogglingProtection: boolean;
  isLightMode: boolean;
}>();

defineEmits<{
  (e: 'toggle-protection'): void;
  (e: 'enroll-vps'): void;
  (e: 'toggle-theme'): void;
  (e: 'logout'): void;
}>();
</script>
