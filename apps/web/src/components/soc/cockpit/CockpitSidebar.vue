<template>
  <aside
    :class="[
      'bg-slate-950 border-r border-slate-800/80 flex flex-col justify-between shrink-0 z-30 transition-all duration-200 py-3.5 h-full max-h-screen overflow-hidden select-none',
      isSidebarExpanded ? 'w-60 px-3' : 'w-16 px-2 items-center'
    ]"
  >
    <!-- 1. En-tête Sidebar : Logo + Rétraction -->
    <div class="shrink-0 w-full">
      <div class="flex items-center justify-between pb-3.5 mb-2.5 border-b border-slate-800/80">
        <a
          href="/"
          class="flex items-center gap-2.5 group overflow-hidden"
          :title="t.cockpit.sidebar.backToSite"
        >
          <AegisLogo size="sm" class="shrink-0" />
          <div v-if="isSidebarExpanded" class="flex flex-col min-w-0">
            <div class="flex items-center gap-1.5">
              <span class="text-sm font-bold text-white tracking-tight leading-none truncate">Aegis</span>
              <span class="text-[9px] font-mono text-slate-400 px-1 py-0.2 rounded bg-slate-900 border border-slate-800">v1.2</span>
            </div>
            <span class="text-[10px] text-slate-400 font-mono tracking-wider uppercase mt-1 truncate">
              {{ t.cockpit.sidebar.title }}
            </span>
          </div>
        </a>

        <button
          type="button"
          @click="$emit('toggle-expand')"
          class="w-7 h-7 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 flex items-center justify-center cursor-pointer transition-colors shrink-0"
          :title="isSidebarExpanded ? t.cockpit.sidebar.collapse : t.cockpit.sidebar.expand"
          :aria-label="isSidebarExpanded ? t.cockpit.sidebar.collapse : t.cockpit.sidebar.expand"
        >
          <AegisIcon :name="isSidebarExpanded ? 'chevron-left' : 'chevron-right'" size="xs" />
        </button>
      </div>
    </div>

    <!-- 2. Navigation Principale (Monochrome + Accent Émeraude Unique) -->
    <nav class="flex-1 min-h-0 w-full overflow-y-auto space-y-1 py-1 font-sans text-xs">
      <button
        v-for="item in navItems"
        :key="item.id"
        type="button"
        @click="$emit('switch-nav', item.id)"
        :class="[
          'w-full flex items-center rounded-lg transition-colors cursor-pointer relative group',
          isSidebarExpanded ? 'px-2.5 py-2 gap-2.5' : 'w-10 h-10 justify-center mx-auto',
          isItemActive(item.id)
            ? 'bg-slate-900 text-white font-semibold border border-slate-700/80'
            : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent font-medium'
        ]"
        :title="item.desc"
      >
        <span
          v-if="isItemActive(item.id)"
          class="absolute left-0 top-2 bottom-2 w-0.5 bg-emerald-400 rounded-r"
        ></span>
        <AegisIcon
          :name="item.icon"
          size="sm"
          :class="isItemActive(item.id) ? 'text-emerald-400' : 'text-slate-400 group-hover:text-slate-300'"
        />
        <span v-if="isSidebarExpanded" class="truncate">{{ item.label }}</span>
      </button>
    </nav>

    <!-- 3. Pied de Sidebar : Compte & Déconnexion -->
    <div class="shrink-0 w-full pt-3 border-t border-slate-800/80 space-y-1 font-sans text-xs">
      <button
        type="button"
        @click="$emit('open-account')"
        :class="[
          'w-full flex items-center rounded-lg transition-colors cursor-pointer text-slate-300 hover:text-white hover:bg-slate-900/80',
          isSidebarExpanded ? 'px-2.5 py-2 gap-2.5' : 'w-10 h-10 justify-center mx-auto'
        ]"
        :title="t.cockpit.sidebar.myAccount"
      >
        <AegisIcon name="user" size="sm" class="text-slate-400" />
        <div v-if="isSidebarExpanded" class="flex flex-col text-left min-w-0">
          <span class="font-medium text-xs truncate">{{ t.cockpit.sidebar.myAccount }}</span>
          <span class="text-[10px] font-mono text-slate-500 truncate">{{ t.cockpit.sidebar.accountRole }}</span>
        </div>
      </button>

      <button
        type="button"
        @click="$emit('logout')"
        :class="[
          'w-full flex items-center rounded-lg transition-colors cursor-pointer text-slate-400 hover:text-rose-300 hover:bg-rose-500/10',
          isSidebarExpanded ? 'px-2.5 py-2 gap-2.5' : 'w-10 h-10 justify-center mx-auto'
        ]"
        :title="t.cockpit.sidebar.logout"
      >
        <AegisIcon name="log-out" size="sm" />
        <span v-if="isSidebarExpanded" class="font-medium truncate">{{ t.cockpit.sidebar.logout }}</span>
      </button>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import AegisLogo from '../AegisLogo.vue';
import AegisIcon from '../AegisIcon.vue';
import { useI18n } from '../../../composables/useI18n';

const { t } = useI18n();

const props = defineProps<{
  isSidebarExpanded: boolean;
  activeNav: string;
}>();

defineEmits<{
  (e: 'toggle-expand'): void;
  (e: 'switch-nav', nav: string): void;
  (e: 'open-account'): void;
  (e: 'logout'): void;
}>();

const navItems = computed(() => [
  {
    id: 'dashboard',
    icon: 'overview',
    label: t.value.cockpit.sidebar.overview,
    desc: t.value.cockpit.sidebar.overviewDesc
  },
  {
    id: 'audit',
    icon: 'search',
    label: t.value.cockpit.sidebar.diagnostics,
    desc: t.value.cockpit.sidebar.diagnosticsDesc
  },
  {
    id: 'streams',
    icon: 'activity',
    label: t.value.cockpit.sidebar.streams,
    desc: t.value.cockpit.sidebar.streamsDesc
  },
  {
    id: 'telemetry',
    icon: 'cpu',
    label: t.value.cockpit.sidebar.telemetry,
    desc: t.value.cockpit.sidebar.telemetryDesc
  },
  {
    id: 'cve',
    icon: 'shield',
    label: t.value.cockpit.sidebar.cve,
    desc: t.value.cockpit.sidebar.cveDesc
  },
  {
    id: 'controls',
    icon: 'sliders',
    label: t.value.cockpit.sidebar.controls,
    desc: t.value.cockpit.sidebar.controlsDesc
  }
]);

function isItemActive(id: string): boolean {
  if (id === 'streams' && (props.activeNav === 'streams' || props.activeNav === 'security')) return true;
  if (id === 'telemetry' && (props.activeNav === 'telemetry' || props.activeNav === 'green')) return true;
  if (id === 'controls' && (props.activeNav === 'controls' || props.activeNav === 'compliance')) return true;
  return props.activeNav === id;
}
</script>
