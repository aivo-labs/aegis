import { ref, computed } from 'vue';
import { cveApi, type CveItem } from '../services/api/cveApi';

export function useCveFeed() {
  const cves = ref<CveItem[]>([]);
  const activeRulesCount = ref(6);
  const blockedByPatchCount = ref(0);
  const catalogCves = ref<CveItem[]>([]);
  const exposedCves = ref<CveItem[]>([]);
  const updatedAt = ref('');

  const activeDefenses = computed(() => cves.value.filter(c => c.is_active_defense || (c as any).blocked_by_aegis));

  async function fetchCveFeed() {
    const res = await cveApi.getFeed();
    if (res.ok && res.data) {
      cves.value = res.data.cves || [];
      catalogCves.value = res.data.catalog_cves || res.data.cves || [];
      activeRulesCount.value = res.data.active_rules_count ?? (res.data.cves ? res.data.cves.length : 6);
      if (res.data.blocked_by_virtual_patch_count !== undefined) blockedByPatchCount.value = res.data.blocked_by_virtual_patch_count;
      if (res.data.exposed_cves) exposedCves.value = res.data.exposed_cves;
      updatedAt.value = res.data.updated_at || '';
    }
  }

  return {
    cves,
    activeRulesCount,
    blockedByPatchCount,
    catalogCves,
    exposedCves,
    updatedAt,
    activeDefenses,
    fetchCveFeed,
  };
}
