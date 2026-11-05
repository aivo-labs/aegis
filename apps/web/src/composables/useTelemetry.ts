import { ref, computed } from 'vue';
import { telemetryApi, type PowerPoint } from '../services/api/telemetryApi';

export function useTelemetry() {
  const instantWatts = ref(0);
  const cpuWatts = ref(0);
  const ramWatts = ref(0);
  const cpuLoadPct = ref(3.2);
  const carbonIntensity = ref(0.12);
  const totalJoules = ref(0);
  const pue = ref(1.12);
  const powerHistory = ref<PowerPoint[]>([]);

  const dynamicSvgPath = computed(() => {
    const history = powerHistory.value;
    if (history.length >= 2) {
      const stepX = 440 / (history.length - 1);
      const points = history.map((pt, idx) => {
        const x = Math.round(40 + idx * stepX);
        const w = Number(pt.watts) || 0;
        const y = Math.max(20, Math.min(145, Math.round(150 - (w * 6))));
        return `${x},${y}`;
      });
      return `M ${points.join(' L ')}`;
    }
    const w = instantWatts.value || 0;
    const y = w > 0 ? Math.max(20, Math.min(145, Math.round(150 - (w * 6)))) : 140;
    return `M 40,${y} L 480,${y}`;
  });

  async function fetchTelemetry() {
    const res = await telemetryApi.getSummary();
    if (res.ok && res.data?.green) {
      const g = res.data.green;
      instantWatts.value = Number(g.instant_power_watts) || 0;
      cpuWatts.value = Number(g.cpu_watts) || 0;
      ramWatts.value = Number(g.ram_watts) || 0;
      if (g.cpu_load_pct !== undefined) cpuLoadPct.value = Number(g.cpu_load_pct);
      else if ((g as any).cpu_utilization_pct !== undefined) cpuLoadPct.value = Number((g as any).cpu_utilization_pct);
      carbonIntensity.value = Number(g.carbon_intensity_gco2_h) || 0;
      powerHistory.value = g.power_history || [];
      if (g.total_joules) totalJoules.value = g.total_joules;
      if (g.pue) pue.value = g.pue;
    }
  }

  return {
    instantWatts,
    cpuWatts,
    ramWatts,
    cpuLoadPct,
    carbonIntensity,
    totalJoules,
    pue,
    powerHistory,
    dynamicSvgPath,
    fetchTelemetry,
  };
}
