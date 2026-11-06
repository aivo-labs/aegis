import { ref, computed } from 'vue';
import {
  telemetryApi,
  type PowerPoint,
  type EnergySummary,
  type EnergyTimePoint,
  type WorkloadEnergy,
  type NodeEnergy,
  type EnergyQueryParams,
} from '../services/api/telemetryApi';

export function useTelemetry() {
  // Navigation & Scope
  const selectedRange = ref<string>('24h');
  const selectedMonth = ref<string>('2026-11');
  const selectedYear = ref<string>('2026');
  const customFrom = ref<string>('');
  const customTo = ref<string>('');
  const selectedNode = ref<string>('all');
  const selectedNamespace = ref<string>('all');
  const activeMetric = ref<'watts' | 'cpu' | 'water_carbon'>('watts');

  // Loading & Simulation state
  const isLoading = ref(false);
  const isSimulatedHistory = ref(false);

  // Summary Metrics (starts clean, populated on fetch)
  const summary = ref<EnergySummary>({
    instant_watts: 0,
    cpu_watts: 0,
    ram_watts: 0,
    avg_watts: 0,
    max_watts: 0,
    min_watts: 0,
    total_joules: 0,
    total_kwh: 0,
    avg_cpu_load_pct: 0,
    max_cpu_load_pct: 0,
    carbon_intensity_gco2_kwh: 52.0,
    total_carbon_gco2: 0,
    total_carbon_kg: 0,
    water_usage_liters: 0,
    estimated_cost_eur: 0,
    pue: 1.15,
    equivalencies: {
      car_km: 0,
      smartphones_charged: 0,
      water_bottles: 0,
      showers_pct: 0,
    },
  });

  const timeseries = ref<EnergyTimePoint[]>([]);
  const workloads = ref<WorkloadEnergy[]>([]);
  const nodes = ref<NodeEnergy[]>([]);
  const availableMonths = ref<string[]>(['2026-11', '2026-10', '2026-09', '2026-08', '2026-07']);
  const availableNamespaces = ref<string[]>(['all', 'dokploy', 'aegis-system', 'kube-system']);

  // Reactive two-way bindings for backward compatibility and tests
  const instantWatts = computed({
    get: () => summary.value.instant_watts || 0,
    set: (w: number) => {
      summary.value.instant_watts = w;
    },
  });

  const cpuWatts = computed({
    get: () => summary.value.cpu_watts || 0,
    set: (w: number) => {
      summary.value.cpu_watts = w;
    },
  });

  const ramWatts = computed({
    get: () => summary.value.ram_watts || 0,
    set: (w: number) => {
      summary.value.ram_watts = w;
    },
  });

  const cpuLoadPct = computed({
    get: () => summary.value.avg_cpu_load_pct || 0,
    set: (p: number) => {
      summary.value.avg_cpu_load_pct = p;
    },
  });

  const carbonIntensity = computed({
    get: () => summary.value.total_carbon_gco2 || 0,
    set: (c: number) => {
      summary.value.total_carbon_gco2 = c;
    },
  });

  const totalJoules = computed({
    get: () => summary.value.total_joules || 0,
    set: (j: number) => {
      summary.value.total_joules = j;
    },
  });

  const pue = computed({
    get: () => summary.value.pue || 1.15,
    set: (p: number) => {
      summary.value.pue = p;
    },
  });

  const powerHistory = computed({
    get: () => timeseries.value.map(t => ({ time: t.time, watts: t.watts })),
    set: (val: PowerPoint[]) => {
      timeseries.value = val.map(p => ({
        time: p.time,
        timestamp: new Date().toISOString(),
        watts: p.watts,
        cpu_watts: roundFloat(p.watts * 0.7, 2),
        ram_watts: roundFloat(p.watts * 0.3, 2),
        cpu_load_pct: 4.2,
        carbon_gco2: roundFloat((p.watts / 1000) * 52, 3),
        water_cl: roundFloat((p.watts / 1000) * 150, 2),
      }));
    },
  });

  // Dynamic Y-axis scale calculation
  const maxYWatts = computed(() => {
    const maxVal = Math.max(
      summary.value.max_watts,
      summary.value.instant_watts,
      ...timeseries.value.map(t => t.watts),
      15
    );
    return Math.ceil(maxVal / 5) * 5;
  });

  const maxYCpu = computed(() => {
    const maxVal = Math.max(
      summary.value.max_cpu_load_pct,
      ...timeseries.value.map(t => t.cpu_load_pct),
      10
    );
    return Math.min(100, Math.ceil(maxVal / 10) * 10);
  });

  // SVG Paths with 40 -> 480 scale (baseline y=140 / 150)
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

  const dynamicAreaSvgPath = computed(() => {
    const pts = timeseries.value;
    if (pts.length < 2) return '';
    const stepX = 440 / (pts.length - 1);
    const points = pts.map((pt, idx) => {
      const x = Math.round(40 + idx * stepX);
      const w = Number(pt.watts) || 0;
      const y = Math.max(20, Math.min(145, Math.round(150 - (w * 6))));
      return `${x},${y}`;
    });
    return `M ${points.join(' L ')} L 480,150 L 40,150 Z`;
  });

  const dynamicCpuLoadSvgPath = computed(() => {
    const pts = timeseries.value;
    if (pts.length < 2) {
      const cpu = summary.value.avg_cpu_load_pct || 0;
      const y = Math.max(20, Math.min(145, Math.round(150 - (cpu * 1.2))));
      return `M 40,${y} L 480,${y}`;
    }
    const stepX = 440 / (pts.length - 1);
    const points = pts.map((pt, idx) => {
      const x = Math.round(40 + idx * stepX);
      const cpu = Number(pt.cpu_load_pct) || 0;
      const y = Math.max(20, Math.min(145, Math.round(150 - (cpu * 1.2))));
      return `${x},${y}`;
    });
    return `M ${points.join(' L ')}`;
  });

  const dynamicCpuAreaSvgPath = computed(() => {
    const pts = timeseries.value;
    if (pts.length < 2) return '';
    const stepX = 440 / (pts.length - 1);
    const points = pts.map((pt, idx) => {
      const x = Math.round(40 + idx * stepX);
      const cpu = Number(pt.cpu_load_pct) || 0;
      const y = Math.max(20, Math.min(145, Math.round(150 - (cpu * 1.2))));
      return `${x},${y}`;
    });
    return `M ${points.join(' L ')} L 480,150 L 40,150 Z`;
  });

  const dynamicWaterSvgPath = computed(() => {
    const pts = timeseries.value;
    if (pts.length < 2) return 'M 40,140 L 480,140';
    const stepX = 440 / (pts.length - 1);
    const maxVal = Math.max(...pts.map(p => p.water_cl), 1);
    const points = pts.map((pt, idx) => {
      const x = Math.round(40 + idx * stepX);
      const val = Number(pt.water_cl) || 0;
      const y = Math.max(20, Math.min(145, Math.round(150 - ((val / maxVal) * 110))));
      return `${x},${y}`;
    });
    return `M ${points.join(' L ')}`;
  });

  async function fetchEnergyTelemetry(customParams?: EnergyQueryParams) {
    isLoading.value = true;
    try {
      const params: EnergyQueryParams = {
        range: selectedRange.value,
        node: selectedNode.value,
        namespace: selectedNamespace.value,
        ...customParams,
      };

      if (selectedRange.value === 'month') {
        params.month = selectedMonth.value;
      } else if (selectedRange.value === 'year') {
        params.year = selectedYear.value;
      } else if (selectedRange.value === 'custom' && customFrom.value && customTo.value) {
        params.from = customFrom.value;
        params.to = customTo.value;
      }

      const res = await telemetryApi.getEnergyTelemetry(params);
      if (res.ok && res.data) {
        if (res.data.summary) summary.value = res.data.summary;
        timeseries.value = res.data.timeseries || [];
        workloads.value = res.data.workloads || [];
        nodes.value = res.data.nodes || [];
        isSimulatedHistory.value = !!res.data.is_simulated_history;
        if (res.data.available_months?.length) {
          availableMonths.value = res.data.available_months;
        }
        if (res.data.available_namespaces?.length) {
          availableNamespaces.value = res.data.available_namespaces;
        }
      }
    } finally {
      isLoading.value = false;
    }
  }

  // Backward compatibility alias
  async function fetchTelemetry() {
    return fetchEnergyTelemetry();
  }

  function roundFloat(val: number, precision: number): number {
    const p = Math.pow(10, precision);
    return Math.round(val * p) / p;
  }

  return {
    selectedRange,
    selectedMonth,
    selectedYear,
    customFrom,
    customTo,
    selectedNode,
    selectedNamespace,
    activeMetric,
    isLoading,
    isSimulatedHistory,
    summary,
    timeseries,
    workloads,
    nodes,
    availableMonths,
    availableNamespaces,
    instantWatts,
    cpuWatts,
    ramWatts,
    cpuLoadPct,
    carbonIntensity,
    totalJoules,
    pue,
    powerHistory,
    maxYWatts,
    maxYCpu,
    dynamicSvgPath,
    dynamicAreaSvgPath,
    dynamicCpuLoadSvgPath,
    dynamicCpuAreaSvgPath,
    dynamicWaterSvgPath,
    fetchEnergyTelemetry,
    fetchTelemetry,
  };
}
