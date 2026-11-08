import { ref, computed } from 'vue';
import { streamsApi, type IngressEvent, type EgressEvent } from '../services/api/streamsApi';
import { REPLAY_ATTACK_SEEDS } from '../data/sandboxFixtures';

export function useLiveStreams(options?: { isDemo?: boolean }) {
  const ingressStream = ref<IngressEvent[]>([]);
  const egressStream = ref<EgressEvent[]>([]);
  const streamFilter = ref<'all' | 'probes' | 'exploits' | 'clean'>('all');
  const selectedHost = ref<string>('all');
  const selectedDate = ref<string>('');
  const searchQuery = ref<string>('');
  const isSimulatingProbes = ref(false);
  const isLoading = ref(true);

  // 24h Totals from Backend / Database
  const totalIngress24h = ref<number>(0);
  const blockedIngress24h = ref<number>(0);
  const totalEgress24h = ref<number>(0);
  const blockedEgress24h = ref<number>(0);

  // Classification helpers
  function isClean(item: IngressEvent): boolean {
    return item.decision === 'ALLOW' || item.decision === 'OK' || ((item as any).http_status ?? item.status_code) < 400;
  }

  function isProbe(item: IngressEvent): boolean {
    if (isClean(item)) return false;
    const cat = (item.category || (item as any).threat_category || '').toUpperCase();
    const uri = (item.target || (item as any).request_uri || '').toLowerCase();
    const threat = (item.threat_type || (item as any).threat_detected || '').toUpperCase();
    return (
      cat.includes('SONDE') ||
      cat.includes('SCAN') ||
      threat.includes('SCAN') ||
      threat.includes('PROBE') ||
      uri.includes('wp-') ||
      uri.includes('.env') ||
      uri.includes('.git') ||
      uri.includes('xmlrpc') ||
      uri.includes('phpmyadmin') ||
      uri.includes('phpinfo') ||
      uri.includes('cgi-bin') ||
      uri.includes('setup.cgi')
    );
  }

  function isExploit(item: IngressEvent): boolean {
    if (isClean(item)) return false;
    return !isProbe(item);
  }

  // Base list filtered by host and search
  const baseIngressList = computed(() => {
    let list = ingressStream.value;
    if (selectedHost.value && selectedHost.value !== 'all') {
      const h = selectedHost.value.toLowerCase();
      list = list.filter(i => (i.host || i.domain || '').toLowerCase() === h);
    }
    if (searchQuery.value.trim()) {
      const q = searchQuery.value.trim().toLowerCase();
      list = list.filter(i => 
        (i.client_ip || '').toLowerCase().includes(q) ||
        (i.target || '').toLowerCase().includes(q) ||
        (i.host || '').toLowerCase().includes(q) ||
        (i.category || '').toLowerCase().includes(q)
      );
    }
    return list;
  });

  const probeEventsCount = computed(() => baseIngressList.value.filter(isProbe).length);
  const exploitEventsCount = computed(() => baseIngressList.value.filter(isExploit).length);
  const cleanEventsCount = computed(() => baseIngressList.value.filter(isClean).length);

  const filteredIngressStream = computed(() => {
    const list = baseIngressList.value;
    if (streamFilter.value === 'probes') {
      return list.filter(isProbe);
    }
    if (streamFilter.value === 'exploits') {
      return list.filter(isExploit);
    }
    if (streamFilter.value === 'clean') {
      return list.filter(isClean);
    }
    return list;
  });

  const filteredEgressStream = computed(() => {
    let list = egressStream.value;
    if (selectedHost.value && selectedHost.value !== 'all') {
      const h = selectedHost.value.toLowerCase();
      list = list.filter(e => 
        (e.host || '').toLowerCase() === h ||
        (e.domain || '').toLowerCase().includes(h)
      );
    }
    if (searchQuery.value.trim()) {
      const q = searchQuery.value.trim().toLowerCase();
      list = list.filter(e => 
        (e.domain || '').toLowerCase().includes(q) ||
        (e.client_ip || '').toLowerCase().includes(q) ||
        (e.target_ip || '').toLowerCase().includes(q)
      );
    }
    return list;
  });

  const availableHosts = computed(() => {
    const set = new Set<string>();
    ingressStream.value.forEach(i => {
      const h = i.host || i.domain;
      if (h) set.add(h);
    });
    egressStream.value.forEach(e => {
      const h = e.host || e.domain;
      if (h && !h.includes(':')) set.add(h);
    });
    return Array.from(set).sort();
  });

  const mapEvents = computed(() => {
    return filteredIngressStream.value
      .filter(i => i.decision !== 'ALLOW')
      .map(i => ({
        id: i.id,
        client_ip: i.client_ip,
        fqdn: `${i.method || (i as any).http_method || 'GET'} ${i.target || (i as any).request_uri || '/'}`,
        threat_type: i.threat_type || 'THREAT',
        lat: i.lat || 48.8566,
        lon: i.lon || 2.3522,
      }));
  });

  function loadSandboxStreams() {
    ingressStream.value = REPLAY_ATTACK_SEEDS.map((s, idx) => ({
      id: `seed-ingress-${idx}`,
      client_ip: s.client_ip,
      method: s.method,
      target: s.target,
      host: s.host,
      domain: s.host,
      user_agent: s.user_agent,
      threat_type: s.threat_type,
      category: s.category,
      decision: s.decision === 'SINKHOLE' ? 'BLOCK' : s.decision,
      status_code: s.status_code,
      timestamp: new Date(Date.now() - idx * 360000).toISOString(),
      lat: s.lat,
      lon: s.lon,
      country: s.country,
      entropy: s.entropy,
      latency_ms: s.latency_ms,
    }));

    egressStream.value = REPLAY_ATTACK_SEEDS
      .filter(s => s.decision === 'SINKHOLE' || s.category.includes('Egress'))
      .map((s, idx) => ({
        id: `seed-egress-${idx}`,
        protocol: 'DNS',
        domain: s.target.replace('/dns-query?name=', '').replace('&type=A', ''),
        target: s.target,
        target_ip: '0.0.0.0',
        client_ip: s.client_ip,
        port: 53,
        decision: 'BLOCK',
        threat_type: s.threat_type,
        entropy: s.entropy,
        timestamp: new Date(Date.now() - idx * 120000).toISOString(),
        latency_ms: s.latency_ms,
        exfil_probability: 0.98,
      }));

    totalIngress24h.value = 13950;
    blockedIngress24h.value = 13845;
    totalEgress24h.value = 870;
    blockedEgress24h.value = 867;
  }

  async function fetchLiveStreams(params?: { date?: string; host?: string; limit?: number }) {
    if (options?.isDemo) {
      loadSandboxStreams();
      isLoading.value = false;
      return;
    }

    try {
      const reqDate = params?.date !== undefined ? params.date : selectedDate.value;
      const reqHost = params?.host !== undefined ? params.host : (selectedHost.value === 'all' ? '' : selectedHost.value);
      const limit = params?.limit ?? 50;

      const res = await streamsApi.getLiveStreams({
        date: reqDate || undefined,
        host: reqHost || undefined,
        limit,
      });

      if (res.ok && res.data) {
        ingressStream.value = res.data.ingress_stream || [];
        egressStream.value = res.data.egress_stream || [];
        totalIngress24h.value = res.data.total_ingress_24h ?? ingressStream.value.length;
        blockedIngress24h.value = res.data.blocked_ingress_24h ?? ingressStream.value.filter(i => i.decision === 'BLOCK').length;
        totalEgress24h.value = res.data.total_egress_24h ?? egressStream.value.length;
        blockedEgress24h.value = res.data.blocked_egress_24h ?? egressStream.value.filter(e => e.decision === 'BLOCK').length;
      } else if (ingressStream.value.length === 0) {
        loadSandboxStreams();
      }
    } catch (e) {
      if (ingressStream.value.length === 0) {
        loadSandboxStreams();
      }
    } finally {
      isLoading.value = false;
    }
  }

  async function simulateBotProbes() {
    if (isSimulatingProbes.value) return;
    isSimulatingProbes.value = true;
    try {
      await streamsApi.simulateBotProbes();
      await fetchLiveStreams();
    } finally {
      isSimulatingProbes.value = false;
    }
  }

  return {
    ingressStream,
    egressStream,
    streamFilter,
    selectedHost,
    selectedDate,
    searchQuery,
    isLoading,
    isSimulatingProbes,
    totalIngress24h,
    blockedIngress24h,
    totalEgress24h,
    blockedEgress24h,
    availableHosts,
    probeEventsCount,
    exploitEventsCount,
    cleanEventsCount,
    filteredIngressStream,
    filteredEgressStream,
    mapEvents,
    fetchLiveStreams,
    simulateBotProbes,
  };
}
