import { ref, computed } from 'vue';
import { streamsApi, type IngressEvent, type EgressEvent } from '../services/api/streamsApi';

export function useLiveStreams() {
  const ingressStream = ref<IngressEvent[]>([]);
  const egressStream = ref<EgressEvent[]>([]);
  const streamFilter = ref<'all' | 'probes' | 'exploits' | 'clean'>('all');
  const isSimulatingProbes = ref(false);

  const probeEventsCount = computed(() =>
    ingressStream.value.filter(i => {
      const cat = i.category || (i as any).threat_category || '';
      return cat.includes('SONDE') || cat.includes('SCANNER');
    }).length
  );

  const exploitEventsCount = computed(() =>
    ingressStream.value.filter(i => {
      const cat = i.category || (i as any).threat_category || '';
      return i.decision !== 'ALLOW' && !cat.includes('SONDE') && !cat.includes('SCANNER');
    }).length
  );

  const cleanEventsCount = computed(() =>
    ingressStream.value.filter(i => i.decision === 'ALLOW').length
  );

  const filteredIngressStream = computed(() => {
    if (streamFilter.value === 'probes') {
      return ingressStream.value.filter(i => {
        const cat = i.category || (i as any).threat_category || '';
        return cat.includes('SONDE') || cat.includes('SCANNER');
      });
    }
    if (streamFilter.value === 'exploits') {
      return ingressStream.value.filter(i => {
        const cat = i.category || (i as any).threat_category || '';
        return i.decision !== 'ALLOW' && !cat.includes('SONDE') && !cat.includes('SCANNER');
      });
    }
    if (streamFilter.value === 'clean') {
      return ingressStream.value.filter(i => i.decision === 'ALLOW');
    }
    return ingressStream.value;
  });

  const mapEvents = computed(() => {
    return ingressStream.value
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

  async function fetchLiveStreams() {
    const res = await streamsApi.getLiveStreams();
    if (res.ok && res.data) {
      ingressStream.value = res.data.ingress_stream || [];
      egressStream.value = res.data.egress_stream || [];
    }
  }

  async function simulateBotProbes() {
    if (isSimulatingProbes.value) return;
    isSimulatingProbes.value = true;
    const gateHost = typeof window !== 'undefined' ? `http://${window.location.hostname}:8000` : 'http://localhost:8000';
    try {
      await streamsApi.simulateBotProbes(gateHost);
      await fetchLiveStreams();
    } finally {
      isSimulatingProbes.value = false;
    }
  }

  return {
    ingressStream,
    egressStream,
    streamFilter,
    isSimulatingProbes,
    probeEventsCount,
    exploitEventsCount,
    cleanEventsCount,
    filteredIngressStream,
    mapEvents,
    fetchLiveStreams,
    simulateBotProbes,
  };
}
