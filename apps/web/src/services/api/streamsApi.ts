import { apiRequest } from './client';

export interface IngressEvent {
  id: string;
  client_ip: string;
  method: string;
  target: string;
  threat_type?: string;
  category?: string;
  decision: 'ALLOW' | 'BLOCK' | 'BYPASS';
  status_code: number;
  timestamp: string;
  lat?: number;
  lon?: number;
  country?: string;
}

export interface EgressEvent {
  id: string;
  protocol: 'DNS' | 'TCP';
  domain?: string;
  target_ip?: string;
  port?: number;
  decision: 'ALLOW' | 'BLOCK' | 'BYPASS';
  threat_type?: string;
  entropy?: number;
  timestamp: string;
}

export interface LiveStreamsResponse {
  ingress_stream: IngressEvent[];
  egress_stream: EgressEvent[];
  timestamp: string;
}

export const streamsApi = {
  async getLiveStreams() {
    return apiRequest<LiveStreamsResponse>('/api/v1/dashboard/live-streams', { method: 'GET' });
  },

  async simulateBotProbes() {
    try {
      const res = await fetch('/_aegis/simulate', { method: 'POST' });
      if (res.ok) {
        return await res.json();
      }
    } catch {}

    // Fallback direct relatif
    const probes = [
      '/wp-login.php',
      '/wp-content/plugins/revslider/temp/update_extract/revslider/db.php',
      '/xmlrpc.php',
      '/.env',
      '/phpmyadmin/index.php',
      '/api/v1/search?q=1+UNION+SELECT+username,password+FROM+users--',
    ];
    for (const p of probes) {
      await fetch(p, { method: 'GET' }).catch(() => {});
    }
  },
};
