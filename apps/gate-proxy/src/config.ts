import crypto from 'node:crypto';

export interface GateConfig {
  port: number;
  backendUrl: string;
  webUrl: string;
  telemetryUrl: string;
  tenantId: string;
  sessionSecret: string;
  internalAdminToken?: string;
  trustedProxies?: string[];
  allowDemoAuth?: boolean;
  defaultMaxPayloadBytes: number;
  defaultProtectionEnabled: boolean;
  upstreamRouting: Record<string, string>;
  nodeMode?: 'control-plane' | 'edge';
  nodeHostname?: string;
  egressGatewayUrl?: string;
}

export function loadConfigFromEnv(): GateConfig {
  const backendUrl = process.env.BACKEND_URL || 'http://backend:80';
  let upstreamRouting: Record<string, string> = {};
  if (process.env.AEGIS_UPSTREAM_ROUTING) {
    try {
      upstreamRouting = JSON.parse(process.env.AEGIS_UPSTREAM_ROUTING);
    } catch {
      for (const pair of process.env.AEGIS_UPSTREAM_ROUTING.split(',')) {
        const [k, v] = pair.split('=');
        if (k && v) upstreamRouting[k.trim().toLowerCase()] = v.trim();
      }
    }
  }

  let sessionSecret = process.env.BFF_SESSION_SECRET || process.env.APP_SECRET || '';
  if (!sessionSecret || sessionSecret.includes('aegis_sovereign_session_secret') || sessionSecret.includes('ctf_aegis_bff_session_secret')) {
    sessionSecret = crypto.randomBytes(32).toString('hex');
    console.warn('⚠️ [Aegis Gate Security] BFF_SESSION_SECRET absent ou valeur par défaut détectée — génération d\'une clé aléatoire éphémère (256-bit).');
  }

  let internalAdminToken = process.env.AEGIS_INTERNAL_TOKEN || '';
  if (!internalAdminToken) {
    internalAdminToken = crypto.randomBytes(32).toString('hex');
  }

  const trustedProxies = (process.env.AEGIS_TRUSTED_PROXIES || '127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  const isCtfMode = process.env.AEGIS_CTF_MODE === 'true';
  const allowDemoAuth = !isCtfMode && process.env.AEGIS_ALLOW_DEMO_AUTH === 'true';

  return {
    port: parseInt(process.env.GATE_PORT || '8000', 10),
    backendUrl,
    webUrl: process.env.WEB_URL || 'http://web:80',
    telemetryUrl: process.env.AEGIS_GATE_API_URL || `${backendUrl}/api/v1/gate/telemetry/ingress`,
    tenantId: process.env.AEGIS_TENANT_ID || '00000000-0000-0000-0000-000000000001',
    sessionSecret,
    internalAdminToken,
    trustedProxies,
    allowDemoAuth,
    defaultMaxPayloadBytes: parseInt(process.env.AEGIS_MAX_PAYLOAD_BYTES || '32768', 10),
    defaultProtectionEnabled: process.env.AEGIS_PROTECTION_ENABLED !== 'false',
    upstreamRouting,
    nodeMode: process.env.AEGIS_NODE_MODE === 'edge' ? 'edge' : 'control-plane',
    nodeHostname: process.env.AEGIS_NODE_HOSTNAME || process.env.AEGIS_SERVER_ID || '',
    egressGatewayUrl: process.env.EGRESS_GATEWAY_URL || 'http://egress-gateway:5053'
  };
}

