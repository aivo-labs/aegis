export interface GateConfig {
  port: number;
  backendUrl: string;
  webUrl: string;
  telemetryUrl: string;
  tenantId: string;
  sessionSecret: string;
  defaultMaxPayloadBytes: number;
  defaultProtectionEnabled: boolean;
  upstreamRouting: Record<string, string>;
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

  return {
    port: parseInt(process.env.GATE_PORT || '8000', 10),
    backendUrl,
    webUrl: process.env.WEB_URL || 'http://web:80',
    telemetryUrl: process.env.AEGIS_GATE_API_URL || `${backendUrl}/api/v1/gate/telemetry/ingress`,
    tenantId: process.env.AEGIS_TENANT_ID || '00000000-0000-0000-0000-000000000001',
    sessionSecret: process.env.BFF_SESSION_SECRET || process.env.APP_SECRET || 'aegis_sovereign_session_secret_32b_key!',
    defaultMaxPayloadBytes: parseInt(process.env.AEGIS_MAX_PAYLOAD_BYTES || '32768', 10),
    defaultProtectionEnabled: process.env.AEGIS_PROTECTION_ENABLED !== 'false',
    upstreamRouting
  };
}
