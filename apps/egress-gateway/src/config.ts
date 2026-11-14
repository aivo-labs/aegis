export interface EgressConfig {
  tenantId: string;
  gateApiUrl: string;
  listenPort: number;
  systemOneApiUrl: string;
  systemOneModelName: string;
  systemOneApiKey: string;
  defaultProtectionEnabled: boolean;
}

export function loadEgressConfigFromEnv(): EgressConfig {
  const systemOneApiUrl = process.env.SYSTEMONE_API_URL ||
    (process.env.TYPESAFE_BASE_URL ? `${process.env.TYPESAFE_BASE_URL}/v1/systemone` : 'http://localhost:11434/v1/systemone');
  const systemOneModelName = process.env.SYSTEMONE_MODEL_NAME || process.env.TYPESAFE_DEFAULT_MODEL || 'nimble';
  const systemOneApiKey = process.env.SYSTEMONE_API_KEY || process.env.TYPESAFE_API_KEY || '';

  return {
    tenantId: process.env.AEGIS_TENANT_ID || '00000000-0000-0000-0000-000000000001',
    gateApiUrl: process.env.AEGIS_GATE_API_URL || 'http://localhost:8080/api/v1/gate/telemetry/egress',
    listenPort: parseInt(process.env.EGRESS_LISTEN_PORT || '5053', 10),
    systemOneApiUrl,
    systemOneModelName,
    systemOneApiKey,
    defaultProtectionEnabled: process.env.AEGIS_PROTECTION_ENABLED !== 'false'
  };
}
