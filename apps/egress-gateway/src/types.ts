export type EgressAction = 'BLOCK' | 'ALLOW' | 'QUARANTINE' | 'BYPASS';

export interface EgressStateVector {
  fqdn: string;
  domain_entropy?: number;
  entropy?: number;
  isCrowdSecMatch?: boolean;
  client_ip?: string;
  protocol_context?: string;
}

export interface SystemOneDecision {
  action: EgressAction;
  confidence: number;
  threat_type: string;
  risk_score: number;
  latency_ms: number;
  engine: string;
  reasoning?: string;
}

export interface EgressVerdict extends SystemOneDecision {
  protection_enabled: boolean;
}

export interface EgressTelemetryPayload {
  tenant_id: string;
  client_ip: string;
  fqdn: string;
  domain_entropy: number;
  action: string;
  threat_type: string;
  confidence: number;
  latency_ms: number;
  metadata?: Record<string, unknown>;
}
