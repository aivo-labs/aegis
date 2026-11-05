import type { IncomingHttpHeaders } from 'node:http';

export type ThreatSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'COMPLIANT';

export type WafDecision = 'BLOCK' | 'ALLOW' | 'BYPASS';

export interface InspectionContext {
  url: string;
  method: string;
  headers: IncomingHttpHeaders;
  rawBody: string;
  byteLength: number;
  clientIp: string;
}

export interface RuleMatch {
  threatType: string;
  severity: ThreatSeverity;
  riskScore: number;
  pattern: string;
  httpStatus?: number;
}

export interface WafVerdict {
  blocked: boolean;
  http_status: number;
  decision: WafDecision;
  threat_type: string;
  severity: ThreatSeverity;
  risk_score: number;
  entropy: number;
  pattern: string;
}

export interface IngressTelemetryPayload {
  tenant_id: string;
  client_ip: string;
  user_agent: string;
  http_method: string;
  request_uri: string;
  decision: string;
  http_status_returned: number;
  latency_ms: number;
  threat_type?: string;
  severity?: string;
  risk_score?: number;
  entropy?: number;
  matched_pattern?: string;
  metadata?: Record<string, unknown>;
}
