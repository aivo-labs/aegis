import type { ISystemOneClient } from './system-one.js';
import type { IEgressTelemetryReporter } from '../telemetry/reporter.js';
import type { ICtiBlocklistManager } from '../cti/blocklist.js';
import type { EgressVerdict } from '../types.js';
import { calculateShannonEntropy } from './entropy.js';

export interface IEgressEvaluator {
  processQuery(fqdn: string, clientIp?: string, protocolContext?: string): Promise<EgressVerdict>;
  isProtectionEnabled(): boolean;
  setProtectionEnabled(enabled: boolean): void;
}

export class EgressEvaluator implements IEgressEvaluator {
  constructor(
    private readonly systemOneClient: ISystemOneClient,
    private readonly telemetryReporter: IEgressTelemetryReporter,
    private readonly ctiManager: ICtiBlocklistManager,
    private readonly tenantId: string,
    private protectionEnabled: boolean = true
  ) {}

  public isProtectionEnabled(): boolean {
    return this.protectionEnabled;
  }

  public setProtectionEnabled(enabled: boolean): void {
    this.protectionEnabled = enabled;
  }

  public async processQuery(
    fqdn: string,
    clientIp = '127.0.0.1',
    protocolContext = 'dns_query'
  ): Promise<EgressVerdict> {
    const cleanFqdn = (fqdn || 'unknown.local').replace(/\.$/, '').trim();
    const entropy = calculateShannonEntropy(cleanFqdn);
    const isCrowdSecMatch = this.ctiManager.isBlocked(cleanFqdn);

    const stateVector = {
      fqdn: cleanFqdn,
      domain_entropy: entropy,
      entropy,
      isCrowdSecMatch,
      client_ip: clientIp,
      protocol_context: protocolContext
    };

    const decision = await this.systemOneClient.evaluate(stateVector);
    const wouldBlock = decision.action === 'BLOCK' || decision.action === 'QUARANTINE';

    const effectiveAction = (!this.protectionEnabled && wouldBlock) ? 'BYPASS' : decision.action;
    const effectiveThreatType = (!this.protectionEnabled && wouldBlock)
      ? `${decision.threat_type} [EXFILTRÉ]`
      : decision.threat_type;
    const effectiveEngine = (!this.protectionEnabled && wouldBlock)
      ? '⚠️ Egress Désactivé (Fuite C2 / Reverse Shell Actif)'
      : decision.engine;

    const telemetryPayload = {
      tenant_id: this.tenantId,
      client_ip: clientIp,
      fqdn: cleanFqdn,
      domain_entropy: entropy,
      action: effectiveAction,
      threat_type: effectiveThreatType,
      confidence: decision.confidence,
      latency_ms: decision.latency_ms,
      metadata: {
        engine: effectiveEngine,
        risk_score: decision.risk_score,
        protocol: protocolContext,
        protection_enabled: this.protectionEnabled
      }
    };

    this.telemetryReporter.send(telemetryPayload).catch(() => {});

    return {
      ...decision,
      action: effectiveAction,
      threat_type: effectiveThreatType,
      engine: effectiveEngine,
      protection_enabled: this.protectionEnabled
    };
  }
}
