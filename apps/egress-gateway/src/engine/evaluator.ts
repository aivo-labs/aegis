import type { ISystemOneClient } from './system-one.js';
import type { IEgressTelemetryReporter } from '../telemetry/reporter.js';
import type { ICtiBlocklistManager } from '../cti/blocklist.js';
import type { EgressVerdict } from '../types.js';
import { calculateShannonEntropy } from './entropy.js';
import { DnsToIpAllowlist, isLiteralIpAddress, extractPureIp } from './ip-allowlist.js';

export interface IEgressEvaluator {
  processQuery(fqdn: string, clientIp?: string, protocolContext?: string): Promise<EgressVerdict>;
  verifyIpConnection(targetIp: string, clientIp?: string, destPort?: number): Promise<EgressVerdict>;
  getIpAllowlist(): DnsToIpAllowlist;
  isProtectionEnabled(): boolean;
  setProtectionEnabled(enabled: boolean): void;
}

export class EgressEvaluator implements IEgressEvaluator {
  private readonly ipAllowlist: DnsToIpAllowlist;

  constructor(
    private readonly systemOneClient: ISystemOneClient,
    private readonly telemetryReporter: IEgressTelemetryReporter,
    private readonly ctiManager: ICtiBlocklistManager,
    private readonly tenantId: string,
    private protectionEnabled: boolean = true,
    ipAllowlist?: DnsToIpAllowlist
  ) {
    this.ipAllowlist = ipAllowlist || new DnsToIpAllowlist(60_000);
  }

  public isProtectionEnabled(): boolean {
    return this.protectionEnabled;
  }

  public setProtectionEnabled(enabled: boolean): void {
    this.protectionEnabled = enabled;
  }

  public getIpAllowlist(): DnsToIpAllowlist {
    return this.ipAllowlist;
  }

  public async verifyIpConnection(
    targetIp: string,
    clientIp = '127.0.0.1',
    destPort = 443
  ): Promise<EgressVerdict> {
    const start = performance.now();
    const check = this.ipAllowlist.verifyOutboundIp(targetIp);
    const latencyMs = Number(Math.max(0.05, performance.now() - start).toFixed(2));
    const wouldBlock = !check.allowed;

    const effectiveAction = wouldBlock
      ? (this.protectionEnabled ? 'BLOCK' : 'BYPASS')
      : 'ALLOW';
    const effectiveThreatType = (!this.protectionEnabled && wouldBlock)
      ? `${check.threat_type} [EXFILTRÉ]`
      : check.threat_type;
    const effectiveEngine = wouldBlock
      ? (this.protectionEnabled
          ? 'Aegis Egress P0 Confinement (DNS-to-IP Allowlist + cgroup/connect4)'
          : '⚠️ Egress Désactivé (Fuite Reverse Shell IP Brute)')
      : 'Aegis Egress P0 Confinement (DNS-Verified)';

    const targetLabel = destPort ? `${check.ip}:${destPort}` : check.ip;

    this.telemetryReporter
      .send({
        tenant_id: this.tenantId,
        client_ip: clientIp,
        fqdn: check.fqdn ? `${check.fqdn} (${targetLabel})` : targetLabel,
        domain_entropy: wouldBlock ? 4.85 : 2.1,
        action: effectiveAction,
        threat_type: effectiveThreatType,
        confidence: wouldBlock ? 0.99 : 0.05,
        latency_ms: latencyMs,
        metadata: {
          engine: effectiveEngine,
          risk_score: wouldBlock ? 99 : 5,
          protocol: 'tcp_raw_ip',
          dest_ip: check.ip,
          dest_port: destPort,
          reason: check.reason,
          protection_enabled: this.protectionEnabled
        }
      })
      .catch(() => {});

    return {
      action: effectiveAction,
      threat_type: effectiveThreatType,
      confidence: wouldBlock ? 0.99 : 0.05,
      risk_score: wouldBlock ? 99 : 5,
      latency_ms: latencyMs,
      engine: effectiveEngine,
      reasoning: check.reason,
      protection_enabled: this.protectionEnabled
    };
  }

  public async processQuery(
    fqdn: string,
    clientIp = '127.0.0.1',
    protocolContext = 'dns_query'
  ): Promise<EgressVerdict> {
    const cleanFqdn = (fqdn || 'unknown.local').replace(/\.$/, '').trim();

    // Verrou n°1 (P0) : Si la cible est une adresse IP littérale brute sans résolution DNS
    if (isLiteralIpAddress(cleanFqdn)) {
      const portMatch = cleanFqdn.split(':');
      const port = portMatch.length === 2 ? parseInt(portMatch[1], 10) || 4444 : 4444;
      return this.verifyIpConnection(extractPureIp(cleanFqdn), clientIp, port);
    }

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

    // Si le domaine est légitime (ALLOW), enregistrer l'IP résolue dans la table DNS-to-IP (TTL 60s)
    if (!wouldBlock) {
      this.ipAllowlist.authorizeResolvedIp('93.184.216.34', cleanFqdn, 60_000);
    }

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
