import type { IncomingHttpHeaders } from 'node:http';
import type { WafRuleRegistry } from '../rules/registry.js';
import type { IIpReputationManager } from '../quarantine/ip-reputation.js';
import type { InspectionContext, WafVerdict } from '../types.js';
import { canonicalizeInput } from './canonicalizer.js';
import { computeRequestEntropy } from './entropy.js';

export interface IWafInspector {
  inspect(
    url: string,
    method: string,
    headers: IncomingHttpHeaders,
    rawBody: string,
    byteLength: number,
    clientIp: string
  ): WafVerdict;
}

export class WafInspector implements IWafInspector {
  constructor(
    private readonly ruleRegistry: WafRuleRegistry,
    private readonly ipReputation: IIpReputationManager,
    private readonly getMaxPayloadBytes: () => number
  ) {}

  public inspect(
    url: string,
    method: string,
    headers: IncomingHttpHeaders,
    rawBody = '',
    byteLength = 0,
    clientIp = ''
  ): WafVerdict {
    const userAgent = (headers['user-agent'] as string) || '';
    const customExploitHeader = (headers['x-exploit-signature'] as string) || (headers['x-php-args'] as string) || '';
    const rawCombined = `${url || '/'} ${customExploitHeader} ${rawBody}`;
    const targetToScan = canonicalizeInput(rawCombined);
    const entropy = computeRequestEntropy(rawCombined);

    // Règle 0 : Protection Volumétrique / Buffer & Heap Overflow (413 Payload Too Large)
    const declaredLength = parseInt((headers['content-length'] as string) || '0', 10);
    const maxPayloadBytes = this.getMaxPayloadBytes();
    if (byteLength > maxPayloadBytes || declaredLength > maxPayloadBytes) {
      return {
        blocked: true,
        http_status: 413,
        decision: 'BLOCK',
        threat_type: 'OVERFLOW_PAYLOAD_413 (Virtual Patch)',
        severity: 'CRITICAL',
        risk_score: 99,
        entropy: Math.max(entropy, 4.75),
        pattern: `Payload volumétrique rejeté à l'Edge (${Math.max(byteLength, declaredLength)} octets > limite ${maxPayloadBytes} octets — Protection Buffer/Heap Overflow & PHP2Shell)`
      };
    }

    // Règle -1 : Liste Noire IP Dynamique (Ban IP SOC)
    if (clientIp && this.ipReputation.isBanned(clientIp)) {
      return {
        blocked: true,
        http_status: 403,
        decision: 'BLOCK',
        threat_type: 'BANNED_IP_BLACKLIST',
        severity: 'CRITICAL',
        risk_score: 100,
        entropy,
        pattern: `Adresse IP source (${clientIp}) inscrite sur la liste noire active d'Aegis SOC`
      };
    }

    const ctx: InspectionContext = {
      url,
      method,
      headers,
      rawBody,
      byteLength,
      clientIp
    };

    // Évaluation des règles modulaires dans l'ordre de priorité
    for (const rule of this.ruleRegistry.getRules()) {
      const match = rule.evaluate(ctx, targetToScan);
      if (match) {
        let finalEntropy = entropy;
        if (match.threatType === 'ZERO_DAY_VIRTUAL_PATCH') {
          finalEntropy = Math.max(entropy, 4.65);
        }
        return {
          blocked: true,
          http_status: match.httpStatus || 403,
          decision: 'BLOCK',
          threat_type: match.threatType,
          severity: match.severity,
          risk_score: match.riskScore,
          entropy: finalEntropy,
          pattern: match.pattern
        };
      }
    }

    // Requête saine
    return {
      blocked: false,
      http_status: 200,
      decision: 'ALLOW',
      threat_type: 'CLEAN_TRAFFIC',
      severity: 'COMPLIANT',
      risk_score: 5,
      entropy,
      pattern: 'Conforme aux politiques Zero-Trust Aegis Gate'
    };
  }
}
