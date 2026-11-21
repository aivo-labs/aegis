import type { EgressStateVector, SystemOneDecision } from '../types.js';
import type { ICtiBlocklistManager } from '../cti/blocklist.js';
import { calculateShannonEntropy } from './entropy.js';

export interface ISystemOneClient {
  evaluate(stateVector: EgressStateVector): Promise<SystemOneDecision>;
}

export class SystemOneClient implements ISystemOneClient {
  constructor(
    private readonly apiUrl: string,
    private readonly modelName: string,
    private readonly apiKey: string,
    private readonly ctiManager: ICtiBlocklistManager
  ) {}

  public async evaluate(stateVector: EgressStateVector): Promise<SystemOneDecision> {
    const startTime = performance.now();
    const { fqdn, domain_entropy, entropy: rawEntropy, isCrowdSecMatch, protocol_context } = stateVector;
    const entropy = domain_entropy ?? rawEntropy ?? calculateShannonEntropy(fqdn);

    // Level 1A-Bis (v1.3 Anti-Artex): Neutralisation des serveurs de callback OAST & tunnels LOTC (< 0.5 ms)
    const oastLotc = this.ctiManager.isOastOrLotcRelay ? this.ctiManager.isOastOrLotcRelay(fqdn) : { matched: false };
    if (oastLotc.matched) {
      const latency = Math.max(0.15, performance.now() - startTime);
      const isOast = oastLotc.category === 'OAST_BLIND_CALLBACK';
      return {
        action: 'BLOCK',
        confidence: 0.999,
        threat_type: isOast
          ? 'OAST_BLIND_EXPLOIT_CALLBACK_BLOCKED'
          : 'LOTC_TUNNEL_EXFILTRATION_BLOCKED',
        risk_score: isOast ? 99 : 97,
        reasoning: isOast
          ? `Serveur de callback OAST intercepté (${oastLotc.matchedSuffix}) — Neutralisation Blind SSRF/RCE Anti-Artex`
          : `Relais/Tunnel d'exfiltration LOTC intercepté (${oastLotc.matchedSuffix})`,
        latency_ms: parseFloat(latency.toFixed(2)),
        engine: isOast ? 'AEGIS_ANTI_ARTEX_OAST_SINKHOLE' : 'AEGIS_ANTI_ARTEX_LOTC_GUARD'
      };
    }

    const matchedCti = isCrowdSecMatch ?? this.ctiManager.isBlocked(fqdn);

    // Level 1A: Match immédiat CTI CrowdSec / CERT-FR (< 1 ms)
    if (matchedCti) {
      const latency = Math.max(0.2, performance.now() - startTime);
      return {
        action: 'BLOCK',
        confidence: 0.999,
        threat_type: 'C2_KNOWN_THREAT_CTI',
        risk_score: 99,
        latency_ms: parseFloat(latency.toFixed(2)),
        engine: 'CROWDSEC_CTI_LEVEL_1'
      };
    }

    // Level 1B: Détection coupe-circuit Reverse Shell / Tunneling C2
    if (this.ctiManager.matchesExfilPattern(fqdn) || protocol_context === 'reverse_shell_socket') {
      const latency = Math.max(0.3, performance.now() - startTime);
      return {
        action: 'BLOCK',
        confidence: 0.995,
        threat_type:
          protocol_context === 'reverse_shell_socket'
            ? 'REVERSE_SHELL_SOCKET_KILLED'
            : 'C2_CALLBACK_OR_TUNNELING',
        risk_score: 98,
        latency_ms: parseFloat(latency.toFixed(2)),
        engine: 'AEGIS_EGRESS_KERNEL_GUARD'
      };
    }

    // Level 2: Appel API System One si joignable
    if (this.apiUrl && !this.apiUrl.includes('mock')) {
      try {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (this.apiKey) {
          headers['Authorization'] = `Bearer ${this.apiKey}`;
        }
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 350);

        const response = await fetch(this.apiUrl, {
          method: 'POST',
          headers,
          signal: controller.signal,
          body: JSON.stringify({
            model: this.modelName,
            state: { ...stateVector, entropy }
          })
        });
        clearTimeout(timeoutId);

        if (response.ok) {
          const data = (await response.json()) as Partial<SystemOneDecision>;
          const latency = performance.now() - startTime;
          return {
            action: data.action || 'ALLOW',
            confidence: data.confidence || 0.95,
            threat_type: data.threat_type || 'CLEAN',
            risk_score: data.risk_score || 10,
            reasoning: data.reasoning || 'System One evaluation',
            latency_ms: parseFloat(latency.toFixed(2)),
            engine: `SYSTEMONE_${this.modelName.toUpperCase()}`
          };
        }
      } catch {
        // Fallback heuristique local rapide si Ollama n'a pas encore chargé le modèle
      }
    }

    // Level 2 (Local Engine Fallback): Calcul d'Entropie & Analyse Heuristique Nimble
    const lowFqdn = fqdn.toLowerCase();
    const isSuspiciousTLD =
      lowFqdn.endsWith('.top') ||
      lowFqdn.endsWith('.xyz') ||
      lowFqdn.endsWith('.click') ||
      lowFqdn.endsWith('.cc') ||
      lowFqdn.endsWith('.ru') ||
      lowFqdn.endsWith('.tk');
    const isHighEntropy = entropy >= 3.55;
    const isVeryHighEntropy = entropy >= 3.95;

    let action: 'BLOCK' | 'ALLOW' | 'QUARANTINE' = 'ALLOW';
    let threatType = 'CLEAN_EGRESS';
    let confidence = 0.98;
    let riskScore = 8;

    if ((isHighEntropy && isSuspiciousTLD) || isVeryHighEntropy) {
      action = 'BLOCK';
      threatType = 'DGA_EXFILTRATION_DETECTED';
      confidence = 0.985;
      riskScore = 95;
    } else if (isHighEntropy || isSuspiciousTLD) {
      action = 'QUARANTINE';
      threatType = 'SUSPECTED_ANOMALOUS_EGRESS';
      confidence = 0.84;
      riskScore = 72;
    }

    const latency = Math.max(0.4, performance.now() - startTime);

    return {
      action,
      confidence,
      threat_type: threatType,
      risk_score: riskScore,
      latency_ms: parseFloat(latency.toFixed(2)),
      engine: `SYSTEMONE_${this.modelName.toUpperCase()}_LOCAL`
    };
  }
}
