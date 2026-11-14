import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const SSRF_REGEX = /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|gopher:\/\/|dict:\/\/|file:\/\/\/|localhost:(?:2375|6379|9200|27017)|127\.0\.0\.1:(?:2375|6379|9200))/i;

export class SsrfRule implements IWafRule {
  public readonly id = 'SSRF';
  public readonly name = 'SSRF & Cloud Metadata Probes';
  public readonly order = 40;

  public evaluate(_ctx: InspectionContext, canonicalTarget: string): RuleMatch | null {
    if (SSRF_REGEX.test(canonicalTarget)) {
      return {
        threatType: 'SSRF_METADATA_PROBE',
        severity: 'CRITICAL',
        riskScore: 96,
        pattern: 'Tentative SSRF vers métadonnées Cloud (169.254.169.254) ou démon interne',
        httpStatus: 403
      };
    }
    return null;
  }
}
