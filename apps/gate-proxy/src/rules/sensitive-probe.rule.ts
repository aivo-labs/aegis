import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const SENSITIVE_PROBE_REGEX = /(?:\.aws\/credentials|wp-config\.php|id_rsa|backup\.sql|phpinfo\.php|\/eval-stdin|\.ds_store|vendor\/phpunit)/i;

export class SensitiveProbeRule implements IWafRule {
  public readonly id = 'SENSITIVE_PROBE';
  public readonly name = 'Sensitive File Probes & Backdoors';
  public readonly order = 70;

  public evaluate(_ctx: InspectionContext, canonicalTarget: string): RuleMatch | null {
    if (SENSITIVE_PROBE_REGEX.test(canonicalTarget)) {
      return {
        threatType: 'SENSITIVE_FILE_PROBE',
        severity: 'HIGH',
        riskScore: 88,
        pattern: 'Sonde de fichier critique ou composant vulnérable (wp-config, id_rsa, phpunit)',
        httpStatus: 403
      };
    }
    return null;
  }
}
