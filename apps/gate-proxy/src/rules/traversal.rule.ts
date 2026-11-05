import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const TRAVERSAL_REGEX = /(?:\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow|\/proc\/self|\.env|\.git\/|win\.ini|boot\.ini|WEB-INF)/i;

export class TraversalRule implements IWafRule {
  public readonly id = 'TRAVERSAL';
  public readonly name = 'Path Traversal & Local File Inclusion';
  public readonly order = 60;

  public evaluate(_ctx: InspectionContext, canonicalTarget: string): RuleMatch | null {
    if (TRAVERSAL_REGEX.test(canonicalTarget)) {
      return {
        threatType: 'PATH_TRAVERSAL_LFI',
        severity: 'HIGH',
        riskScore: 90,
        pattern: "Tentative d'accès arborescent non autorisé (/etc/passwd, .env, .git)",
        httpStatus: 403
      };
    }
    return null;
  }
}
