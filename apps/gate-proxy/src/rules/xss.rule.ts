import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const XSS_REGEX =
  /(?:<(?:script|iframe|svg|object|embed|math)[\s/>]|(?:javascript|vbscript):|\bon(?:error|load|focus|blur|click|mouseover|pointerenter|toggle|animationstart|transitionend|input|change)\s*=|alert\s*\(|eval\s*\(|document\.cookie)/i;

export class XssRule implements IWafRule {
  public readonly id = 'XSS';
  public readonly name = 'Cross-Site Scripting (XSS)';
  public readonly order = 90;

  public evaluate(_ctx: InspectionContext, canonicalTarget: string): RuleMatch | null {
    if (XSS_REGEX.test(canonicalTarget)) {
      return {
        threatType: 'XSS_ATTEMPT',
        severity: 'MEDIUM',
        riskScore: 78,
        pattern: 'Vecteur Cross-Site Scripting (balise script ou gestionnaire DOM)',
        httpStatus: 403
      };
    }
    return null;
  }
}
