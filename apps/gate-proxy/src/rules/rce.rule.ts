import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const RCE_REGEX = /(?:;\s*(?:cat|ls|id|whoami|curl|wget|nc|ncat|bash|sh|python|perl|php|ruby|powershell)\b|\|\s*(?:cat|ls|id|whoami|sh|bash)\b|`.*(?:whoami|id|cat).*`|\$\((?:whoami|id|cat|curl|wget).*\)|\/bin\/(?:sh|bash|zsh)|\/dev\/tcp\/|mkfifo\s+)/i;

export class RceRule implements IWafRule {
  public readonly id = 'RCE';
  public readonly name = 'Remote Command Execution & Reverse Shells';
  public readonly order = 30;

  public evaluate(_ctx: InspectionContext, canonicalTarget: string): RuleMatch | null {
    if (RCE_REGEX.test(canonicalTarget)) {
      return {
        threatType: 'COMMAND_INJECTION_RCE',
        severity: 'CRITICAL',
        riskScore: 99,
        pattern: "Tentative d'exécution de commandes système ou Reverse Shell (/bin/sh)",
        httpStatus: 403
      };
    }
    return null;
  }
}
