import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const RCE_REGEX =
  /(?:;\s*(?:cat|ls|id|whoami|curl|wget|nc|ncat|bash|sh|dash|python3?|perl|php|ruby|powershell|awk|busybox|base64|uname)\b|\|\s*(?:cat|ls|id|whoami|sh|bash|dash|awk|base64|nc|curl|wget)\b|`[^`]*(?:whoami|id|cat|curl|wget|sh|bash|uname)[^`]*`|\$\(\s*(?:whoami|id|cat|curl|wget|sh|bash|python3?|uname|env|printenv)[^)]*\)|\$\{IFS\}|\/bin\/(?:sh|bash|zsh|dash|busybox)|\/dev\/(?:tcp|udp)\/|mkfifo\s+)/i;

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
