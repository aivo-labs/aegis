import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const ZERODAY_EXPLOIT_REGEX = /(?:allow_url_include|auto_prepend_file|php:\/\/(?:input|filter|memory)|expect:\/\/|phar:\/\/|%ad[dD]\+|\$\{jndi:(?:ldap|rmi|dns|nis|iiop)|\{\{\s*7\s*\*\s*7\s*\}\}|O:\d+:"[^"]+":\d+:\{|rO0ABX|X-PHP2Shell|cve-2026-109618)/i;

export class ZeroDayRule implements IWafRule {
  public readonly id = 'ZERODAY';
  public readonly name = 'Zero-Day Virtual Patching (PHP2Shell, Log4Shell, SSTI, Deserialization)';
  public readonly order = 20;

  public evaluate(_ctx: InspectionContext, canonicalTarget: string): RuleMatch | null {
    if (ZERODAY_EXPLOIT_REGEX.test(canonicalTarget)) {
      return {
        threatType: 'ZERO_DAY_VIRTUAL_PATCH',
        severity: 'CRITICAL',
        riskScore: 99,
        pattern: 'Signature Zero-Day interceptée (Injection Runtime PHP/CGI, JNDI, SSTI ou Désérialisation)',
        httpStatus: 403
      };
    }
    return null;
  }
}
