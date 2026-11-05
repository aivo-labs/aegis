import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const CMS_PHP_PROBE_REGEX = /(?:\/wp-login\.php|\/wp-content\/|\/wp-includes\/|\/wp-admin\/|\/xmlrpc\.php|\/phpmyadmin|\/adminer\.php|\/pma\/)/i;

export class CmsProbeRule implements IWafRule {
  public readonly id = 'CMS_PROBE';
  public readonly name = 'Automated CMS & PHP Admin Probes';
  public readonly order = 80;

  public evaluate(_ctx: InspectionContext, canonicalTarget: string): RuleMatch | null {
    if (CMS_PHP_PROBE_REGEX.test(canonicalTarget)) {
      return {
        threatType: 'CMS_PHP_BOT_PROBE',
        severity: 'HIGH',
        riskScore: 86,
        pattern: 'Sonde automatisée de bruit de fond ciblant WordPress / PHP (wp-login, wp-content, xmlrpc, phpmyadmin)',
        httpStatus: 403
      };
    }
    return null;
  }
}
