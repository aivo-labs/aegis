import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const SCANNER_REGEX = /(?:nikto|sqlmap|nuclei|gobuster|dirbuster|nmap|masscan|wpscan|acunetix|nessus|havij|hydra|burpcollaborator|ffuf|feroxbuster|zgrab|openvas)/i;

export class ScannerRule implements IWafRule {
  public readonly id = 'SCANNER';
  public readonly name = 'Security Scanners & Pentest Tools';
  public readonly order = 10;

  public evaluate(ctx: InspectionContext): RuleMatch | null {
    const userAgent = (ctx.headers['user-agent'] as string) || '';
    if (SCANNER_REGEX.test(userAgent)) {
      const match = userAgent.match(SCANNER_REGEX);
      return {
        threatType: 'PENTEST_SCANNER_DETECTED',
        severity: 'HIGH',
        riskScore: 92,
        pattern: `Scanner User-Agent intercepté : ${match ? match[0] : 'Scanner'}`,
        httpStatus: 403
      };
    }
    return null;
  }
}
