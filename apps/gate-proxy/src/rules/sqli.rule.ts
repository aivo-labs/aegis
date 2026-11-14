import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const SQLI_REGEX = /(?:(?:\bunion\b\s+(?:all\s+)?\bselect\b)|\bselect\b\s+.*\s+\bfrom\b|'\s*(?:or|and)\s*'?\d+'?\s*=\s*'?\d+|;\s*waitfor\s+delay|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|information_schema|pg_sleep\s*\(|(?:'|"|;|\))\s*--|\s+--(?:\s+|$)|--\s+|\/\*.*\*\/)/i;

export class SqliRule implements IWafRule {
  public readonly id = 'SQLI';
  public readonly name = 'SQL Injection (OWASP Top 10)';
  public readonly order = 50;

  public evaluate(_ctx: InspectionContext, canonicalTarget: string): RuleMatch | null {
    if (SQLI_REGEX.test(canonicalTarget)) {
      return {
        threatType: 'SQL_INJECTION',
        severity: 'CRITICAL',
        riskScore: 98,
        pattern: "Signature d'injection SQL détectée dans l'URI ou le corps de requête",
        httpStatus: 403
      };
    }
    return null;
  }
}
