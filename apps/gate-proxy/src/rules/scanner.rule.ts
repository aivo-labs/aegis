import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

export const SCANNER_REGEX =
  /(?:artex|hexstrike|cyberstrike|pentestgpt|reaperai|xbow|cairn|nikto|sqlmap|nuclei|gobuster|dirbuster|nmap|masscan|wpscan|acunetix|nessus|havij|hydra|burpcollaborator|ffuf|feroxbuster|zgrab|openvas|katana|dalfox|commix|arjun|subfinder|naabu|amass|wfuzz)/i;

const MODERN_BROWSER_CLAIM_REGEX = /(?:Chrome|Edg)\/1[1-9]\d\./i;

export class ScannerRule implements IWafRule {
  public readonly id = 'SCANNER';
  public readonly name = 'Security Scanners & Autonomous AI Pentest Agents';
  public readonly order = 10;

  public evaluate(ctx: InspectionContext): RuleMatch | null {
    const userAgent = (ctx.headers['user-agent'] as string) || '';
    const customAgentHeader =
      (ctx.headers['x-artex-worker'] as string) ||
      (ctx.headers['x-pentest-agent'] as string) ||
      (ctx.headers['x-scanner'] as string) ||
      '';

    if (SCANNER_REGEX.test(userAgent) || SCANNER_REGEX.test(customAgentHeader)) {
      const match = userAgent.match(SCANNER_REGEX) || customAgentHeader.match(SCANNER_REGEX);
      return {
        threatType: 'PENTEST_SCANNER_DETECTED',
        severity: 'HIGH',
        riskScore: 94,
        pattern: `Scanner ou Agent IA offensif intercepté : ${match ? match[0] : 'Scanner'}`,
        httpStatus: 403
      };
    }

    // Verrou n°5-Bis (v1.3 « Anti-Artex ») : Détection d'incohérence d'empreinte navigateur (Header Fingerprint Mismatch)
    // Un Worker Go/Python (net/http, requests, curl) usurpant un User-Agent Chrome/Edge moderne mais envoyant
    // "Accept: */*" sans aucun en-tête structurel de navigateur (Sec-Ch-Ua, Sec-Fetch-Mode, Accept-Language).
    if (
      MODERN_BROWSER_CLAIM_REGEX.test(userAgent) &&
      String(ctx.headers['accept'] || '').trim() === '*/*' &&
      !ctx.headers['sec-ch-ua'] &&
      !ctx.headers['sec-fetch-mode'] &&
      !ctx.headers['accept-language']
    ) {
      return {
        threatType: 'AI_AGENT_SPOOFED_BROWSER_FINGERPRINT',
        severity: 'HIGH',
        riskScore: 91,
        pattern: `Incohérence d'empreinte protocole Anti-Artex : User-Agent Chrome/Edge déclaré avec 'Accept: */*' sans Sec-Ch-Ua / Sec-Fetch-Mode / Accept-Language`,
        httpStatus: 403
      };
    }

    return null;
  }
}

