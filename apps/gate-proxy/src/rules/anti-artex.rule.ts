import type { IWafRule } from './rule.interface.js';
import type { InspectionContext, RuleMatch } from '../types.js';

/**
 * Verrou n°5-Bis (v1.3 « Anti-Artex ») :
 * Règle dédiée à la neutralisation des orchestrateurs de pentest IA autonomes (ARTEX, Hexstrike, CyberStrikeAI) :
 * 1. Piège Canary Honeypot (détection de chaînage de secrets factices par un Agent Worker)
 * 2. Injection de callback OAST entrant (Blind SSRF / RCE / Log4Shell via interact.sh / oast.*)
 * 3. Verrouillage des schémas de découverte d'API (OpenAPI, Swagger, Actuator, Introspection GraphQL)
 * 4. Protection logique métier Anti-Mass Assignment & Prototype Pollution
 */

export const CANARY_TRIPWIRE_REGEX = /(?:AEGIS_CANARY_TRAP_[A-Z0-9_]+|ak_live_aegis_canary_[a-z0-9_]+)/i;

export const OAST_INBOUND_CALLBACK_REGEX =
  /\b(?:[a-z0-9-]+\.)*(?:interact\.sh|interactsh\.com|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net|oastify\.com|canarytokens\.com|webhook\.site|dnslog\.cn|ceye\.io)\b/i;

export const API_SCHEMA_RECON_REGEX =
  /(?:^|\/)(?:swagger(?:-ui|-resources)?(?:\.(?:json|yaml|yml|html))?|openapi\.(?:json|yaml|yml)|v[23]\/api-docs|api-docs(?:\.json)?|redoc|actuator(?:\/[a-z0-9_-]+)?)(?:\/|\?|\s|$)|(?:\b__schema\b|\b__type\s*\()/i;

export const MASS_ASSIGNMENT_REGEX =
  /(?:"__proto__"|constructor\s*\.\s*prototype|"(?:is_admin|isAdmin|is_superuser|isSuperuser|is_staff)"\s*:\s*true|"(?:user_role|account_role|privilege_level)"\s*:\s*"(?:admin|superadmin|root|owner)")/i;

export class AntiArtexRule implements IWafRule {
  public readonly id = 'ANTI_ARTEX_SHIELD';
  public readonly name = 'Anti-Artex Autonomous AI Pentest Shield (Canary, OAST, API Schema & Mass Assignment)';
  public readonly order = 15;

  public evaluate(ctx: InspectionContext, canonicalTarget: string): RuleMatch | null {
    const authHeader = (ctx.headers['authorization'] as string) || '';
    const apiKeyHeader = (ctx.headers['x-api-key'] as string) || (ctx.headers['x-aegis-token'] as string) || '';
    const cookieHeader = (ctx.headers['cookie'] as string) || '';
    const refererHeader = (ctx.headers['referer'] as string) || '';
    const hostHeader = ((ctx.headers['x-forwarded-host'] || ctx.headers['host'] || '') as string);

    const combinedInspectionSurface = `${canonicalTarget} ${authHeader} ${apiKeyHeader} ${cookieHeader} ${refererHeader} ${hostHeader}`;

    // 1. Canary Token Tripwire : Preuve mathématique d'un agent autonome rejouant un secret extrait d'un Honeypot
    if (CANARY_TRIPWIRE_REGEX.test(combinedInspectionSurface)) {
      const match = combinedInspectionSurface.match(CANARY_TRIPWIRE_REGEX);
      return {
        threatType: 'CANARY_TOKEN_TRIPWIRE_TRIGGERED',
        severity: 'CRITICAL',
        riskScore: 100,
        pattern: `Piège Canary Anti-Artex déclenché : Chaînage autonome d'un secret leurre détecté (${match ? match[0] : 'CANARY_TOKEN'})`,
        httpStatus: 403
      };
    }

    // 2. OAST Blind Callback Payload : Neutralisation à l'entrée des sondes Blind SSRF / RCE / XXE
    if (OAST_INBOUND_CALLBACK_REGEX.test(combinedInspectionSurface)) {
      const match = combinedInspectionSurface.match(OAST_INBOUND_CALLBACK_REGEX);
      return {
        threatType: 'OAST_BLIND_CALLBACK_INJECTION',
        severity: 'CRITICAL',
        riskScore: 98,
        pattern: `Domaine de callback OAST offensif détecté (${match ? match[0] : 'OAST'}) — Neutralisation Blind SSRF/RCE Anti-Artex`,
        httpStatus: 403
      };
    }

    // 3. API Discovery & Schema Lockdown (OpenAPI / Swagger / Actuator / GraphQL Introspection)
    if (API_SCHEMA_RECON_REGEX.test(canonicalTarget)) {
      const match = canonicalTarget.match(API_SCHEMA_RECON_REGEX);
      return {
        threatType: 'API_SCHEMA_RECON_BLOCKED',
        severity: 'HIGH',
        riskScore: 90,
        pattern: `Tentative de cartographie de schéma API ou d'introspection GraphQL bloquée (${match ? match[0] : 'API_SCHEMA'})`,
        httpStatus: 403
      };
    }

    // 4. Anti-Mass Assignment & Prototype Pollution
    if (MASS_ASSIGNMENT_REGEX.test(canonicalTarget)) {
      const match = canonicalTarget.match(MASS_ASSIGNMENT_REGEX);
      return {
        threatType: 'MASS_ASSIGNMENT_PRIVILEGE_ESCALATION',
        severity: 'CRITICAL',
        riskScore: 96,
        pattern: `Tentative d'élévation de privilèges par Mass Assignment ou Prototype Pollution (${match ? match[0] : 'MASS_ASSIGNMENT'})`,
        httpStatus: 403
      };
    }

    return null;
  }
}
