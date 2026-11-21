import type { IncomingHttpHeaders } from 'node:http';
import type { WafRuleRegistry } from '../rules/registry.js';
import { isExemptIp, type IIpReputationManager } from '../quarantine/ip-reputation.js';
import type { InspectionContext, WafVerdict } from '../types.js';
import { canonicalizeInput } from './canonicalizer.js';
import { computeRequestEntropy } from './entropy.js';

const MAX_TOTAL_HEADERS_BYTES = 8192; // 8 Ko (Verrou n°4 P1)
const MAX_SINGLE_HEADER_BYTES = 4096; // 4 Ko (Verrou n°4 P1)
const MAX_HEADER_COUNT = 64;

const STATIC_ASSET_EXT_REGEX = /\.(?:css|js|mjs|svg|png|jpg|jpeg|webp|gif|ico|woff2?|ttf)(?:\?|$)/i;
const DANGEROUS_MULTIPART_FILENAME_REGEX =
  /\bfilename\s*=\s*["']?[^"'\r\n]*\.(?:php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|sh|bash|cgi|pl|py|rb|exe|dll|bat|cmd|scr|war)(?:["'\s;]|$)/i;

export interface IWafInspector {
  inspect(
    url: string,
    method: string,
    headers: IncomingHttpHeaders,
    rawBody: string,
    byteLength: number,
    clientIp: string
  ): WafVerdict;
}

export class WafInspector implements IWafInspector {
  constructor(
    private readonly ruleRegistry: WafRuleRegistry,
    private readonly ipReputation: IIpReputationManager,
    private readonly getMaxPayloadBytes: () => number
  ) {}

  private isStaticAsset(url: string): boolean {
    if (!url) return false;
    return url.startsWith('/_astro/') || url === '/favicon.svg' || STATIC_ASSET_EXT_REGEX.test(url);
  }

  private inspectHeadersHardening(
    headers: IncomingHttpHeaders,
    entropy: number
  ): WafVerdict | null {
    const entries = Object.entries(headers || {});
    if (entries.length > MAX_HEADER_COUNT) {
      return {
        blocked: true,
        http_status: 431,
        decision: 'BLOCK',
        threat_type: 'HEADER_OVERFLOW_431 (Protocol Hardening)',
        severity: 'HIGH',
        risk_score: 94,
        entropy: Math.max(entropy, 4.2),
        pattern: `Nombre d'en-têtes HTTP excessif (${entries.length} > plafond ${MAX_HEADER_COUNT} — Verrou P1 HTTP 431)`
      };
    }

    let totalHeaderBytes = 0;
    for (const [key, val] of entries) {
      const valStr = Array.isArray(val) ? val.join(', ') : String(val ?? '');
      const entryBytes = Buffer.byteLength(key, 'utf8') + Buffer.byteLength(valStr, 'utf8');
      if (entryBytes > MAX_SINGLE_HEADER_BYTES) {
        return {
          blocked: true,
          http_status: 431,
          decision: 'BLOCK',
          threat_type: 'HEADER_OVERFLOW_431 (Protocol Hardening)',
          severity: 'HIGH',
          risk_score: 95,
          entropy: Math.max(entropy, 4.35),
          pattern: `En-tête HTTP '${key}' surdimensionné (${entryBytes} octets > plafond ${MAX_SINGLE_HEADER_BYTES} octets — Verrou P1 HTTP 431)`
        };
      }
      totalHeaderBytes += entryBytes;
    }

    if (totalHeaderBytes > MAX_TOTAL_HEADERS_BYTES) {
      return {
        blocked: true,
        http_status: 431,
        decision: 'BLOCK',
        threat_type: 'HEADER_OVERFLOW_431 (Protocol Hardening)',
        severity: 'HIGH',
        risk_score: 96,
        entropy: Math.max(entropy, 4.4),
        pattern: `Volume cumulé des en-têtes HTTP excessif (${totalHeaderBytes} octets > plafond ${MAX_TOTAL_HEADERS_BYTES} octets — Verrou P1 HTTP 431)`
      };
    }

    // Anti-Compression Bomb (chaînage d'encodages multiples)
    const contentEncoding = String(headers['content-encoding'] || '').toLowerCase();
    if (contentEncoding) {
      const encodings = contentEncoding
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);
      if (encodings.length > 1) {
        return {
          blocked: true,
          http_status: 403,
          decision: 'BLOCK',
          threat_type: 'COMPRESSION_BOMB_DETECTED',
          severity: 'CRITICAL',
          risk_score: 97,
          entropy: Math.max(entropy, 4.7),
          pattern: `Chaînage Content-Encoding suspect (${contentEncoding}) rejeté (Protection Anti-Bombe de Décompression Verrou P1)`
        };
      }
    }

    return null;
  }

  private inspectMultipartHardening(
    headers: IncomingHttpHeaders,
    rawBody: string,
    entropy: number
  ): WafVerdict | null {
    const contentType = String(headers['content-type'] || '');
    if (!/^multipart\/form-data/i.test(contentType)) {
      return null;
    }

    const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^\s;]+))/i);
    const boundary = boundaryMatch ? (boundaryMatch[1] || boundaryMatch[2] || '').trim() : '';

    if (!boundary || boundary.length < 1 || boundary.length > 70) {
      return {
        blocked: true,
        http_status: 403,
        decision: 'BLOCK',
        threat_type: 'MALFORMED_MULTIPART_RFC_VIOLATION',
        severity: 'HIGH',
        risk_score: 92,
        entropy,
        pattern: `Requête multipart/form-data non conforme RFC 2046 (boundary absente ou hors bornes 1..70 octets — Verrou P1)`
      };
    }

    if (rawBody) {
      const nestedMultiparts = (rawBody.match(/content-type\s*:\s*multipart\//gi) || []).length;
      if (nestedMultiparts > 3) {
        return {
          blocked: true,
          http_status: 403,
          decision: 'BLOCK',
          threat_type: 'MALFORMED_MULTIPART_RFC_VIOLATION',
          severity: 'CRITICAL',
          risk_score: 96,
          entropy: Math.max(entropy, 4.5),
          pattern: `Profondeur d'imbrication multipart excessive (${nestedMultiparts} > max 3 — Protection Parser DoS Verrou P1)`
        };
      }

      if (DANGEROUS_MULTIPART_FILENAME_REGEX.test(rawBody)) {
        return {
          blocked: true,
          http_status: 403,
          decision: 'BLOCK',
          threat_type: 'MALICIOUS_UPLOAD_EXECUTABLE_EXTENSION',
          severity: 'CRITICAL',
          risk_score: 98,
          entropy: Math.max(entropy, 4.5),
          pattern: `Tentative d'upload d'exécutable ou webshell déguisé dans Content-Disposition (Verrou P1 Multipart Hardening)`
        };
      }
    }

    return null;
  }

  public inspect(
    url: string,
    method: string,
    headers: IncomingHttpHeaders,
    rawBody = '',
    byteLength = 0,
    clientIp = ''
  ): WafVerdict {
    const customExploitHeader =
      (headers['x-exploit-signature'] as string) || (headers['x-php-args'] as string) || '';
    const rawCombined = `${url || '/'} ${customExploitHeader} ${rawBody}`;
    const targetToScan = canonicalizeInput(rawCombined);
    const entropy = computeRequestEntropy(rawCombined);

    // Règle -1 : Liste Noire IP Dynamique & Quarantaine Auto-Jail (Verrou n°3 P1)
    if (clientIp && this.ipReputation.isBanned(clientIp)) {
      if (isExemptIp(clientIp)) {
        this.ipReputation.unban(clientIp);
      } else {
        return {
          blocked: true,
          http_status: 403,
          decision: 'BLOCK',
          threat_type: 'BANNED_IP_BLACKLIST',
          severity: 'CRITICAL',
          risk_score: 100,
          entropy,
          pattern: `Adresse IP source (${clientIp}) en quarantaine active ou sur liste noire Aegis SOC`
        };
      }
    }

    // Règle -0.8 : Limiteur Volumétrique à Fenêtre Glissante (60 req / 10 s -> HTTP 429)
    if (clientIp && !this.isStaticAsset(url) && this.ipReputation.checkRateLimit) {
      const rateCheck = this.ipReputation.checkRateLimit(clientIp);
      if (rateCheck.limited) {
        return {
          blocked: true,
          http_status: 429,
          decision: 'BLOCK',
          threat_type: 'RATE_LIMIT_EXCEEDED_429',
          severity: 'HIGH',
          risk_score: 88,
          entropy,
          pattern: `Dépassement de débit volumétrique (${rateCheck.count} req / ${rateCheck.windowMs / 1000}s > plafond ${rateCheck.limit} req — Verrou P1 Anti-Fuzzing)`
        };
      }
    }

    // Règle -0.7 : Détection d'énumération séquentielle Anti-BOLA / IDOR (Verrou n°5-Bis v1.3 « Anti-Artex »)
    if (clientIp && !this.isStaticAsset(url) && this.ipReputation.checkBolaEnumeration) {
      const bolaCheck = this.ipReputation.checkBolaEnumeration(clientIp, url);
      if (bolaCheck.enumerated) {
        if (this.ipReputation.recordOffense) {
          this.ipReputation.recordOffense(clientIp, 94, 'API_BOLA_IDOR_ENUMERATION');
        }
        return {
          blocked: true,
          http_status: 403,
          decision: 'BLOCK',
          threat_type: 'API_BOLA_IDOR_ENUMERATION',
          severity: 'HIGH',
          risk_score: 94,
          entropy,
          pattern: `Énumération séquentielle BOLA/IDOR détectée sur '${bolaCheck.routeTemplate}' (${bolaCheck.distinctIdsCount} identifiants distincts > plafond ${bolaCheck.limit} / 60s — Bouclier Anti-Artex v1.3)`
        };
      }
    }

    // Règle -0.5 : Durcissement Protocole HTTP 431 & Anti-Compression Bomb (Verrou n°4 P1)
    const headerVerdict = this.inspectHeadersHardening(headers, entropy);
    if (headerVerdict) {
      if (clientIp && this.ipReputation.recordOffense) {
        this.ipReputation.recordOffense(clientIp, headerVerdict.risk_score, headerVerdict.threat_type);
      }
      return headerVerdict;
    }

    // Règle 0 : Protection Volumétrique / Buffer & Heap Overflow (413 Payload Too Large)
    const declaredLength = parseInt((headers['content-length'] as string) || '0', 10);
    const maxPayloadBytes = this.getMaxPayloadBytes();
    if (byteLength > maxPayloadBytes || declaredLength > maxPayloadBytes) {
      const overflowVerdict: WafVerdict = {
        blocked: true,
        http_status: 413,
        decision: 'BLOCK',
        threat_type: 'OVERFLOW_PAYLOAD_413 (Virtual Patch)',
        severity: 'CRITICAL',
        risk_score: 99,
        entropy: Math.max(entropy, 4.75),
        pattern: `Payload volumétrique rejeté à l'Edge (${Math.max(byteLength, declaredLength)} octets > limite ${maxPayloadBytes} octets — Protection Buffer/Heap Overflow & PHP2Shell)`
      };
      if (clientIp && this.ipReputation.recordOffense) {
        this.ipReputation.recordOffense(clientIp, overflowVerdict.risk_score, overflowVerdict.threat_type);
      }
      return overflowVerdict;
    }

    // Règle 0.5 : Validation Multipart RFC 2046 & Anti-Webshell Upload (Verrou n°4 P1)
    const multipartVerdict = this.inspectMultipartHardening(headers, rawBody, entropy);
    if (multipartVerdict) {
      if (clientIp && this.ipReputation.recordOffense) {
        this.ipReputation.recordOffense(
          clientIp,
          multipartVerdict.risk_score,
          multipartVerdict.threat_type
        );
      }
      return multipartVerdict;
    }

    const ctx: InspectionContext = {
      url,
      method,
      headers,
      rawBody,
      byteLength,
      clientIp
    };

    // Évaluation des règles modulaires dans l'ordre de priorité
    for (const rule of this.ruleRegistry.getRules()) {
      const match = rule.evaluate(ctx, targetToScan);
      if (match) {
        let finalEntropy = entropy;
        if (match.threatType === 'ZERO_DAY_VIRTUAL_PATCH') {
          finalEntropy = Math.max(entropy, 4.65);
        }
        const ruleVerdict: WafVerdict = {
          blocked: true,
          http_status: match.httpStatus || 403,
          decision: 'BLOCK',
          threat_type: match.threatType,
          severity: match.severity,
          risk_score: match.riskScore,
          entropy: finalEntropy,
          pattern: match.pattern
        };
        if (clientIp && this.ipReputation.recordOffense) {
          this.ipReputation.recordOffense(clientIp, ruleVerdict.risk_score, ruleVerdict.threat_type);
        }
        return ruleVerdict;
      }
    }

    // Requête saine
    return {
      blocked: false,
      http_status: 200,
      decision: 'ALLOW',
      threat_type: 'CLEAN_TRAFFIC',
      severity: 'COMPLIANT',
      risk_score: 5,
      entropy,
      pattern: 'Conforme aux politiques Zero-Trust Aegis Gate'
    };
  }
}
