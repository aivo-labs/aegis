/**
 * Verrou n°3 (P1) : Rate-Limiting Volumétrique à Fenêtre Glissante (60 req / 10 s -> HTTP 429)
 * & Quarantaine IP Automatique (Auto-Jail : 3 alertes critiques en < 5 min -> ban 15 min)
 */

export interface QuarantineEntry {
  ip: string;
  reason: string;
  source: 'MANUAL_SOC' | 'AUTO_JAIL_WAF';
  riskScore: number;
  createdAt: number;
  expiresAt: number | null; // null = permanent
  blockedHits: number;
}

export interface RateLimitResult {
  limited: boolean;
  count: number;
  limit: number;
  windowMs: number;
  retryAfterSec: number;
}

export interface AutoJailResult {
  autoJailed: boolean;
  offensesCount: number;
  expiresAt?: string;
  reason?: string;
}

export interface IIpReputationManager {
  isBanned(ip: string): boolean;
  ban(ip: string, ttlMs?: number | null, reason?: string, source?: 'MANUAL_SOC' | 'AUTO_JAIL_WAF'): void;
  unban(ip: string): void;
  clear(): void;
  getAll(): string[];
  setAll(ips: string[]): void;
  size(): number;
  checkRateLimit?(ip: string, now?: number): RateLimitResult;
  recordOffense?(ip: string, riskScore: number, threatType?: string, now?: number): AutoJailResult;
  getQuarantineEntries?(): QuarantineEntry[];
}

const BASE_EXEMPT_IPS = new Set(['127.0.0.1', '::1', 'localhost', '92.157.163.164']);
const DOCKER_BRIDGE_GATEWAY_REGEX = /^172\.(?:1[6-9]|2\d|3[01])\.\d+\.1$/;

/**
 * Vérifie si une IP est exemptée d'Auto-Jail et de Rate-Limiting global :
 * - Loopback & IP administrateur SOC (92.157.163.164 + AEGIS_ADMIN_IPS)
 * - Passerelles de bridge Docker (ex: 172.17.0.1, 172.18.0.1) utilisées lors du NAT IPv6->IPv4,
 *   afin d'éviter qu'un attaquant passant par la passerelle ne bloque l'ensemble du bridge.
 * Note : Les payloads malveillants restent systématiquement bloqués (HTTP 403) par l'inspecteur WAF.
 */
export function isExemptIp(ip: string): boolean {
  const cleanIp = (ip || '').trim();
  if (!cleanIp) return true;
  if (BASE_EXEMPT_IPS.has(cleanIp)) return true;
  if (DOCKER_BRIDGE_GATEWAY_REGEX.test(cleanIp)) return true;
  const envAdmins = process.env.AEGIS_ADMIN_IPS;
  if (envAdmins) {
    for (const entry of envAdmins.split(',')) {
      if (entry.trim() === cleanIp) return true;
    }
  }
  return false;
}

export class IpReputationManager implements IIpReputationManager {
  private readonly bannedEntries = new Map<string, QuarantineEntry>();
  private readonly rateWindows = new Map<string, number[]>();
  private readonly offenseWindows = new Map<string, number[]>();

  private readonly rateLimitMaxReq: number;
  private readonly rateLimitWindowMs: number;
  private readonly autoJailThreshold: number;
  private readonly autoJailOffenseWindowMs: number;
  private readonly autoJailDurationMs: number;

  constructor(options?: {
    rateLimitMaxReq?: number;
    rateLimitWindowMs?: number;
    autoJailThreshold?: number;
    autoJailOffenseWindowMs?: number;
    autoJailDurationMs?: number;
  }) {
    this.rateLimitMaxReq = options?.rateLimitMaxReq ?? 60;
    this.rateLimitWindowMs = options?.rateLimitWindowMs ?? 10_000; // 10s
    this.autoJailThreshold = options?.autoJailThreshold ?? 3;
    this.autoJailOffenseWindowMs = options?.autoJailOffenseWindowMs ?? 5 * 60 * 1000; // 5 min
    this.autoJailDurationMs = options?.autoJailDurationMs ?? 15 * 60 * 1000; // 15 min
  }

  private purgeExpired(now = Date.now()): void {
    for (const [ip, entry] of this.bannedEntries.entries()) {
      if (entry.expiresAt !== null && entry.expiresAt <= now) {
        this.bannedEntries.delete(ip);
      }
    }
  }

  public isBanned(ip: string): boolean {
    if (!ip) return false;
    const cleanIp = ip.trim();
    const entry = this.bannedEntries.get(cleanIp);
    if (!entry) return false;

    if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
      this.bannedEntries.delete(cleanIp);
      return false;
    }

    entry.blockedHits += 1;
    return true;
  }

  public ban(
    ip: string,
    ttlMs: number | null = null,
    reason = 'Bannissement SOC / Liste Noire Active',
    source: 'MANUAL_SOC' | 'AUTO_JAIL_WAF' = 'MANUAL_SOC'
  ): void {
    if (!ip || typeof ip !== 'string') return;
    const cleanIp = ip.trim();
    if (!cleanIp) return;

    const now = Date.now();
    const existing = this.bannedEntries.get(cleanIp);
    this.bannedEntries.set(cleanIp, {
      ip: cleanIp,
      reason,
      source,
      riskScore: source === 'AUTO_JAIL_WAF' ? 98 : 95,
      createdAt: existing?.createdAt ?? now,
      expiresAt: ttlMs && ttlMs > 0 ? now + ttlMs : null,
      blockedHits: existing?.blockedHits ?? 0
    });
  }

  public unban(ip: string): void {
    if (!ip) return;
    const cleanIp = ip.trim();
    this.bannedEntries.delete(cleanIp);
    this.offenseWindows.delete(cleanIp);
    this.rateWindows.delete(cleanIp);
  }

  public clear(): void {
    this.bannedEntries.clear();
    this.offenseWindows.clear();
    this.rateWindows.clear();
  }

  public getAll(): string[] {
    this.purgeExpired();
    return Array.from(this.bannedEntries.keys());
  }

  public getQuarantineEntries(): QuarantineEntry[] {
    this.purgeExpired();
    return Array.from(this.bannedEntries.values());
  }

  public setAll(ips: string[]): void {
    // Préserver les entrées AUTO_JAIL_WAF locales non expirées tout en synchronisant la liste SOC
    const now = Date.now();
    const preservedAutoJails = new Map<string, QuarantineEntry>();
    for (const [ip, entry] of this.bannedEntries.entries()) {
      if (entry.source === 'AUTO_JAIL_WAF' && (entry.expiresAt === null || entry.expiresAt > now)) {
        preservedAutoJails.set(ip, entry);
      }
    }

    this.bannedEntries.clear();
    for (const [ip, entry] of preservedAutoJails.entries()) {
      this.bannedEntries.set(ip, entry);
    }
    for (const ip of ips) {
      if (!this.bannedEntries.has(ip.trim())) {
        this.ban(ip, null, 'Bannissement SOC persistant', 'MANUAL_SOC');
      }
    }
  }

  public size(): number {
    this.purgeExpired();
    return this.bannedEntries.size;
  }

  /**
   * Limiteur volumétrique à fenêtre glissante (60 req / 10 s par IP)
   */
  public checkRateLimit(ip: string, now = Date.now()): RateLimitResult {
    const cleanIp = (ip || '').trim();
    if (!cleanIp || isExemptIp(cleanIp)) {
      return {
        limited: false,
        count: 1,
        limit: this.rateLimitMaxReq,
        windowMs: this.rateLimitWindowMs,
        retryAfterSec: 0
      };
    }

    const cutoff = now - this.rateLimitWindowMs;
    const prevTimestamps = this.rateWindows.get(cleanIp) || [];
    const activeTimestamps = prevTimestamps.filter(ts => ts > cutoff);
    activeTimestamps.push(now);
    this.rateWindows.set(cleanIp, activeTimestamps);

    const limited = activeTimestamps.length > this.rateLimitMaxReq;
    return {
      limited,
      count: activeTimestamps.length,
      limit: this.rateLimitMaxReq,
      windowMs: this.rateLimitWindowMs,
      retryAfterSec: limited ? Math.ceil(this.rateLimitWindowMs / 1000) : 0
    };
  }

  /**
   * Auto-Jail : 3 alertes critiques (risk_score >= 90) en < 5 minutes -> Quarantaine 15 minutes
   */
  public recordOffense(
    ip: string,
    riskScore: number,
    threatType = 'WAF_CRITICAL_OFFENSE',
    now = Date.now()
  ): AutoJailResult {
    const cleanIp = (ip || '').trim();
    if (!cleanIp || isExemptIp(cleanIp) || riskScore < 90) {
      return { autoJailed: false, offensesCount: 0 };
    }

    const cutoff = now - this.autoJailOffenseWindowMs;
    const prevOffenses = this.offenseWindows.get(cleanIp) || [];
    const activeOffenses = prevOffenses.filter(ts => ts > cutoff);
    activeOffenses.push(now);
    this.offenseWindows.set(cleanIp, activeOffenses);

    if (activeOffenses.length >= this.autoJailThreshold) {
      const reason = `Auto-Jail WAF (15 min) : ${activeOffenses.length} alertes critiques en < 5 min (Dernière : ${threatType})`;
      this.ban(cleanIp, this.autoJailDurationMs, reason, 'AUTO_JAIL_WAF');
      const expiresAtIso = new Date(now + this.autoJailDurationMs).toISOString();
      return {
        autoJailed: true,
        offensesCount: activeOffenses.length,
        expiresAt: expiresAtIso,
        reason
      };
    }

    return {
      autoJailed: false,
      offensesCount: activeOffenses.length
    };
  }
}
