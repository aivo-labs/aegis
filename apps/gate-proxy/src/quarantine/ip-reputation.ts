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

export interface BolaEnumerationResult {
  enumerated: boolean;
  distinctIdsCount: number;
  limit: number;
  routeTemplate?: string;
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
  checkBolaEnumeration?(ip: string, url: string, now?: number): BolaEnumerationResult;
  getOffenseCount?(ip: string, now?: number): number;
  getTarpitDelayMs?(ip: string, now?: number): number;
  getQuarantineEntries?(): QuarantineEntry[];
}

const BASE_EXEMPT_IPS = new Set(['127.0.0.1', '::1', 'localhost']);
const DOCKER_BRIDGE_GATEWAY_REGEX = /^172\.(?:1[6-9]|2\d|3[01])\.\d+\.1$/;
const NUMERIC_ID_SEGMENT_REGEX = /^\d+$/;
const UUID_SEGMENT_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Vérifie si une IP est exemptée d'Auto-Jail et de Rate-Limiting global :
 * - Loopback & IPs administrateur SOC configurées via AEGIS_ADMIN_IPS / AEGIS_EXEMPT_IPS (jamais codées en dur)
 * - Passerelles de bridge Docker (ex: 172.17.0.1, 172.18.0.1) utilisées lors du NAT IPv6->IPv4,
 *   afin d'éviter qu'un attaquant passant par la passerelle ne bloque l'ensemble du bridge.
 * Note : Les payloads malveillants restent systématiquement bloqués (HTTP 403) par l'inspecteur WAF.
 */
export function isExemptIp(ip: string): boolean {
  const cleanIp = (ip || '').trim();
  if (!cleanIp) return true;
  if (BASE_EXEMPT_IPS.has(cleanIp)) return true;
  if (DOCKER_BRIDGE_GATEWAY_REGEX.test(cleanIp)) return true;
  const envAdmins = [process.env.AEGIS_ADMIN_IPS, process.env.AEGIS_EXEMPT_IPS].filter(Boolean).join(',');
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
  private readonly bolaWindows = new Map<string, Array<{ objectId: string; ts: number }>>();

  private readonly rateLimitMaxReq: number;
  private readonly rateLimitWindowMs: number;
  private readonly autoJailThreshold: number;
  private readonly autoJailOffenseWindowMs: number;
  private readonly autoJailDurationMs: number;
  private readonly bolaMaxDistinctIds: number;
  private readonly bolaWindowMs: number;

  constructor(options?: {
    rateLimitMaxReq?: number;
    rateLimitWindowMs?: number;
    autoJailThreshold?: number;
    autoJailOffenseWindowMs?: number;
    autoJailDurationMs?: number;
    bolaMaxDistinctIds?: number;
    bolaWindowMs?: number;
  }) {
    this.rateLimitMaxReq = options?.rateLimitMaxReq ?? 60;
    this.rateLimitWindowMs = options?.rateLimitWindowMs ?? 10_000; // 10s
    this.autoJailThreshold = options?.autoJailThreshold ?? 3;
    this.autoJailOffenseWindowMs = options?.autoJailOffenseWindowMs ?? 5 * 60 * 1000; // 5 min
    this.autoJailDurationMs = options?.autoJailDurationMs ?? 15 * 60 * 1000; // 15 min
    this.bolaMaxDistinctIds = options?.bolaMaxDistinctIds ?? 10;
    this.bolaWindowMs = options?.bolaWindowMs ?? 60_000; // 60s
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

  /**
   * Retourne le nombre d'infractions critiques actives dans la fenêtre courante pour une IP.
   */
  public getOffenseCount(ip: string, now = Date.now()): number {
    const cleanIp = (ip || '').trim();
    if (!cleanIp) return 0;
    const cutoff = now - this.autoJailOffenseWindowMs;
    const prevOffenses = this.offenseWindows.get(cleanIp) || [];
    return prevOffenses.filter(ts => ts > cutoff).length;
  }

  /**
   * Verrou n°5-Bis (v1.3 « Anti-Artex ») : Calcul du délai Tarpit adaptatif (3s -> 10s -> 25s)
   * pour épuiser les boucles synchrones et budgets de timeouts des Agent Workers IA offensifs.
   */
  public getTarpitDelayMs(ip: string, now = Date.now()): number {
    const cleanIp = (ip || '').trim();
    if (!cleanIp || isExemptIp(cleanIp)) return 0;
    const offenses = this.getOffenseCount(cleanIp, now);
    if (offenses <= 0) return 0;
    if (offenses === 1) return 3_000;
    if (offenses === 2) return 10_000;
    return 25_000;
  }

  /**
   * Verrou n°5-Bis (v1.3 « Anti-Artex ») : Détecteur d'énumération séquentielle BOLA / IDOR.
   * Identifie lorsqu'un client interroge plus de N identifiants d'objets distincts (numériques ou UUID)
   * sur une même route d'API paramétrée (ex: /api/v1/invoices/{id}) en moins de 60 secondes.
   */
  public checkBolaEnumeration(ip: string, url: string, now = Date.now()): BolaEnumerationResult {
    const cleanIp = (ip || '').trim();
    if (!cleanIp || !url) {
      return { enumerated: false, distinctIdsCount: 0, limit: this.bolaMaxDistinctIds };
    }

    const pathname = url.split('?')[0] || '/';
    // Exclure les routes internes de télémétrie/polling Aegis Cockpit
    if (
      pathname.startsWith('/api/v1/dashboard/') ||
      pathname.startsWith('/api/v1/gate/') ||
      pathname.startsWith('/api/v1/audit/') ||
      pathname.startsWith('/api/v1/cve/') ||
      pathname.startsWith('/api/auth/') ||
      pathname.startsWith('/_aegis/') ||
      pathname.startsWith('/_astro/')
    ) {
      return { enumerated: false, distinctIdsCount: 0, limit: this.bolaMaxDistinctIds };
    }

    const segments = pathname.split('/').filter(Boolean);
    if (segments.length < 2) {
      return { enumerated: false, distinctIdsCount: 0, limit: this.bolaMaxDistinctIds };
    }

    let extractedObjectId: string | null = null;
    const templateSegments = segments.map(seg => {
      if (NUMERIC_ID_SEGMENT_REGEX.test(seg) || UUID_SEGMENT_REGEX.test(seg)) {
        extractedObjectId = seg.toLowerCase();
        return '{id}';
      }
      return seg;
    });

    if (!extractedObjectId) {
      return { enumerated: false, distinctIdsCount: 0, limit: this.bolaMaxDistinctIds };
    }

    const routeTemplate = `/${templateSegments.join('/')}`;
    const key = `${cleanIp}::${routeTemplate}`;
    const cutoff = now - this.bolaWindowMs;

    const existing = (this.bolaWindows.get(key) || []).filter(entry => entry.ts > cutoff);
    existing.push({ objectId: extractedObjectId, ts: now });
    this.bolaWindows.set(key, existing);

    const distinctIds = new Set(existing.map(e => e.objectId));
    const distinctIdsCount = distinctIds.size;
    const enumerated = distinctIdsCount > this.bolaMaxDistinctIds;

    return {
      enumerated,
      distinctIdsCount,
      limit: this.bolaMaxDistinctIds,
      routeTemplate
    };
  }
}

