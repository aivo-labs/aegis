import http from 'node:http';
import crypto from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { IWafInspector } from './engine/inspector.js';
import { isExemptIp, type IIpReputationManager } from './quarantine/ip-reputation.js';
import type { ITelemetryReporter } from './telemetry/reporter.js';
import type { IProxyForwarder } from './proxy/forwarder.js';
import type { GateConfig } from './config.js';
import { BffAuthHandler } from './bff/auth-handler.js';
import { extractSessionFromRequest } from './bff/session.js';
import { renderCtfLandingHtml } from './ctf-page.js';

const STATIC_OR_ASSET_REGEX = /\.(?:css|js|mjs|svg|png|jpg|jpeg|webp|gif|ico|woff2?|ttf|map)(?:\?|$)/i;

const PRIVATE_PROXY_REGEX = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1$|fc00:|fd00:|fe80:)/i;
const MAX_M2M_BODY_BYTES = 1024 * 1024; // 1 Mo max pour l'ingestion M2M
const MAX_CONTROL_BODY_BYTES = 64 * 1024; // 64 Ko max pour /_aegis/mode
const MAX_CONCURRENT_TARPIT = 50; // Plafond anti-Auto-DoS Tarpit (VM e2-micro safe)

export function isTrustedProxyIp(ip: string): boolean {
  const clean = (ip || '').replace(/^::ffff:/, '').trim();
  if (!clean) return false;
  if (PRIVATE_PROXY_REGEX.test(clean)) return true;
  const extra = process.env.AEGIS_TRUSTED_PROXIES;
  if (extra) {
    for (const entry of extra.split(',')) {
      if (entry.trim() === clean) return true;
    }
  }
  return false;
}

/**
 * Résolution sécurisée de l'IP client (Anti-Spoofing X-Forwarded-For) :
 * - Si la connexion TCP directe ne provient pas d'un reverse-proxy de confiance (Caddy/Traefik/Docker),
 *   l'en-tête X-Forwarded-For est totalement ignoré.
 * - Si elle provient d'un proxy de confiance, on lit X-Forwarded-For de DROITE À GAUCHE pour retenir
 *   la dernière IP non-proxy (injectée par le reverse-proxy de bordure, non forgeable par le client).
 */
export function getClientIp(req: IncomingMessage): string {
  const remote = (req.socket?.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '').trim();
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && isTrustedProxyIp(remote)) {
    const hops = forwarded
      .split(',')
      .map(s => s.replace(/^::ffff:/, '').trim())
      .filter(Boolean);
    for (let i = hops.length - 1; i >= 0; i--) {
      if (!isTrustedProxyIp(hops[i])) {
        return hops[i];
      }
    }
    if (hops.length > 0) {
      return hops[hops.length - 1];
    }
  }
  return remote || '127.0.0.1';
}

function timingSafeTokenMatch(provided: string, expected: string): boolean {
  if (!provided || !expected) return false;
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function isAuthorizedControlRequest(req: IncomingMessage, config: GateConfig): boolean {
  const expectedToken = config.internalAdminToken || process.env.AEGIS_INTERNAL_TOKEN || '';
  const headerToken =
    (req.headers['x-aegis-internal-token'] as string) ||
    ((req.headers.authorization as string) || '').replace(/^Bearer\s+/i, '').trim();
  if (expectedToken && timingSafeTokenMatch(headerToken, expectedToken)) {
    return true;
  }
  // En mode CTF, seul le token interne M2M est autorisé pour /_aegis/mode et /_aegis/simulate
  if (process.env.AEGIS_CTF_MODE === 'true') {
    return false;
  }
  const clientIp = getClientIp(req);
  const userAgent = (req.headers['user-agent'] as string) || 'unknown';
  const session = extractSessionFromRequest(req.headers.cookie, config.sessionSecret, {
    userAgent,
    clientIp
  });
  return session?.role === 'admin' || session?.role === 'secops';
}

export const DECOY_CANARY_ENV_PAYLOAD = [
  '# PRODUCTION ENVIRONMENT CONFIGURATION',
  'APP_ENV=production',
  'AEGIS_API_KEY=ak_live_aegis_canary_9f8e7d6c5b4a3210',
  'AWS_SECRET_ACCESS_KEY=AEGIS_CANARY_TRAP_SECRET_KEY_8842',
  'DATABASE_PASSWORD=AEGIS_CANARY_TRAP_DB_PASS_9910'
].join('\n');

export interface GateServerState {
  protectionEnabled: boolean;
  maxPayloadBytes: number;
  stealthBlockMode?: boolean;
  tarpitEnabled?: boolean;
  tarpitMaxMs?: number;
  canaryHoneypotEnabled?: boolean;
}

export function createGateServer(
  config: GateConfig,
  inspector: IWafInspector,
  ipReputation: IIpReputationManager,
  telemetry: ITelemetryReporter,
  forwarder: IProxyForwarder,
  state: GateServerState,
  authHandler?: BffAuthHandler
): http.Server {
  let activeTarpitConnections = 0;

  const scheduleTarpitResponse = (res: ServerResponse, delayMs: number, sendFn: () => void) => {
    if (delayMs <= 0 || activeTarpitConnections >= MAX_CONCURRENT_TARPIT) {
      sendFn();
      return;
    }
    activeTarpitConnections++;
    let done = false;
    const finish = (executeSend: boolean) => {
      if (done) return;
      done = true;
      activeTarpitConnections = Math.max(0, activeTarpitConnections - 1);
      if (executeSend && !res.writableEnded) {
        sendFn();
      }
    };
    const timer = setTimeout(() => finish(true), delayMs);
    res.once('close', () => {
      clearTimeout(timer);
      finish(false);
    });
  };

  return http.createServer((req: IncomingMessage, res: ServerResponse) => {
    // 0. Interception du Token Handler Pure BFF (/api/auth/*)
    if (authHandler && authHandler.handleAuthRequest(req, res)) {
      return;
    }

    // Endpoint de santé interne Docker
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'healthy',
          service: 'aegis-gate-proxy',
          port: config.port,
          node_mode: config.nodeMode || 'control-plane',
          node_hostname: config.nodeHostname || undefined,
          protection_enabled: state.protectionEnabled,
          max_payload_bytes: state.maxPayloadBytes,
          banned_ips_count: ipReputation.size()
        })
      );
      return;
    }

    // Exemption M2M (Control Plane) : les rapports de télémétrie, d'enrôlement et de synchronisation Auto-Jail
    // envoyés par des nœuds Edge distants (ex: VM Google Cloud ctf.aegis.aivo.fr ou Oracle Cloud) contiennent
    // les URI/payloads d'attaques bloquées dans leur corps JSON et ne doivent jamais être auto-bloqués ni rate-limités.
    const isInternalM2mSync =
      req.headers['x-aegis-internal'] === 'PEP-Ingress' || Boolean(req.headers['x-aegis-node']);
    if (
      config.nodeMode !== 'edge' &&
      req.url &&
      (req.url.startsWith('/api/v1/gate/telemetry/') ||
        req.url.startsWith('/api/v1/agent/') ||
        req.url.startsWith('/api/v1/protection/status') ||
        (isInternalM2mSync && req.url.startsWith('/api/v1/dashboard/bans')))
    ) {
      const m2mChunks: Buffer[] = [];
      let m2mBytes = 0;
      let m2mOverflow = false;
      req.on('data', (chunk: Buffer) => {
        m2mBytes += chunk.length;
        if (m2mBytes > MAX_M2M_BODY_BYTES) {
          m2mOverflow = true;
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 413, error: 'M2M Payload Too Large' }));
          req.destroy();
          return;
        }
        m2mChunks.push(chunk);
      });
      req.on('end', () => {
        if (m2mOverflow) return;
        const buffered = Buffer.concat(m2mChunks);
        const clientIp = getClientIp(req);
        forwarder.forward(
          req,
          res,
          config.backendUrl,
          clientIp,
          state.protectionEnabled,
          buffered.length,
          buffered
        );
      });
      return;
    }

    // Endpoint de simulation de sondes bots / pentest (Ingress & Egress) pour le Cockpit SOC (Authentification requise)
    if (req.url === '/_aegis/simulate' && (req.method === 'POST' || req.method === 'GET' || req.method === 'OPTIONS')) {
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (!isAuthorizedControlRequest(req, config)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 401, error: 'Unauthorized — Admin session or internal token required' }));
        return;
      }

      // IP d'attaque simulée dédiée (RFC 5737 TEST-NET-2) pour ne jamais impacter l'IP de l'administrateur
      const simulatedIp = '198.51.100.77';

      // 1. Simulation des requêtes Ingress (Scanners, CMS, Exploits)
      const simulatedProbes = [
        { path: '/wp-login.php', method: 'GET', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap/1.5.11', threat: 'SCANNER' },
        { path: '/wp-content/plugins/revslider/temp/update_extract/revslider/db.php', method: 'GET', ua: 'nikto/2.1.6', threat: 'CMS_PROBE' },
        { path: '/xmlrpc.php', method: 'POST', ua: 'python-requests/2.31.0', threat: 'CMS_PROBE' },
        { path: '/.env', method: 'GET', ua: 'gobuster/3.5', threat: 'SENSITIVE_PROBE' },
        { path: '/phpmyadmin/index.php', method: 'GET', ua: 'zgrab/0.x', threat: 'CMS_PROBE' },
        { path: '/api/v1/search?q=1+UNION+SELECT+username,password+FROM+users--', method: 'GET', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap', threat: 'SQLI' }
      ];

      const hostHeader = ((req.headers['x-forwarded-host'] || req.headers.host || 'aegis.aivo.fr') as string).split(':')[0];
      const ingressResults: any[] = [];
      for (const p of simulatedProbes) {
        const headers = { 'user-agent': p.ua, host: hostHeader };
        const inspection = inspector.inspect(p.path, p.method, headers, '', 0, simulatedIp);
        const decision = state.protectionEnabled ? (inspection.decision || 'BLOCK') : 'BYPASS';
        const statusCode = decision === 'BLOCK' ? 403 : 200;
        const threatType = inspection.threat_type || p.threat;
        const severity = inspection.severity || 'CRITICAL';
        const entropy = inspection.entropy || 3.5;
        const riskScore = inspection.risk_score || 95;

        telemetry.send({
          tenant_id: config.tenantId,
          client_ip: simulatedIp,
          user_agent: p.ua,
          http_method: p.method,
          request_uri: p.path,
          decision,
          http_status_returned: statusCode,
          latency_ms: 0.8,
          threat_type: threatType,
          severity,
          risk_score: riskScore,
          entropy,
          matched_pattern: inspection.pattern,
          metadata: {
            simulated: true,
            pattern: inspection.pattern,
            threat_type: threatType,
            severity,
            risk_score: riskScore,
            entropy,
            host: hostHeader,
            domain: hostHeader,
            engine: 'Aegis Gate PEP (:8000)'
          }
        });

        ingressResults.push({
          uri: p.path,
          method: p.method,
          decision,
          status_code: statusCode,
          threat_type: threatType
        });
      }

      // 2. Simulation des requêtes Egress (DNS & Callbacks C2 Sortants)
      const simulatedEgress = [
        { fqdn: 'c2-beacon.random-domain.top', entropy: 4.85, threat: 'KNOWN_C2_INFRASTRUCTURE', conf: 0.98, lat: 1.2, isMalicious: true },
        { fqdn: 'revshell.xmrig-pool.xyz', entropy: 4.62, threat: 'REVERSE_SHELL_C2', conf: 0.95, lat: 0.9, isMalicious: true },
        { fqdn: 'data-tunnel.exfil-dns-payload.io', entropy: 4.92, threat: 'DNS_TUNNEL_EXFIL', conf: 0.99, lat: 1.1, isMalicious: true },
        { fqdn: 'api.github.com', entropy: 2.15, threat: 'CLEAN_EGRESS', conf: 0.05, lat: 3.2, isMalicious: false }
      ];

      const egressEndpoint = `${config.backendUrl}/api/v1/gate/telemetry/egress`;
      const egressPromises = simulatedEgress.map(async eg => {
        const action = eg.isMalicious
          ? (state.protectionEnabled ? 'BLOCK' : 'BYPASS')
          : 'ALLOW';

        const egressPayload = {
          tenant_id: config.tenantId,
          client_ip: simulatedIp,
          fqdn: eg.fqdn,
          domain_entropy: eg.entropy,
          action,
          threat_type: eg.threat,
          confidence: eg.conf,
          latency_ms: eg.lat,
          metadata: {
            simulated: true,
            sinkhole_ip: action === 'BLOCK' ? '0.0.0.0' : undefined,
            engine: eg.isMalicious
              ? (state.protectionEnabled ? 'Aegis System One DNS Sinkhole (:5053)' : '⚠️ Egress Désactivé (Fuite C2 Active)')
              : 'DNS Direct',
            host: hostHeader,
            domain: hostHeader
          }
        };

        try {
          await fetch(egressEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(egressPayload)
          });
        } catch {
          // Tolérance réseau
        }

        return {
          fqdn: eg.fqdn,
          action,
          threat_type: eg.threat,
          entropy: eg.entropy
        };
      });

      Promise.all(egressPromises).then(egressRes => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'success',
          protection_enabled: state.protectionEnabled,
          simulated_ingress_count: ingressResults.length,
          simulated_egress_count: egressRes.length,
          ingress_results: ingressResults,
          egress_results: egressRes
        }));
      }).catch(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'success',
          protection_enabled: state.protectionEnabled,
          simulated_ingress_count: ingressResults.length,
          ingress_results: ingressResults
        }));
      });
      return;
    }

    // Endpoint de vérification ForwardAuth pour Traefik / Dokploy (WAF en coupure sur les autres applications du VPS)
    if ((req.url || '').startsWith('/_aegis/verify')) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS');

      if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
      }

      const targetMethod = (req.headers['x-forwarded-method'] as string) || req.method || 'GET';
      const targetUri =
        (req.headers['x-forwarded-uri'] as string) ||
        (req.headers['x-original-uri'] as string) ||
        (req.headers['x-rewrite-url'] as string) ||
        (req.url || '/').replace(/^\/_aegis\/verify/, '') ||
        '/';
      const clientIp = getClientIp(req);
      const userAgent = (req.headers['user-agent'] as string) || 'unknown';
      const targetHost = (
        (req.headers['x-forwarded-host'] as string) ||
        (req.headers.host as string) ||
        'unknown'
      ).split(':')[0];

      // Immunité totale pour les flux d'authentification BFF OIDC (/api/auth/*) & ingestion M2M (nœuds Edge distants)
      const isInternalM2mHeader =
        req.headers['x-aegis-internal'] === 'PEP-Ingress' || Boolean(req.headers['x-aegis-node']);
      if (
        targetUri.startsWith('/api/auth/') ||
        targetUri.startsWith('/api/v1/gate/telemetry/') ||
        targetUri.startsWith('/api/v1/agent/') ||
        targetUri.startsWith('/api/v1/protection/status') ||
        (isInternalM2mHeader && targetUri.startsWith('/api/v1/dashboard/bans'))
      ) {
        res.writeHead(200, {
          'X-Aegis-Verified': 'auth-or-m2m-flow',
          'X-Aegis-Engine': 'Aegis Gate PEP',
          'X-Aegis-Client-IP': clientIp
        });
        res.end();
        return;
      }

      // Immunité d'accès pour l'administrateur SOC & passerelles Docker (unban préventif uniquement)
      const session = extractSessionFromRequest(req.headers.cookie, config.sessionSecret, {
        userAgent,
        clientIp
      });
      const isAdminSession = session?.role === 'admin' || session?.role === 'secops';
      const isImmuneIp = isExemptIp(clientIp);

      // Verrou n°5-Bis (v1.3 « Anti-Artex ») : Leurre Canary Honeypot (/.env.canary ou mode Canary actif)
      const isCanaryTrapEndpoint =
        targetUri === '/.env.canary' ||
        targetUri === '/.aegis-canary' ||
        (Boolean(state.canaryHoneypotEnabled || req.headers['x-aegis-canary-honeypot'] === 'true') &&
          targetUri === '/.env');
      if (isCanaryTrapEndpoint && state.protectionEnabled) {
        const eventId = `aegis-canary-${crypto.randomBytes(6).toString('hex')}`;
        telemetry.send({
          tenant_id: config.tenantId,
          client_ip: clientIp,
          user_agent: userAgent,
          http_method: targetMethod,
          request_uri: targetUri,
          decision: 'BLOCK',
          http_status_returned: 200,
          latency_ms: 0.5,
          threat_type: 'CANARY_HONEYPOT_TRAP_SERVED',
          severity: 'CRITICAL',
          risk_score: 96,
          entropy: 3.9,
          matched_pattern: `Piège Canary Honeypot servi sur ${targetUri} (Secrets leurres ak_live_aegis_canary_* armés contre ARTEX)`,
          metadata: {
            threat_type: 'CANARY_HONEYPOT_TRAP_SERVED',
            severity: 'CRITICAL',
            risk_score: 96,
            entropy: 3.9,
            pattern: `Piège Canary Honeypot servi sur ${targetUri}`,
            event_id: eventId,
            engine: 'Aegis Anti-Artex Deception Honeypot',
            host: targetHost,
            domain: targetHost
          }
        });
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'X-Aegis-Canary-Trap': 'armed',
          'X-Aegis-Event-ID': eventId
        });
        res.end(DECOY_CANARY_ENV_PAYLOAD);
        return;
      }

      const verdict = inspector.inspect(
        targetUri,
        targetMethod,
        req.headers,
        '',
        0,
        clientIp
      );

      if (verdict.threat_type === 'BANNED_IP_BLACKLIST' && (isAdminSession || isImmuneIp)) {
        ipReputation.unban(clientIp);
        fetch(`${config.backendUrl}/api/v1/dashboard/bans?ip=${encodeURIComponent(clientIp)}`, { method: 'DELETE' }).catch(() => {});
      } else if (verdict.blocked && state.protectionEnabled) {
        const statusCode = verdict.http_status || 403;
        const eventId = `aegis-fwd-${crypto.randomBytes(6).toString('hex')}`;

        // Si un agent autonome (ARTEX) rejoue un Canary Token, bannissement immédiat de 60 minutes
        if (verdict.threat_type === 'CANARY_TOKEN_TRIPWIRE_TRIGGERED' && !isImmuneIp) {
          ipReputation.ban(
            clientIp,
            60 * 60 * 1000,
            `Piège Canary Anti-Artex déclenché sur ${targetHost} (Chaînage autonome de secret leurre)`,
            'AUTO_JAIL_WAF'
          );
        }

        telemetry.send({
          tenant_id: config.tenantId,
          client_ip: clientIp,
          user_agent: userAgent,
          http_method: targetMethod,
          request_uri: targetUri,
          decision: verdict.decision,
          http_status_returned: statusCode,
          latency_ms: 0.4,
          threat_type: verdict.threat_type,
          severity: verdict.severity,
          risk_score: verdict.risk_score,
          entropy: verdict.entropy,
          matched_pattern: verdict.pattern,
          metadata: {
            threat_type: verdict.threat_type,
            severity: verdict.severity,
            risk_score: verdict.risk_score,
            entropy: verdict.entropy,
            pattern: verdict.pattern,
            event_id: eventId,
            engine: 'Traefik ForwardAuth PEP',
            host: targetHost,
            domain: targetHost
          }
        });

        // Si l'IP vient de passer en Auto-Jail suite à cette infraction critique, synchroniser avec le Control Plane
        if (verdict.threat_type !== 'BANNED_IP_BLACKLIST' && ipReputation.isBanned(clientIp)) {
          const isCanaryBan = verdict.threat_type === 'CANARY_TOKEN_TRIPWIRE_TRIGGERED';
          fetch(`${config.backendUrl}/api/v1/dashboard/bans`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Aegis-Internal': 'PEP-Ingress',
              'X-Aegis-Node': config.nodeHostname || targetHost
            },
            body: JSON.stringify({
              ip: clientIp,
              reason: isCanaryBan
                ? `Piège Canary Anti-Artex déclenché sur ${targetHost} (Chaînage autonome de secret leurre)`
                : `Auto-Jail WAF (15 min) suite à répétition d'alertes critiques sur ${targetHost} (${verdict.threat_type})`,
              source: 'AUTO_JAIL_WAF',
              risk_score: isCanaryBan ? 100 : 98,
              ttl_minutes: isCanaryBan ? 60 : 15
            })
          }).catch(() => {});
        }

        const isStealth = Boolean(
          state.stealthBlockMode ||
          process.env.AEGIS_STEALTH_BLOCK === 'true' ||
          req.headers['x-aegis-stealth'] === 'true'
        );
        const isTarpit = Boolean(
          state.tarpitEnabled ||
          process.env.AEGIS_TARPIT_ENABLED === 'true'
        );
        const rawTarpitDelay =
          isTarpit && ipReputation.getTarpitDelayMs ? ipReputation.getTarpitDelayMs(clientIp) : 0;
        const effectiveTarpitDelay =
          state.tarpitMaxMs !== undefined ? Math.min(rawTarpitDelay, state.tarpitMaxMs) : rawTarpitDelay;

        const externalThreatLabel = isStealth
          ? 'SECURITY_POLICY_VIOLATION'
          : (verdict.threat_type || 'SECURITY_THREAT');

        const blockHeaders: Record<string, string> = {
          'Content-Type': 'application/json',
          'X-Aegis-Decision': 'BLOCK',
          'X-Aegis-Threat': externalThreatLabel
        };
        if (statusCode === 429) {
          blockHeaders['Retry-After'] = '10';
        }
        if (rawTarpitDelay > 0) {
          blockHeaders['X-Aegis-Tarpit-Delay-Ms'] = String(rawTarpitDelay);
        }

        const sendFwdBlock = () => {
          res.writeHead(statusCode, blockHeaders);
          res.end(JSON.stringify({
            status: statusCode,
            error:
              statusCode === 413
                ? 'Payload Too Large — Blocked by Aegis Gate Virtual Patching'
                : statusCode === 429
                  ? 'Too Many Requests — Volumetric Sliding-Window Rate Limit Exceeded'
                  : statusCode === 431
                    ? 'Request Header Fields Too Large — Blocked by Aegis Protocol Hardening'
                    : 'Access Denied by Aegis Gate Zero-Trust PEP (Traefik ForwardAuth)',
            verdict: 'BLOCKED',
            threat_detected: externalThreatLabel,
            severity: isStealth ? 'RESTRICTED' : verdict.severity,
            risk_score: isStealth ? undefined : verdict.risk_score,
            client_ip: clientIp,
            target_uri: targetUri,
            event_id: eventId,
            tarpit_delay_ms: rawTarpitDelay > 0 ? rawTarpitDelay : undefined,
            security_standard: 'ANSSI NIS 2 Hardened • Virtual Patching Active'
          }));
        };

        if (effectiveTarpitDelay > 0) {
          scheduleTarpitResponse(res, effectiveTarpitDelay, sendFwdBlock);
        } else {
          sendFwdBlock();
        }
        return;
      }

      // CAS 1-BIS (ForwardAuth) : Attaque détectée mais bouclier désactivé -> journalisation BYPASS
      if (verdict.blocked && !state.protectionEnabled) {
        const eventId = `aegis-fwd-byp-${crypto.randomBytes(6).toString('hex')}`;
        telemetry.send({
          tenant_id: config.tenantId,
          client_ip: clientIp,
          user_agent: userAgent,
          http_method: targetMethod,
          request_uri: targetUri,
          decision: 'BYPASS',
          http_status_returned: 200,
          latency_ms: 0.4,
          threat_type: `${verdict.threat_type} [NON BLOQUÉ]`,
          severity: 'CRITICAL',
          risk_score: 100,
          entropy: verdict.entropy,
          matched_pattern: `⚠️ BOUCLIER DÉSACTIVÉ — Exploit transmis au serveur (${targetHost}) : ${verdict.pattern}`,
          metadata: {
            threat_type: `${verdict.threat_type} [NON BLOQUÉ]`,
            severity: 'CRITICAL',
            risk_score: 100,
            entropy: verdict.entropy,
            pattern: `⚠️ BOUCLIER DÉSACTIVÉ — Exploit transmis au serveur (${targetHost}) : ${verdict.pattern}`,
            event_id: eventId,
            host: targetHost,
            domain: targetHost,
            engine: '⚠️ Protection Désactivée (Traefik ForwardAuth)'
          }
        });
      } else {
        // CAS 2 (ForwardAuth) : Trafic conforme -> journalisation ALLOW (hors assets statiques & polling interne)
        const isStaticOrPoll =
          targetUri.startsWith('/_astro/') ||
          targetUri === '/favicon.ico' ||
          targetUri === '/favicon.svg' ||
          targetUri.startsWith('/api/v1/dashboard/') ||
          targetUri.startsWith('/_aegis/') ||
          STATIC_OR_ASSET_REGEX.test(targetUri);
        if (!isStaticOrPoll) {
          telemetry.send({
            tenant_id: config.tenantId,
            client_ip: clientIp,
            user_agent: userAgent,
            http_method: targetMethod,
            request_uri: targetUri,
            decision: 'ALLOW',
            http_status_returned: 200,
            latency_ms: 0.3,
            metadata: {
              threat_type: 'CLEAN_TRAFFIC',
              severity: 'COMPLIANT',
              risk_score: 5,
              entropy: verdict.entropy,
              host: targetHost,
              domain: targetHost,
              engine: 'Traefik ForwardAuth PEP'
            }
          });
        }
      }

      // Requête autorisée -> HTTP 200 avec headers transmis à l'application cible
      res.writeHead(200, {
        'X-Aegis-Verified': state.protectionEnabled ? 'true' : 'bypass-unprotected',
        'X-Aegis-Engine': 'Aegis Gate PEP',
        'X-Aegis-Client-IP': clientIp
      });
      res.end();
      return;
    }

    // Endpoint interne de contrôle du bouclier (Authentification Admin / Token interne obligatoire — Correctif P0)
    if (req.url === '/_aegis/mode') {
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (!isAuthorizedControlRequest(req, config)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 401,
            error: 'Unauthorized — Admin session or X-Aegis-Internal-Token required'
          })
        );
        return;
      }

      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 'success',
            protection_enabled: state.protectionEnabled,
            max_payload_bytes: state.maxPayloadBytes,
            stealth_block_mode: Boolean(state.stealthBlockMode),
            tarpit_enabled: Boolean(state.tarpitEnabled),
            canary_honeypot_enabled: Boolean(state.canaryHoneypotEnabled),
            banned_ips: ipReputation.getAll(),
            quarantine_entries: ipReputation.getQuarantineEntries
              ? ipReputation.getQuarantineEntries()
              : []
          })
        );
        return;
      }

      if (req.method === 'POST') {
        const chunks: Buffer[] = [];
        let controlBytes = 0;
        let controlOverflow = false;
        req.on('data', (c: Buffer) => {
          controlBytes += c.length;
          if (controlBytes > MAX_CONTROL_BODY_BYTES) {
            controlOverflow = true;
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'error', message: 'Control payload too large' }));
            req.destroy();
            return;
          }
          chunks.push(c);
        });
        req.on('end', () => {
          if (controlOverflow) return;
          try {
            const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
            if (typeof body.enabled === 'boolean') {
              state.protectionEnabled = body.enabled;
            } else if (typeof body.protection_enabled === 'boolean') {
              state.protectionEnabled = body.protection_enabled;
            }
            if (typeof body.max_payload_bytes === 'number' && body.max_payload_bytes >= 1024) {
              state.maxPayloadBytes = body.max_payload_bytes;
            }
            if (typeof body.stealth_block_mode === 'boolean') {
              state.stealthBlockMode = body.stealth_block_mode;
            }
            if (typeof body.tarpit_enabled === 'boolean') {
              state.tarpitEnabled = body.tarpit_enabled;
            }
            if (typeof body.canary_honeypot_enabled === 'boolean') {
              state.canaryHoneypotEnabled = body.canary_honeypot_enabled;
            }
            if (body.reset === true) {
              ipReputation.clear();
            } else if (Array.isArray(body.banned_ips)) {
              ipReputation.setAll(
                body.banned_ips.filter((ip: unknown) => typeof ip === 'string').map((ip: string) => ip.trim())
              );
            }
            console.log(
              `⚡ [Aegis Gate PEP] Mode: ${state.protectionEnabled ? '🛡️ ACTIF' : '⚠️ DÉSACTIVÉ'} | Seuil 413: ${state.maxPayloadBytes}B | Bans: ${ipReputation.size()}`
            );
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                status: 'success',
                protection_enabled: state.protectionEnabled,
                max_payload_bytes: state.maxPayloadBytes,
                stealth_block_mode: Boolean(state.stealthBlockMode),
                tarpit_enabled: Boolean(state.tarpitEnabled),
                canary_honeypot_enabled: Boolean(state.canaryHoneypotEnabled),
                banned_ips_count: ipReputation.size()
              })
            );
          } catch (e: unknown) {
            const err = e as Error;
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'error', message: err.message }));
          }
        });
        return;
      }
    }

    const startTime = performance.now();
    const clientIp = getClientIp(req);
    const userAgent = (req.headers['user-agent'] as string) || 'unknown';
    const declaredLength = parseInt((req.headers['content-length'] as string) || '0', 10);

    const bodyChunks: Buffer[] = [];
    let totalBytes = 0;
    let abortedForSize = false;

    if (declaredLength > state.maxPayloadBytes) {
      abortedForSize = true;
    }

    req.on('data', (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes <= state.maxPayloadBytes) {
        bodyChunks.push(chunk);
      } else {
        abortedForSize = true;
      }
    });

    req.on('end', () => {
      const rawBody = Buffer.concat(bodyChunks).toString('utf-8');
      const effectiveBytes = Math.max(totalBytes, declaredLength);
      const effectiveHost =
        config.nodeHostname ||
        ((req.headers['x-forwarded-host'] || req.headers.host || 'aegis.aivo.fr') as string).split(':')[0];

      // Verrou n°5-Bis (v1.3 « Anti-Artex ») : Leurre Canary Honeypot en mode Reverse-Proxy (/.env.canary)
      const reqPathname = (req.url || '/').split('?')[0];
      const isCanaryTrapEndpoint =
        reqPathname === '/.env.canary' ||
        reqPathname === '/.aegis-canary' ||
        (Boolean(state.canaryHoneypotEnabled || req.headers['x-aegis-canary-honeypot'] === 'true') &&
          reqPathname === '/.env');
      if (isCanaryTrapEndpoint && state.protectionEnabled) {
        const eventId = `aegis-canary-${crypto.randomBytes(6).toString('hex')}`;
        telemetry.send({
          tenant_id: config.tenantId,
          client_ip: clientIp,
          user_agent: userAgent,
          http_method: req.method || 'GET',
          request_uri: req.url || '/',
          decision: 'BLOCK',
          http_status_returned: 200,
          latency_ms: 0.5,
          threat_type: 'CANARY_HONEYPOT_TRAP_SERVED',
          severity: 'CRITICAL',
          risk_score: 96,
          entropy: 3.9,
          matched_pattern: `Piège Canary Honeypot servi sur ${reqPathname} (Secrets leurres ak_live_aegis_canary_* armés contre ARTEX)`,
          metadata: {
            threat_type: 'CANARY_HONEYPOT_TRAP_SERVED',
            severity: 'CRITICAL',
            risk_score: 96,
            entropy: 3.9,
            pattern: `Piège Canary Honeypot servi sur ${reqPathname}`,
            event_id: eventId,
            engine: 'Aegis Anti-Artex Deception Honeypot',
            host: effectiveHost,
            domain: effectiveHost
          }
        });
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'X-Aegis-Canary-Trap': 'armed',
          'X-Aegis-Event-ID': eventId
        });
        res.end(DECOY_CANARY_ENV_PAYLOAD);
        return;
      }

      const verdict = inspector.inspect(
        req.url || '/',
        req.method || 'GET',
        req.headers,
        rawBody,
        abortedForSize ? effectiveBytes : totalBytes,
        clientIp
      );
      const latency = Math.max(0.2, parseFloat((performance.now() - startTime).toFixed(2)));

      // Immunité d'accès pour l'Administrateur SOC Authentifié (Zero-Trust Identity > IP Heuristic)
      const session = extractSessionFromRequest(req.headers.cookie, config.sessionSecret, {
        userAgent,
        clientIp
      });
      const isAdminSession = session?.role === 'admin' || session?.role === 'secops';
      // En mode 'edge' (ex: VM Oracle Cloud), nous n'immunisons pas 127.0.0.1 afin que les scripts
      // de test locaux ou distants exécutés sur la VM soient réellement inspectés et bloqués par le WAF.
      const isImmuneIp =
        config.nodeMode === 'edge'
          ? false
          : isExemptIp(clientIp);
      const alreadyVerifiedByForwardAuth = Boolean(req.headers['x-aegis-verified']);

      if (verdict.threat_type === 'BANNED_IP_BLACKLIST' && (isAdminSession || isImmuneIp)) {
        ipReputation.unban(clientIp);
        // Débannissement automatique dans PostgreSQL / TimescaleDB
        fetch(`${config.backendUrl}/api/v1/dashboard/bans?ip=${encodeURIComponent(clientIp)}`, { method: 'DELETE' }).catch(() => {});
      } else if (verdict.blocked && state.protectionEnabled) {
        const statusCode = verdict.http_status || 403;
        const eventId = `aegis-blk-${crypto.randomBytes(6).toString('hex')}`;

        // Si un agent autonome (ARTEX) rejoue un Canary Token, bannissement immédiat de 60 minutes
        if (verdict.threat_type === 'CANARY_TOKEN_TRIPWIRE_TRIGGERED' && !isImmuneIp) {
          ipReputation.ban(
            clientIp,
            60 * 60 * 1000,
            `Piège Canary Anti-Artex déclenché sur ${effectiveHost} (Chaînage autonome de secret leurre)`,
            'AUTO_JAIL_WAF'
          );
        }

        telemetry.send({
          tenant_id: config.tenantId,
          client_ip: clientIp,
          user_agent: userAgent,
          http_method: req.method || 'GET',
          request_uri: req.url || '/',
          decision: verdict.decision,
          http_status_returned: statusCode,
          latency_ms: latency,
          threat_type: verdict.threat_type,
          severity: verdict.severity,
          risk_score: verdict.risk_score,
          entropy: verdict.entropy,
          matched_pattern: verdict.pattern,
          metadata: {
            threat_type: verdict.threat_type,
            severity: verdict.severity,
            risk_score: verdict.risk_score,
            entropy: verdict.entropy,
            pattern: verdict.pattern,
            payload_bytes: effectiveBytes,
            event_id: eventId,
            host: effectiveHost,
            node_hostname: config.nodeHostname || undefined,
            node_mode: config.nodeMode || 'control-plane',
            engine:
              statusCode === 413
                ? 'Aegis Gate PEP (Virtual Patching Volumétrique)'
                : 'Aegis Gate PEP (OWASP CRS & Zero-Day Shield)'
          }
        });

        // Si l'IP vient de passer en Auto-Jail suite à cette infraction critique, synchroniser avec le Control Plane
        if (verdict.threat_type !== 'BANNED_IP_BLACKLIST' && ipReputation.isBanned(clientIp)) {
          const isCanaryBan = verdict.threat_type === 'CANARY_TOKEN_TRIPWIRE_TRIGGERED';
          fetch(`${config.backendUrl}/api/v1/dashboard/bans`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Aegis-Internal': 'PEP-Ingress',
              'X-Aegis-Node': config.nodeHostname || effectiveHost
            },
            body: JSON.stringify({
              ip: clientIp,
              reason: isCanaryBan
                ? `Piège Canary Anti-Artex déclenché sur ${effectiveHost} (Chaînage autonome de secret leurre)`
                : `Auto-Jail WAF (15 min) suite à répétition d'alertes critiques sur ${effectiveHost} (${verdict.threat_type})`,
              source: 'AUTO_JAIL_WAF',
              risk_score: isCanaryBan ? 100 : 98,
              ttl_minutes: isCanaryBan ? 60 : 15
            })
          }).catch(() => {});
        }

        const isStealth = Boolean(
          state.stealthBlockMode ||
          process.env.AEGIS_STEALTH_BLOCK === 'true' ||
          req.headers['x-aegis-stealth'] === 'true'
        );
        const isTarpit = Boolean(
          state.tarpitEnabled ||
          process.env.AEGIS_TARPIT_ENABLED === 'true'
        );
        const rawTarpitDelay =
          isTarpit && ipReputation.getTarpitDelayMs ? ipReputation.getTarpitDelayMs(clientIp) : 0;
        const effectiveTarpitDelay =
          state.tarpitMaxMs !== undefined ? Math.min(rawTarpitDelay, state.tarpitMaxMs) : rawTarpitDelay;

        const externalThreatLabel = isStealth
          ? 'SECURITY_POLICY_VIOLATION'
          : verdict.threat_type;

        const responsePayload = JSON.stringify(
          {
            status: statusCode,
            error:
              statusCode === 413
                ? 'Payload Too Large — Blocked by Aegis Gate Virtual Patching'
                : statusCode === 429
                  ? 'Too Many Requests — Volumetric Sliding-Window Rate Limit Exceeded'
                  : statusCode === 431
                    ? 'Request Header Fields Too Large — Blocked by Aegis Protocol Hardening'
                    : 'Access Denied by Aegis Gate Zero-Trust PEP',
            verdict: 'BLOCKED',
            threat_detected: externalThreatLabel,
            severity: isStealth ? 'RESTRICTED' : verdict.severity,
            risk_score: isStealth ? undefined : verdict.risk_score,
            details: isStealth
              ? 'Opaque Zero-Trust Block (Anti-LLM Oracle Protection Active)'
              : verdict.pattern,
            client_ip: clientIp,
            node_hostname: config.nodeHostname || effectiveHost,
            latency_ms: latency,
            tarpit_delay_ms: rawTarpitDelay > 0 ? rawTarpitDelay : undefined,
            timestamp: new Date().toISOString(),
            event_id: eventId,
            security_standard: 'ANSSI NIS 2 Hardened • Virtual Patching Active'
          },
          null,
          2
        );

        const blockHeaders: Record<string, string> = {
          'Content-Type': 'application/json',
          'X-Aegis-Verdict': 'BLOCKED',
          'X-Aegis-Threat': externalThreatLabel,
          'X-Aegis-Event-ID': eventId,
          'X-Aegis-Node': config.nodeHostname || effectiveHost,
          'X-Content-Type-Options': 'nosniff',
          'Access-Control-Allow-Origin': '*'
        };
        if (statusCode === 429) {
          blockHeaders['Retry-After'] = '10';
        }
        if (rawTarpitDelay > 0) {
          blockHeaders['X-Aegis-Tarpit-Delay-Ms'] = String(rawTarpitDelay);
        }

        const sendProxyBlock = () => {
          res.writeHead(statusCode, blockHeaders);
          res.end(responsePayload);
        };

        if (effectiveTarpitDelay > 0) {
          scheduleTarpitResponse(res, effectiveTarpitDelay, sendProxyBlock);
        } else {
          sendProxyBlock();
        }
        return;
      }

      // CAS 1-BIS : ATTAQUE DÉTECTÉE MAIS BOUCLIER DÉSACTIVÉ -> LAISSE PASSER VERS LA CIBLE
      if (verdict.blocked && !state.protectionEnabled) {
        if (!alreadyVerifiedByForwardAuth || effectiveBytes > 0) {
          const eventId = `aegis-byp-${crypto.randomBytes(6).toString('hex')}`;
          telemetry.send({
            tenant_id: config.tenantId,
            client_ip: clientIp,
            user_agent: userAgent,
            http_method: req.method || 'GET',
            request_uri: req.url || '/',
            decision: 'BYPASS',
            http_status_returned: 200,
            latency_ms: latency,
            threat_type: `${verdict.threat_type} [NON BLOQUÉ]`,
            severity: 'CRITICAL',
            risk_score: 100,
            entropy: verdict.entropy,
            matched_pattern: `⚠️ BOUCLIER DÉSACTIVÉ — Exploit transmis au serveur : ${verdict.pattern}`,
            metadata: {
              threat_type: `${verdict.threat_type} [NON BLOQUÉ]`,
              severity: 'CRITICAL',
              risk_score: 100,
              entropy: verdict.entropy,
              pattern: `⚠️ BOUCLIER DÉSACTIVÉ — Exploit transmis au serveur : ${verdict.pattern}`,
              payload_bytes: effectiveBytes,
              event_id: eventId,
              host: effectiveHost,
              node_hostname: config.nodeHostname || undefined,
              node_mode: config.nodeMode || 'control-plane',
              engine: '⚠️ Protection Désactivée (Serveur Exposé)'
            }
          });
        }
      } else if (!alreadyVerifiedByForwardAuth) {
        // CAS 2 : TRAFIC CONFORME -> JOURNALISATION (hors assets statiques, polling interne & requêtes déjà journalisées par ForwardAuth)
        const isStaticOrPoll =
          (req.url || '').startsWith('/_astro/') ||
          req.url === '/favicon.ico' ||
          req.url === '/favicon.svg' ||
          (req.url || '').startsWith('/api/v1/dashboard/') ||
          STATIC_OR_ASSET_REGEX.test(req.url || '');
        if (!isStaticOrPoll) {
          telemetry.send({
            tenant_id: config.tenantId,
            client_ip: clientIp,
            user_agent: userAgent,
            http_method: req.method || 'GET',
            request_uri: req.url || '/',
            decision: 'ALLOW',
            http_status_returned: 200,
            latency_ms: latency,
            metadata: {
              threat_type: 'CLEAN_TRAFFIC',
              severity: 'COMPLIANT',
              risk_score: 5,
              entropy: verdict.entropy,
              host: effectiveHost,
              node_hostname: config.nodeHostname || undefined,
              node_mode: config.nodeMode || 'control-plane',
              engine: 'Aegis Gate PEP'
            }
          });
        }
      }

      // Endpoint Cible CTF / Red Team Challenge (ctf.aegis.aivo.fr) — Placé APRÈS l'inspection WAF
      const isCtfEdgeArena =
        process.env.AEGIS_CTF_MODE === 'true' ||
        effectiveHost.toLowerCase().startsWith('ctf.') ||
        (config.nodeHostname || '').toLowerCase().startsWith('ctf.');

      if (
        reqPathname === '/ctf' ||
        reqPathname === '/api/v1/ctf/flag' ||
        reqPathname === '/api/v1/ctf/rules' ||
        (isCtfEdgeArena && reqPathname === '/')
      ) {
        const acceptHeader = String(req.headers.accept || '');
        const wantsHtml =
          (reqPathname === '/' || reqPathname === '/ctf') &&
          acceptHeader.includes('text/html') &&
          !acceptHeader.includes('application/json');

        if (wantsHtml) {
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'X-Aegis-CTF-Target': 'active',
            'X-Aegis-Node': config.nodeHostname || effectiveHost,
            'Cache-Control': 'no-store'
          });
          res.end(renderCtfLandingHtml(state.protectionEnabled, config.nodeHostname || effectiveHost));
          return;
        }

        const isCompromisedDemo = verdict.blocked && !state.protectionEnabled;
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Aegis-CTF-Target': 'active',
          'X-Aegis-Node': config.nodeHostname || effectiveHost,
          'Cache-Control': 'no-store'
        });
        res.end(
          JSON.stringify(
            {
              challenge: 'AEGIS v1.3 — Sovereign Anti-Artex Red Team Challenge (ctf.aegis.aivo.fr)',
              control_plane_cockpit: 'https://aegis.aivo.fr',
              node_hostname: config.nodeHostname || effectiveHost,
              shield_status: state.protectionEnabled ? 'ACTIVE_ZERO_TRUST' : 'DISABLED_BYPASS_DEMO',
              verdict_on_request: isCompromisedDemo ? 'EXPLOIT_BYPASSED_UNPROTECTED' : 'CLEAN_REQUEST_INSPECTED',
              flag: isCompromisedDemo
                ? 'AEGIS_CTF{SHIELD_DISABLED_DEMO_FLAG}'
                : '🔒 FLAG_LOCKED — Authenticate with a valid admin token or bypass Aegis Gate PEP v1.3 to unlock.',
              target_api_surface: [
                'GET /api/v1/ctf/flag',
                'GET /api/v1/invoices/{id}',
                'PATCH /api/v1/profile',
                'GET /v3/api-docs',
                'POST /graphql'
              ],
              debug_notice: 'Legacy configuration snapshot path: /.env.canary',
              rules_of_engagement: [
                'Target Scope: https://ctf.aegis.aivo.fr (Isolated Google Cloud VM connected to https://aegis.aivo.fr)',
                'Allowed: Autonomous AI pentest agents (ARTEX, Hexstrike, CyberStrikeAI, PentestGPT) & manual L7 WAF evasion',
                'Prohibited: Volumetric L3/L4 network DDoS against cloud provider infrastructure'
              ]
            },
            null,
            2
          )
        );
        return;
      }

      // En mode arène CTF autonome (sans conteneur web/backend local sur la VM GCP), réponses applicatives simulées post-WAF
      if (isCtfEdgeArena) {
        const invoiceOrUserMatch = reqPathname.match(/^\/api\/v1\/(invoices|users)\/([^/]+)$/i);
        if (invoiceOrUserMatch) {
          res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Aegis-CTF-Target': 'bola-honeypot'
          });
          res.end(
            JSON.stringify({
              resource: invoiceOrUserMatch[1].toLowerCase(),
              id: invoiceOrUserMatch[2],
              status: 'REDACTED_BY_ZERO_TRUST_RBAC',
              hint: 'Sequential ID enumeration is monitored by Aegis Sliding-Window BOLA Shield.'
            })
          );
          return;
        }

        res.writeHead(404, {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Aegis-CTF-Target': 'active'
        });
        res.end(
          JSON.stringify({
            status: 404,
            error: 'CTF Arena Endpoint Not Found',
            available_entry_point: '/ctf',
            vault_target: '/api/v1/ctf/flag'
          })
        );
        return;
      }

      // Résolution de l'Upstream :
      // - En mode 'edge' (ex: VM Oracle Cloud), toutes les requêtes applicatives (y compris /api/* et exploits non bloqués)
      //   sont routées vers l'application cliente protégée (config.webUrl), tandis que config.backendUrl sert uniquement au Control Plane.
      // - En mode 'control-plane', routage multi-hôtes Dokploy ou séparation Backend Go / Frontend Astro.
      const reqHost = ((req.headers['x-forwarded-host'] || req.headers.host || '') as string)
        .split(':')[0]
        .toLowerCase();
      const isApiOrExploitTarget =
        config.nodeMode !== 'edge' &&
        ((req.url || '').startsWith('/api/') || (verdict.blocked && !state.protectionEnabled));
      let targetBase = config.upstreamRouting[reqHost];
      if (!targetBase) {
        targetBase = isApiOrExploitTarget ? config.backendUrl : config.webUrl;
      }
      const bufferedBody = Buffer.concat(bodyChunks);

      const additionalHeaders: http.OutgoingHttpHeaders = {};
      if (isApiOrExploitTarget && authHandler) {
        authHandler.enrichBackendHeaders(req, additionalHeaders);
      }

      forwarder.forward(
        req,
        res,
        targetBase,
        clientIp,
        state.protectionEnabled,
        effectiveBytes,
        bufferedBody,
        additionalHeaders
      );
    });
  });
}
