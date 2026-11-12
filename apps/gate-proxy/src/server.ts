import http from 'node:http';
import crypto from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { IWafInspector } from './engine/inspector.js';
import type { IIpReputationManager } from './quarantine/ip-reputation.js';
import type { ITelemetryReporter } from './telemetry/reporter.js';
import type { IProxyForwarder } from './proxy/forwarder.js';
import type { GateConfig } from './config.js';
import { BffAuthHandler } from './bff/auth-handler.js';
import { extractSessionFromRequest } from './bff/session.js';

export function getClientIp(req: IncomingMessage): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  const remote = req.socket.remoteAddress || '127.0.0.1';
  return remote.replace(/^::ffff:/, '');
}

export interface GateServerState {
  protectionEnabled: boolean;
  maxPayloadBytes: number;
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

    // Exemption M2M (Control Plane) : les rapports de télémétrie et d'enrôlement envoyés par des nœuds distants
    // (ex: VM Oracle Cloud) contiennent les URI/payloads d'attaques bloquées dans leur corps JSON et ne doivent
    // jamais être auto-bloqués par le WAF du Control Plane.
    if (
      config.nodeMode !== 'edge' &&
      req.url &&
      (req.url.startsWith('/api/v1/gate/telemetry/') || req.url.startsWith('/api/v1/agent/'))
    ) {
      const m2mChunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => m2mChunks.push(chunk));
      req.on('end', () => {
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

    // Endpoint de simulation de sondes bots / pentest (Ingress & Egress) pour le Cockpit SOC
    if (req.url === '/_aegis/simulate' && (req.method === 'POST' || req.method === 'GET' || req.method === 'OPTIONS')) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
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
      const targetUri = (req.headers['x-forwarded-uri'] as string) || (req.url || '/').replace(/^\/_aegis\/verify/, '') || '/';
      const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || getClientIp(req);
      const userAgent = (req.headers['user-agent'] as string) || 'unknown';

      // Immunité totale pour les flux d'authentification BFF OIDC (/api/auth/*)
      if (targetUri.startsWith('/api/auth/')) {
        res.writeHead(200, {
          'X-Aegis-Verified': 'auth-flow',
          'X-Aegis-Engine': 'Aegis Gate PEP',
          'X-Aegis-Client-IP': clientIp
        });
        res.end();
        return;
      }

      // Immunité d'accès pour l'administrateur SOC & IP VPS
      const session = extractSessionFromRequest(req.headers.cookie, config.sessionSecret);
      const isAdminSession = session?.role === 'admin' || session?.role === 'secops';
      const isImmuneIp = clientIp === '92.157.163.164' || clientIp === '127.0.0.1';

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
      } else if (verdict.blocked && state.protectionEnabled && !isImmuneIp) {
        const statusCode = verdict.http_status || 403;
        const eventId = `aegis-fwd-${crypto.randomBytes(6).toString('hex')}`;

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
            host: req.headers['x-forwarded-host'] || req.headers.host
          }
        });

        res.writeHead(statusCode, {
          'Content-Type': 'application/json',
          'X-Aegis-Decision': 'BLOCK',
          'X-Aegis-Threat': verdict.threat_type || 'SECURITY_THREAT'
        });
        res.end(JSON.stringify({
          status: statusCode,
          error: 'Access Denied by Aegis Gate Zero-Trust PEP (Traefik ForwardAuth)',
          verdict: 'BLOCKED',
          threat_detected: verdict.threat_type,
          severity: verdict.severity,
          risk_score: verdict.risk_score,
          client_ip: clientIp,
          target_uri: targetUri,
          event_id: eventId,
          security_standard: 'ANSSI NIS 2 Hardened • Virtual Patching Active'
        }));
        return;
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

    // Endpoint interne de contrôle du bouclier (activation / désactivation à chaud + seuil 413 + Ban IP)
    if (req.url === '/_aegis/mode') {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
      }

      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 'success',
            protection_enabled: state.protectionEnabled,
            max_payload_bytes: state.maxPayloadBytes,
            banned_ips: ipReputation.getAll()
          })
        );
        return;
      }

      if (req.method === 'POST') {
        const chunks: Buffer[] = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => {
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
            if (Array.isArray(body.banned_ips)) {
              ipReputation.clear();
              for (const ip of body.banned_ips) {
                if (ip && typeof ip === 'string') ipReputation.ban(ip.trim());
              }
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
      const session = extractSessionFromRequest(req.headers.cookie, config.sessionSecret);
      const isAdminSession = session?.role === 'admin' || session?.role === 'secops';
      // En mode 'edge' (ex: VM Oracle Cloud), nous n'immunisons pas 127.0.0.1 afin que les scripts
      // de test locaux ou distants exécutés sur la VM soient réellement inspectés et bloqués par le WAF.
      const isImmuneIp =
        config.nodeMode === 'edge'
          ? false
          : clientIp === '92.157.163.164' || clientIp === '127.0.0.1';
      const effectiveHost =
        config.nodeHostname ||
        ((req.headers['x-forwarded-host'] || req.headers.host || 'aegis.aivo.fr') as string).split(':')[0];

      if (verdict.threat_type === 'BANNED_IP_BLACKLIST' && (isAdminSession || isImmuneIp)) {
        ipReputation.unban(clientIp);
        // Débannissement automatique dans PostgreSQL / TimescaleDB
        fetch(`${config.backendUrl}/api/v1/dashboard/bans?ip=${encodeURIComponent(clientIp)}`, { method: 'DELETE' }).catch(() => {});
      } else if (verdict.blocked && state.protectionEnabled && !isImmuneIp) {
        const statusCode = verdict.http_status || 403;
        const eventId = `aegis-blk-${crypto.randomBytes(6).toString('hex')}`;

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

        const responsePayload = JSON.stringify(
          {
            status: statusCode,
            error:
              statusCode === 413
                ? 'Payload Too Large — Blocked by Aegis Gate Virtual Patching'
                : 'Access Denied by Aegis Gate Zero-Trust PEP',
            verdict: 'BLOCKED',
            threat_detected: verdict.threat_type,
            severity: verdict.severity,
            risk_score: verdict.risk_score,
            details: verdict.pattern,
            client_ip: clientIp,
            node_hostname: config.nodeHostname || effectiveHost,
            latency_ms: latency,
            timestamp: new Date().toISOString(),
            event_id: eventId,
            security_standard: 'ANSSI NIS 2 Hardened • Virtual Patching Active'
          },
          null,
          2
        );

        res.writeHead(statusCode, {
          'Content-Type': 'application/json',
          'X-Aegis-Verdict': 'BLOCKED',
          'X-Aegis-Threat': verdict.threat_type,
          'X-Aegis-Event-ID': eventId,
          'X-Aegis-Node': config.nodeHostname || effectiveHost,
          'X-Content-Type-Options': 'nosniff',
          'Access-Control-Allow-Origin': '*'
        });
        res.end(responsePayload);
        return;
      }

      // CAS 1-BIS : ATTAQUE DÉTECTÉE MAIS BOUCLIER DÉSACTIVÉ -> LAISSE PASSER VERS LA CIBLE
      if (verdict.blocked && !state.protectionEnabled) {
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
      } else {
        // CAS 2 : TRAFIC CONFORME -> JOURNALISATION (hors assets statiques & polling interne)
        const isStaticOrPoll =
          (req.url || '').startsWith('/_astro/') ||
          req.url === '/favicon.ico' ||
          req.url === '/favicon.svg' ||
          (req.url || '').startsWith('/api/v1/dashboard/');
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
