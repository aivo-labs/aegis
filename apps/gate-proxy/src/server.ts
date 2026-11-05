import http from 'node:http';
import crypto from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { IWafInspector } from './engine/inspector.js';
import type { IIpReputationManager } from './quarantine/ip-reputation.js';
import type { ITelemetryReporter } from './telemetry/reporter.js';
import type { IProxyForwarder } from './proxy/forwarder.js';
import type { GateConfig } from './config.js';
import { BffAuthHandler } from './bff/auth-handler.js';

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
          protection_enabled: state.protectionEnabled,
          max_payload_bytes: state.maxPayloadBytes,
          banned_ips_count: ipReputation.size()
        })
      );
      return;
    }

    // Endpoint de simulation de sondes bots / pentest pour le Cockpit SOC
    if (req.url === '/_aegis/simulate' && (req.method === 'POST' || req.method === 'GET' || req.method === 'OPTIONS')) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
      }

      const clientIp = getClientIp(req);
      const simulatedProbes = [
        { path: '/wp-login.php', method: 'GET', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap/1.5.11', threat: 'SCANNER' },
        { path: '/wp-content/plugins/revslider/temp/update_extract/revslider/db.php', method: 'GET', ua: 'nikto/2.1.6', threat: 'CMS_PROBE' },
        { path: '/xmlrpc.php', method: 'POST', ua: 'python-requests/2.31.0', threat: 'CMS_PROBE' },
        { path: '/.env', method: 'GET', ua: 'gobuster/3.5', threat: 'SENSITIVE_PROBE' },
        { path: '/phpmyadmin/index.php', method: 'GET', ua: 'zgrab/0.x', threat: 'CMS_PROBE' },
        { path: '/api/v1/search?q=1+UNION+SELECT+username,password+FROM+users--', method: 'GET', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap', threat: 'SQLI' }
      ];

      const results = [];
      for (const p of simulatedProbes) {
        const headers = { 'user-agent': p.ua, host: req.headers.host || 'aegis.aivo.fr' };
        const inspection = inspector.inspect(p.path, p.method, headers, '', 0, clientIp);
        const decision = state.protectionEnabled ? (inspection.decision || 'BLOCK') : 'BYPASS';
        const statusCode = decision === 'BLOCK' ? 403 : 200;

        telemetry.send({
          tenant_id: config.tenantId,
          client_ip: clientIp,
          user_agent: p.ua,
          http_method: p.method,
          request_uri: p.path,
          decision,
          http_status_returned: statusCode,
          latency_ms: 0.8,
          threat_type: inspection.threat_type || p.threat,
          severity: inspection.severity,
          risk_score: inspection.risk_score,
          entropy: inspection.entropy,
          matched_pattern: inspection.pattern,
          metadata: {
            simulated: true,
            pattern: inspection.pattern
          }
        });

        results.push({
          uri: p.path,
          method: p.method,
          decision,
          status_code: statusCode,
          threat_type: inspection.threat_type || p.threat
        });
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'success',
        protection_enabled: state.protectionEnabled,
        simulated_count: results.length,
        results
      }));
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

      // CAS 1 : ATTAQUE DÉTECTÉE ET BOUCLIER ACTIF -> BLOCAGE IMMÉDIAT (403 ou 413)
      if (verdict.blocked && state.protectionEnabled) {
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
              engine: 'Aegis Gate PEP'
            }
          });
        }
      }

      // Si une attaque passe alors que le bouclier est désactivé, on la route vers le backend cible
      const isApiOrExploitTarget =
        (req.url || '').startsWith('/api/') || (verdict.blocked && !state.protectionEnabled);
      const targetBase = isApiOrExploitTarget ? config.backendUrl : config.webUrl;
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
