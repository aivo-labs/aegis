import http from 'node:http';
import { URL } from 'node:url';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { IEgressEvaluator } from '../engine/evaluator.js';

export function createEgressHttpServer(
  evaluator: IEgressEvaluator,
  listenPort: number,
  systemOneModelName: string
): http.Server {
  return http.createServer((req: IncomingMessage, res: ServerResponse) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'healthy',
          service: 'aegis-egress-gateway',
          udp_port: listenPort,
          tcp_port: listenPort,
          protection_enabled: evaluator.isProtectionEnabled(),
          dns_ip_allowlist_entries: evaluator.getIpAllowlist().size(),
          engine: `System One (${systemOneModelName})`
        })
      );
      return;
    }

    if (req.url === '/api/v1/egress/verify-connection' && req.method === 'POST') {
      const vChunks: Buffer[] = [];
      req.on('data', c => vChunks.push(c));
      req.on('end', async () => {
        try {
          const body = JSON.parse(Buffer.concat(vChunks).toString('utf8') || '{}');
          const destIp = String(body.dest_ip || body.ip || '').trim();
          const destPort = Number(body.dest_port || body.port || 4444);
          const clientIp =
            body.client_ip || req.socket.remoteAddress?.replace(/^::ffff:/, '') || '127.0.0.1';

          const verdict = await evaluator.verifyIpConnection(destIp, clientIp, destPort);
          const isBlocked = verdict.action === 'BLOCK' || verdict.action === 'QUARANTINE';

          res.writeHead(isBlocked ? 403 : 200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              status: isBlocked ? 'blocked' : 'allowed',
              dest_ip: destIp,
              dest_port: destPort,
              ...verdict
            })
          );
        } catch (err: unknown) {
          const error = err as Error;
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'error', message: error.message }));
        }
      });
      return;
    }

    if (req.url === '/mode') {
      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 'success',
            protection_enabled: evaluator.isProtectionEnabled()
          })
        );
        return;
      }
      if (req.method === 'POST') {
        const mChunks: Buffer[] = [];
        req.on('data', c => mChunks.push(c));
        req.on('end', () => {
          try {
            const body = JSON.parse(Buffer.concat(mChunks).toString('utf8') || '{}');
            if (typeof body.enabled === 'boolean') {
              evaluator.setProtectionEnabled(body.enabled);
            } else if (typeof body.protection_enabled === 'boolean') {
              evaluator.setProtectionEnabled(body.protection_enabled);
            }
            console.log(
              `⚡ [Aegis Egress] Mode de protection basculé sur : ${
                evaluator.isProtectionEnabled() ? '🛡️ ACTIF (SINKHOLE)' : '⚠️ DÉSACTIVÉ (BYPASS)'
              }`
            );
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                status: 'success',
                protection_enabled: evaluator.isProtectionEnabled()
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

    const chunks: Buffer[] = [];
    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      try {
        const bodyStr = Buffer.concat(chunks).toString('utf8');
        const data = bodyStr ? JSON.parse(bodyStr) : {};
        const urlObj = new URL(req.url || '/', `http://localhost:${listenPort}`);
        const fqdn = data.fqdn || data.dest_ip || urlObj.searchParams.get('fqdn') || 'revshell-callback.darknet-c2.top';
        const protocolContext = data.protocol || urlObj.searchParams.get('protocol') || 'tcp_egress';
        const clientIp =
          data.client_ip || req.socket.remoteAddress?.replace(/^::ffff:/, '') || '127.0.0.1';

        const decision = await evaluator.processQuery(fqdn, clientIp, protocolContext);
        const isBlocked = decision.action === 'BLOCK' || decision.action === 'QUARANTINE';

        res.writeHead(isBlocked ? 403 : 200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: isBlocked ? 'blocked' : 'allowed',
            fqdn,
            protocol: protocolContext,
            simulated_callback: !isBlocked
              ? 'CONNECTED_TO_C2_SOCKET (uid=33(www-data) /bin/sh reverse shell active -> 93.184.216.34:4444)'
              : null,
            ...decision
          })
        );
      } catch (err: unknown) {
        const error = err as Error;
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: error.message }));
      }
    });
  });
}
