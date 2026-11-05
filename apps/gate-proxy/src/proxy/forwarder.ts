import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';
import type { IncomingMessage, ServerResponse } from 'node:http';

export interface IProxyForwarder {
  forward(
    req: IncomingMessage,
    res: ServerResponse,
    targetBase: string,
    clientIp: string,
    protectionEnabled: boolean,
    effectiveBytes: number,
    bufferedBody: Buffer,
    additionalHeaders?: http.OutgoingHttpHeaders
  ): void;
}

export class HttpProxyForwarder implements IProxyForwarder {
  public forward(
    req: IncomingMessage,
    res: ServerResponse,
    targetBase: string,
    clientIp: string,
    protectionEnabled: boolean,
    effectiveBytes: number,
    bufferedBody: Buffer,
    additionalHeaders?: http.OutgoingHttpHeaders
  ): void {
    const targetUrl = new URL(req.url || '/', targetBase);
    const client = targetUrl.protocol === 'https:' ? https : http;

    const proxyHeaders = { ...req.headers, ...(additionalHeaders || {}) };
    proxyHeaders['x-forwarded-for'] = clientIp;
    proxyHeaders['x-aegis-verified'] = protectionEnabled ? 'true' : 'bypass-unprotected';
    proxyHeaders['x-aegis-payload-bytes'] = String(effectiveBytes);
    proxyHeaders['host'] = targetUrl.host;

    if (proxyHeaders['content-length']) {
      proxyHeaders['content-length'] = String(bufferedBody.length);
    }

    const proxyReq = client.request(
      targetUrl,
      {
        method: req.method,
        headers: proxyHeaders,
        timeout: 10000
      },
      proxyRes => {
        res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
        proxyRes.pipe(res);
      }
    );

    proxyReq.on('error', () => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 502,
          error: 'Bad Gateway - Upstream indisponible',
          upstream: targetBase
        })
      );
    });

    if (bufferedBody.length > 0) {
      proxyReq.write(bufferedBody);
    }
    proxyReq.end();
  }
}
