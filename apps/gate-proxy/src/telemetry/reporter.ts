import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';
import type { IngressTelemetryPayload } from '../types.js';

export interface ITelemetryReporter {
  send(payload: IngressTelemetryPayload): void;
}

export class HttpTelemetryReporter implements ITelemetryReporter {
  constructor(private readonly telemetryUrl: string) {}

  public send(payload: IngressTelemetryPayload): void {
    try {
      const targetUrl = new URL(this.telemetryUrl);
      const bodyStr = JSON.stringify(payload);

      const client = targetUrl.protocol === 'https:' ? https : http;
      const req = client.request(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
          'X-Aegis-Internal': 'PEP-Ingress'
        },
        timeout: 2500
      });

      req.on('error', () => {
        // Tolérance aux pannes réseau
      });
      req.write(bodyStr);
      req.end();
    } catch {
      // Tolérance aux erreurs de parsing d'URL
    }
  }
}
