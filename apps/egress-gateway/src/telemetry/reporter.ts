import type { EgressTelemetryPayload } from '../types.js';

export interface IEgressTelemetryReporter {
  send(payload: EgressTelemetryPayload): Promise<boolean>;
}

export class HttpEgressTelemetryReporter implements IEgressTelemetryReporter {
  constructor(private readonly gateApiUrl: string) {}

  public async send(payload: EgressTelemetryPayload): Promise<boolean> {
    try {
      const res = await fetch(this.gateApiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}
