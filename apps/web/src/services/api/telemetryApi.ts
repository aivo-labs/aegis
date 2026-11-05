import { apiRequest } from './client';

export interface PowerPoint {
  time: string;
  watts: number;
}

export interface TelemetrySummary {
  green?: {
    instant_power_watts: number;
    cpu_watts: number;
    ram_watts: number;
    cpu_load_pct: number;
    carbon_intensity_gco2_h: number;
    power_history: PowerPoint[];
    total_joules?: number;
    pue?: number;
  };
  security?: {
    total_blocked?: number;
    interception_rate?: number;
    active_threats?: number;
  };
  nodes_count?: number;
}

export const telemetryApi = {
  async getSummary() {
    return apiRequest<TelemetrySummary>('/api/v1/dashboard/summary', { method: 'GET' });
  },
};
