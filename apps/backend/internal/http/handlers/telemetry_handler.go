package handlers

import (
	"net/http"

	"github.com/aivo-labs/aegis/backend/internal/domain"
	"github.com/aivo-labs/aegis/backend/internal/httputil"
	"github.com/aivo-labs/aegis/backend/internal/service"
)

type TelemetryHandler struct {
	telemetryService *service.TelemetryService
}

func NewTelemetryHandler(telemetryService *service.TelemetryService) *TelemetryHandler {
	return &TelemetryHandler{telemetryService: telemetryService}
}

func (h *TelemetryHandler) IngestEnergy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	body := httputil.ReadJSONBody(r)

	hostname := httputil.AsString(body, "hostname", "")
	if hostname == "" {
		hostname = httputil.AsString(body, "server_id", "vps-main-01")
	}

	provider := httputil.AsString(body, "provider", "ovhcloud")

	powerWatts := httputil.AsFloat(body, "power_watts", 0)
	cpuPower := httputil.AsFloat(body, "cpu_power_watts", 0)
	if cpuPower == 0 && powerWatts > 0 {
		cpuPower = powerWatts * 0.70
	}

	ramPower := httputil.AsFloat(body, "ram_power_watts", 0)
	if ramPower == 0 {
		ramPower = httputil.AsFloat(body, "memory_power_watts", 0)
	}
	if ramPower == 0 && powerWatts > 0 {
		ramPower = powerWatts * 0.30
	}

	energyJoules := httputil.AsFloat(body, "energy_consumed_joules", 0)
	if energyJoules == 0 {
		energyJoules = httputil.AsFloat(body, "energy_joules_delta", 0)
	}

	cpuUtil := httputil.AsFloat(body, "cpu_utilization_pct", 0)
	if cpuUtil == 0 {
		cpuUtil = httputil.AsFloat(body, "cpu_usage_percent", 0)
	}

	payload := domain.EnergyTelemetry{
		TenantID:             httputil.AsString(body, "tenant_id", ""),
		Hostname:             hostname,
		IPAddress:            httputil.AsString(body, "ip_address", "127.0.0.1"),
		Provider:             provider,
		CPUPowerWatts:        cpuPower,
		RAMPowerWatts:        ramPower,
		EnergyConsumedJoules: energyJoules,
		CPUUtilizationPct:    cpuUtil,
		MemoryUsedMB:         httputil.AsInt(body, "memory_used_mb", 0),
	}
	if err := h.telemetryService.IngestEnergy(payload); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]any{"status": "ingested", "type": "energy"})
}

func (h *TelemetryHandler) IngestIngress(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	body := httputil.ReadJSONBody(r)
	meta, _ := body["metadata"].(map[string]any)

	payload := domain.IngressTelemetry{
		TenantID:           httputil.AsString(body, "tenant_id", ""),
		ClientIP:           httputil.AsString(body, "client_ip", "127.0.0.1"),
		UserAgent:          httputil.AsString(body, "user_agent", ""),
		HTTPMethod:         httputil.AsString(body, "http_method", "GET"),
		RequestURI:         httputil.AsString(body, "request_uri", "/"),
		Decision:           httputil.AsString(body, "decision", "ALLOW"),
		HTTPStatusReturned: httputil.AsInt(body, "http_status_returned", 200),
		LatencyMs:          httputil.AsFloat(body, "latency_ms", 0.5),
		ThreatType:         httputil.AsString(body, "threat_type", ""),
		Metadata:           meta,
	}
	if err := h.telemetryService.IngestIngress(payload); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]any{"status": "ingested", "type": "ingress"})
}

func (h *TelemetryHandler) IngestEgress(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	body := httputil.ReadJSONBody(r)
	meta, _ := body["metadata"].(map[string]any)

	payload := domain.EgressTelemetry{
		TenantID:      httputil.AsString(body, "tenant_id", ""),
		ClientIP:      httputil.AsString(body, "client_ip", "127.0.0.1"),
		FQDN:          httputil.AsString(body, "fqdn", "unknown.local"),
		DomainEntropy: httputil.AsFloat(body, "domain_entropy", 0),
		Action:        httputil.AsString(body, "action", "ALLOW"),
		ThreatType:    httputil.AsString(body, "threat_type", "CLEAN_EGRESS"),
		Confidence:    httputil.AsFloat(body, "confidence", 0.95),
		LatencyMs:     httputil.AsFloat(body, "latency_ms", 1.0),
		Metadata:      meta,
	}
	if err := h.telemetryService.IngestEgress(payload); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]any{"status": "ingested", "type": "egress"})
}
