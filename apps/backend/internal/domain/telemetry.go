package domain

// IngressTelemetry représente une requête HTTP entrante analysée par gate-proxy.
type IngressTelemetry struct {
	TenantID           string         `json:"tenant_id"`
	ClientIP           string         `json:"client_ip"`
	UserAgent          string         `json:"user_agent"`
	HTTPMethod         string         `json:"http_method"`
	RequestURI         string         `json:"request_uri"`
	Decision           string         `json:"decision"`
	HTTPStatusReturned int            `json:"http_status_returned"`
	KeycloakUserID     string         `json:"keycloak_user_id,omitempty"`
	LatencyMs          float64        `json:"latency_ms"`
	ThreatType         string         `json:"threat_type,omitempty"`
	Severity           string         `json:"severity,omitempty"`
	RiskScore          int            `json:"risk_score,omitempty"`
	Entropy            float64        `json:"entropy,omitempty"`
	MatchedPattern     string         `json:"matched_pattern,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

// EgressTelemetry représente une requête DNS ou socket sortante évaluée par egress-gateway.
type EgressTelemetry struct {
	TenantID      string         `json:"tenant_id"`
	ClientIP      string         `json:"client_ip"`
	FQDN          string         `json:"fqdn"`
	DomainEntropy float64        `json:"domain_entropy"`
	Action        string         `json:"action"`
	ThreatType    string         `json:"threat_type"`
	Confidence    float64        `json:"confidence"`
	LatencyMs     float64        `json:"latency_ms"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// EnergyTelemetry contient les mesures de puissance matérielle (RAPL / Scaphandre).
type EnergyTelemetry struct {
	TenantID             string  `json:"tenant_id"`
	Hostname             string  `json:"hostname"`
	IPAddress            string  `json:"ip_address"`
	Provider             string  `json:"provider,omitempty"`
	CPUPowerWatts        float64 `json:"cpu_power_watts"`
	RAMPowerWatts        float64 `json:"ram_power_watts"`
	EnergyConsumedJoules float64 `json:"energy_consumed_joules"`
	CPUUtilizationPct    float64 `json:"cpu_utilization_pct"`
	MemoryUsedMB         int     `json:"memory_used_mb"`
}
