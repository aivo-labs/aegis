package domain

// SummaryMetrics consolide l'ensemble des indicateurs de sécurité et d'éco-conception.
type SummaryMetrics struct {
	Timestamp            string           `json:"timestamp"`
	ProtectionEnabled    bool             `json:"protection_enabled"`
	MaxPayloadBytes      int              `json:"max_payload_bytes"`
	SecurityScoreNIS2    int              `json:"security_score_nis2"`
	EcoIndexGlobal       float64          `json:"ecoindex_global"`
	EcoGradeGlobal       string           `json:"eco_grade_global"`
	TotalAttacksBlocked  int              `json:"total_attacks_blocked"`
	TotalAttacksBypassed int              `json:"total_attacks_bypassed"`
	ActiveBansCount      int              `json:"active_bans_count"`
	IngressTotal         int              `json:"ingress_total"`
	IngressBlocked       int              `json:"ingress_blocked"`
	IngressBypassed      int              `json:"ingress_bypassed"`
	EgressTotal          int              `json:"egress_total"`
	EgressBlocked        int              `json:"egress_blocked"`
	EgressBypassed       int              `json:"egress_bypassed"`
	BotProbesTotal       int              `json:"bot_probes_total"`
	InstantWatts         float64          `json:"instant_watts"`
	AvgWatts24h          float64          `json:"avg_watts_24h"`
	CarbonGramsSaved24h  float64          `json:"carbon_grams_saved_24h"`
	MonitoredNodes       []map[string]any `json:"monitored_nodes"`
	PowerHistory         []map[string]any `json:"power_history"`
	Timeline24h          []map[string]any `json:"timeline_24h"`
	GeoIPPoints          []map[string]any `json:"geoip_points"`
}

// ThreatFeedItem représente une ligne d'alerte pour le flux de menaces ou le tableau Kanban de triage.
type ThreatFeedItem struct {
	ID                 string   `json:"id"`
	Timestamp          string   `json:"timestamp"`
	Direction          string   `json:"direction"` // INGRESS, EGRESS
	ClientIP           string   `json:"client_ip"`
	ThreatType         string   `json:"threat_type"`
	ThreatCategory     string   `json:"threat_category"`
	Target             string   `json:"target"`
	Severity           string   `json:"severity"`
	RiskScore          int      `json:"risk_score"`
	Action             string   `json:"action"`
	Engine             string   `json:"engine"`
	KanbanStage        string   `json:"kanban_stage"` // IN_TRIAGE, REMEDIATED, UNDER_INVESTIGATION
	MitreAttckRef      string   `json:"mitre_attck_ref"`
	VirtualPatchStatus string   `json:"virtual_patch_status"`
	RemediationSteps   []string `json:"remediation_steps"`
}
