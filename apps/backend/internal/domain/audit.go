package domain

// PageEcoAudit représente l'analyse d'éco-conception d'une page HTML individuelle.
type PageEcoAudit struct {
	URL            string  `json:"url"`
	Path           string  `json:"path"`
	StatusCode     int     `json:"status_code"`
	ResponseTimeMs int64   `json:"response_time_ms"`
	LoadTimeMs     int64   `json:"load_time_ms"`
	WeightKB       float64 `json:"weight_kb"`
	DOMElements    int     `json:"dom_elements"`
	HTTPRequests   int     `json:"http_requests"`
	EcoScore       float64 `json:"eco_score"`
	EcoIndexScore  float64 `json:"eco_index_score"`
	EcoGrade       string  `json:"eco_grade"`
	EcoIndexGrade  string  `json:"eco_index_grade"`
	GCO2ePerVisit  float64 `json:"gco2e_per_visit"`
	GCO2Grams      float64 `json:"gco2_grams"`
	WaterCL        float64 `json:"water_cl"`
}

// TechFingerprint modélise une technologie détectée sur le site audité.
type TechFingerprint struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version"`
	Source     string `json:"source"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"`
}

// CVEWarning représente une vulnérabilité ou risque identifié ainsi que sa couverture et sa procédure de remédiation.
type CVEWarning struct {
	ID                  string   `json:"id"`
	CVEID               string   `json:"cve_id"`
	Name                string   `json:"name,omitempty"`
	Severity            string   `json:"severity"` // CRITICAL, HIGH, MEDIUM
	CVSS                string   `json:"cvss"`
	Component           string   `json:"component"`
	AffectedVersions    string   `json:"affected_versions,omitempty"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	Vector              string   `json:"vector,omitempty"`
	Remediation         string   `json:"remediation"`
	BlockedByAegis      bool     `json:"blocked_by_aegis"`
	IsActiveDefense     bool     `json:"is_active_defense"`
	CoverageStatus      string   `json:"coverage_status"`       // COVERED_VIRTUAL_PATCH, MITIGATED_EGRESS_ONLY, HOST_PATCH_REQUIRED
	VirtualPatchRuleID  string   `json:"virtual_patch_rule_id"` // ex: WAF-413-VOLUMETRIC, WAF-PHP-CGI-ARGS
	VirtualPatchSummary string   `json:"virtual_patch_summary"` // Action immédiate d'Aegis à chaud (sans downtime)
	RootFixProcedure    []string `json:"root_fix_procedure"`    // Procédure étape par étape pour corriger la cause racine sur l'hôte
	VerificationProbe   string   `json:"verification_probe"`    // Commande de test permettant de vérifier la couverture
	CISAKEV             bool     `json:"cisa_kev"`              // Référencée au catalogue CISA Known Exploited Vulnerabilities
	PublishedAt         string   `json:"published_at,omitempty"`
}

// HeaderCheck détaille la présence et la conformité d'un en-tête HTTP de sécurité.
type HeaderCheck struct {
	Header  string `json:"header"`
	Present bool   `json:"present"`
	Value   string `json:"value"`
	Status  string `json:"status"` // OK, WARNING, CRITICAL
	Impact  string `json:"impact"`
}

// DNSAnalysis contient les enregistrements SPF, DMARC, CAA et IPs résolues.
type DNSAnalysis struct {
	HasSPF      bool     `json:"has_spf"`
	SPFRecord   string   `json:"spf_record"`
	HasDMARC    bool     `json:"has_dmarc"`
	DMARCRecord string   `json:"dmarc_record"`
	HasCAA      bool     `json:"has_caa"`
	ResolvedIPs []string `json:"resolved_ips"`
}

// PassiveAuditResult est le résultat consolidé d'un audit de domaine.
type PassiveAuditResult struct {
	AuditID           string            `json:"audit_id"`
	Domain            string            `json:"domain"`
	ScannedAt         string            `json:"scanned_at"`
	ScanDurationMs    int64             `json:"scan_duration_ms"`
	PagesScanned      int               `json:"pages_scanned"`
	OverallEcoScore   float64           `json:"overall_eco_score"`
	EcoIndexScore     float64           `json:"eco_index_score"`
	OverallEcoGrade   string            `json:"overall_eco_grade"`
	EcoIndexGrade     string            `json:"eco_index_grade"`
	AvgGCO2ePerVisit  float64           `json:"avg_gco2e_per_visit"`
	AvgGCO2Grams      float64           `json:"avg_gco2_grams"`
	AvgWaterCL        float64           `json:"avg_water_cl"`
	SecurityScore     int               `json:"security_score"`
	SecurityGrade     string            `json:"security_grade"`
	IsVerifiedOwner   bool              `json:"is_verified_owner"`
	OwnershipVerified bool              `json:"ownership_verified"`
	ContractHash      string            `json:"contract_hash,omitempty"`
	VerifiedAt        string            `json:"verified_at,omitempty"`
	TechStack         []TechFingerprint `json:"tech_stack"`
	DetectedTech      []TechFingerprint `json:"detected_tech"`
	CVEWarnings       []CVEWarning      `json:"cve_warnings"`
	HeadersAnalysis   []HeaderCheck     `json:"headers_analysis"`
	SecurityHeaders   map[string]bool   `json:"security_headers"`
	DNS               DNSAnalysis       `json:"dns_analysis"`
	DNSChecks         map[string]string `json:"dns_checks"`
	PagesDetail       []PageEcoAudit    `json:"pages_detail"`
	Pages             []PageEcoAudit    `json:"pages"`
	DeepProbes        []map[string]any  `json:"deep_probes,omitempty"`
}
