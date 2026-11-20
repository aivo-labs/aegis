package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/database"
	"github.com/aivo-labs/aegis/backend/internal/domain"
	"github.com/aivo-labs/aegis/backend/internal/scanner"
)

// AuditScheduleConfig modélise la supervision continue planifiée (Verrou n°5 P1).
type AuditScheduleConfig struct {
	Enabled       bool     `json:"enabled"`
	TargetDomain  string   `json:"target_domain"`
	IntervalHours int      `json:"interval_hours"`
	LastRunAt     string   `json:"last_run_at,omitempty"`
	NextRunAt     string   `json:"next_run_at,omitempty"`
	DriftDetected bool     `json:"drift_detected"`
	DriftAlerts   []string `json:"drift_alerts"`
}

type AuditService struct {
	db       *database.PgClient
	mu       sync.RWMutex
	schedule AuditScheduleConfig
	lastScan *domain.PassiveAuditResult
}

func NewAuditService(db *database.PgClient) *AuditService {
	now := time.Now().UTC()
	svc := &AuditService{
		db: db,
		schedule: AuditScheduleConfig{
			Enabled:       true,
			TargetDomain:  "aegis.aivo.fr",
			IntervalHours: 12,
			LastRunAt:     now.Format(time.RFC3339),
			NextRunAt:     now.Add(12 * time.Hour).Format(time.RFC3339),
			DriftDetected: false,
			DriftAlerts:   []string{},
		},
	}
	return svc
}

func (s *AuditService) RunScan(rawDomain string) domain.PassiveAuditResult {
	res := scanner.RunPassiveDomainScan(s.db, rawDomain)

	s.mu.Lock()
	if s.lastScan != nil && s.lastScan.Domain == res.Domain {
		drifts := EvaluatePostureDrift(*s.lastScan, res)
		s.schedule.DriftDetected = len(drifts) > 0
		s.schedule.DriftAlerts = drifts
	}
	s.lastScan = &res
	s.schedule.TargetDomain = res.Domain
	now := time.Now().UTC()
	s.schedule.LastRunAt = now.Format(time.RFC3339)
	s.schedule.NextRunAt = now.Add(time.Duration(s.schedule.IntervalHours) * time.Hour).Format(time.RFC3339)
	driftsToLog := s.schedule.DriftAlerts
	s.mu.Unlock()

	if len(driftsToLog) > 0 && s.db != nil {
		metaJSON, _ := json.Marshal(map[string]any{
			"threat_type":  "CONTINUOUS_AUDIT_DRIFT_ALERT",
			"severity":     "HIGH",
			"domain":       res.Domain,
			"drift_alerts": driftsToLog,
			"engine":       "Aegis Continuous Posture Scheduler (Verrou P1)",
		})
		_ = s.db.Exec(fmt.Sprintf(`
			INSERT INTO security_audit_logs (
				tenant_id, client_ip, user_agent, http_method, request_uri, decision, http_status_returned, latency_ms, metadata, timestamp
			) VALUES (
				'00000000-0000-0000-0000-000000000001', '127.0.0.1', 'Aegis-Posture-Scheduler/1.2', 'AUDIT', %s, 'ALERT', 200, 1.0, %s::jsonb, CURRENT_TIMESTAMP
			);`,
			database.QuoteLiteral("/audit/drift/"+res.Domain),
			database.QuoteLiteral(string(metaJSON)),
		))
	}

	return res
}

// EvaluatePostureDrift compare deux audits successifs d'un même domaine et détecte les régressions (Verrou n°5 P1).
func EvaluatePostureDrift(prev, curr domain.PassiveAuditResult) []string {
	var alerts []string

	if curr.SecurityScore < prev.SecurityScore {
		alerts = append(alerts, fmt.Sprintf(
			"Régression du score de sécurité sur %s : %d/100 (%s) -> %d/100 (%s)",
			curr.Domain, prev.SecurityScore, prev.SecurityGrade, curr.SecurityScore, curr.SecurityGrade,
		))
	}

	if prev.PostQuantum.PostQuantumReady && !curr.PostQuantum.PostQuantumReady {
		alerts = append(alerts, fmt.Sprintf(
			"Régression cryptographique Post-Quantique : perte de l'échange hybride X25519MLKEM768 sur %s",
			curr.Domain,
		))
	}

	prevHeaders := make(map[string]bool)
	for _, h := range prev.HeadersAnalysis {
		if h.Present {
			prevHeaders[strings.ToLower(h.Header)] = true
		}
	}
	for _, h := range curr.HeadersAnalysis {
		if !h.Present && prevHeaders[strings.ToLower(h.Header)] {
			alerts = append(alerts, fmt.Sprintf("En-tête de sécurité disparu : %s", h.Header))
		}
	}

	if len(curr.CVEWarnings) > len(prev.CVEWarnings) {
		alerts = append(alerts, fmt.Sprintf(
			"Nouvelles expositions CVE détectées : %d -> %d alerte(s)",
			len(prev.CVEWarnings), len(curr.CVEWarnings),
		))
	}

	if alerts == nil {
		return []string{}
	}
	return alerts
}

// GenerateGuidedRemediationSnippets produit les extraits de configuration prêts au copier-coller
// pour Traefik, Nginx, Caddy et Apache/php.ini couvrant les en-têtes manquants, TLS PQC et le durcissement hôte.
func GenerateGuidedRemediationSnippets(audit domain.PassiveAuditResult) map[string]string {
	domainName := audit.Domain
	if domainName == "" {
		domainName = "example.com"
	}

	traefik := fmt.Sprintf(`# Traefik v3.3+ — Durcissement En-têtes HTTP & TLS 1.3 Post-Quantique (%s)
http:
  middlewares:
    aegis-security-headers:
      headers:
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
        forceSTSHeader: true
        frameDeny: true
        contentTypeNosniff: true
        browserXssFilter: true
        referrerPolicy: "strict-origin-when-cross-origin"
        contentSecurityPolicy: "default-src 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
        permissionsPolicy: "camera=(), microphone=(), geolocation=(), payment=()"
        customResponseHeaders:
          Server: ""
          X-Powered-By: ""
tls:
  options:
    default:
      minVersion: VersionTLS13
      curvePreferences:
        - X25519MLKEM768
        - X25519`, domainName)

	nginx := fmt.Sprintf(`# Nginx 1.27+ / OpenSSL 3.5+ — En-têtes de Sécurité & TLS 1.3 ML-KEM (%s)
server {
    listen 443 ssl http2;
    server_name %s;

    server_tokens off;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    fastcgi_hide_header X-Powered-By;
    proxy_hide_header X-Powered-By;
}`, domainName, domainName)

	caddy := fmt.Sprintf(`# Caddy 2.9+ (Go 1.24+ X25519MLKEM768 natif) — Caddyfile (%s)
%s {
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        -Server
        -X-Powered-By
    }
}`, domainName, domainName)

	apachePhp := `# Apache 2.4 & php.ini — Durcissement Hôte & Neutralisation RCE PHP-CGI / PHP2Shell
# 1. /etc/php/8.3/fpm/php.ini :
expose_php = Off
allow_url_include = Off
allow_url_fopen = Off
enable_dl = Off
post_max_size = 32K
max_input_vars = 1000
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,show_source

# 2. /etc/apache2/conf-available/security.conf :
ServerTokens Prod
ServerSignature Off
Header always unset X-Powered-By
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"`

	return map[string]string{
		"traefik":    traefik,
		"nginx":      nginx,
		"caddy":      caddy,
		"apache_php": apachePhp,
	}
}

func (s *AuditService) GetScheduleConfig() AuditScheduleConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.schedule
}

func (s *AuditService) UpdateScheduleConfig(enabled bool, targetDomain string, intervalHours int) AuditScheduleConfig {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.schedule.Enabled = enabled
	if strings.TrimSpace(targetDomain) != "" {
		s.schedule.TargetDomain = scanner.NormalizeDomain(targetDomain)
	}
	if intervalHours >= 1 && intervalHours <= 168 {
		s.schedule.IntervalHours = intervalHours
	}
	now := time.Now().UTC()
	s.schedule.NextRunAt = now.Add(time.Duration(s.schedule.IntervalHours) * time.Hour).Format(time.RFC3339)
	return s.schedule
}

func (s *AuditService) GetLatest(rawDomain string) (*domain.PassiveAuditResult, error) {
	domainName := scanner.NormalizeDomain(rawDomain)
	if domainName == "" {
		domainName = "localhost"
	}

	if s.db == nil {
		res := scanner.RunPassiveDomainScan(nil, domainName)
		return &res, nil
	}

	row, err := s.db.QueryRow(fmt.Sprintf(`
		SELECT id, domain, overall_eco_score, overall_eco_grade, security_score, security_grade,
		       pages_scanned, tech_stack, cve_warnings, headers_analysis, dns_analysis, pages_detail,
		       is_verified_owner, created_at
		FROM passive_domain_audits
		WHERE domain = %s
		ORDER BY created_at DESC
		LIMIT 1;`,
		database.QuoteLiteral(domainName),
	))
	if err != nil || row.String("domain") == "" {
		res := scanner.RunPassiveDomainScan(s.db, domainName)
		return &res, nil
	}

	res := domain.PassiveAuditResult{
		AuditID:         row.String("id"),
		Domain:          row.String("domain"),
		ScannedAt:       row.String("created_at"),
		OverallEcoScore: row.Float("overall_eco_score"),
		OverallEcoGrade: row.String("overall_eco_grade"),
		SecurityScore:   row.Int("security_score"),
		SecurityGrade:   row.String("security_grade"),
		PagesScanned:    row.Int("pages_scanned"),
		IsVerifiedOwner: row.Bool("is_verified_owner"),
	}

	_ = json.Unmarshal([]byte(row.String("tech_stack")), &res.TechStack)
	_ = json.Unmarshal([]byte(row.String("cve_warnings")), &res.CVEWarnings)
	_ = json.Unmarshal([]byte(row.String("headers_analysis")), &res.HeadersAnalysis)
	_ = json.Unmarshal([]byte(row.String("dns_analysis")), &res.DNS)
	_ = json.Unmarshal([]byte(row.String("pages_detail")), &res.PagesDetail)

	res.EcoIndexScore = res.OverallEcoScore
	res.EcoIndexGrade = res.OverallEcoGrade
	res.AvgGCO2ePerVisit = 1.35
	res.AvgGCO2Grams = 1.35
	res.AvgWaterCL = 2.05
	res.DetectedTech = res.TechStack
	res.Pages = res.PagesDetail
	res.OwnershipVerified = res.IsVerifiedOwner

	return &res, nil
}

func (s *AuditService) RequestVerification(domainName, email, company string) (map[string]any, error) {
	return scanner.CreateOwnershipVerification(s.db, domainName, email, company)
}

func (s *AuditService) VerifyOwnership(domainName, email string, contractAccepted bool, signerIP, userAgent string) (map[string]any, error) {
	return scanner.VerifyDomainAndRunDeepAudit(s.db, domainName, email, contractAccepted, signerIP, userAgent)
}
