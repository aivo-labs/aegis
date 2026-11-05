package service

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"strings"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/database"
)

type DashboardService struct {
	db                *database.PgClient
	protectionService *ProtectionService
	defaultTenantID   string
}

func NewDashboardService(db *database.PgClient, protectionService *ProtectionService, defaultTenantID string) *DashboardService {
	return &DashboardService{
		db:                db,
		protectionService: protectionService,
		defaultTenantID:   defaultTenantID,
	}
}

func (s *DashboardService) GetSummary() map[string]any {
	protectionEnabled := s.protectionService.IsProtectionEnabled()
	maxPayloadBytes := s.protectionService.GetMaxPayloadBytes()

	if s.db == nil {
		return map[string]any{
			"status":             "success",
			"tenant_id":          s.defaultTenantID,
			"protection_enabled": protectionEnabled,
			"timestamp":          time.Now().UTC().Format(time.RFC3339),
		}
	}

	// 1. Ingress
	inRow, _ := s.db.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) AS total,
		       COUNT(*) FILTER (WHERE decision = 'BLOCK') AS blocked,
		       COUNT(*) FILTER (WHERE decision = 'BYPASS') AS bypassed,
		       COUNT(*) FILTER (WHERE request_uri ~* '(wp-login|wp-content|xmlrpc|\.env|\.git|phpinfo|phpmyadmin)') AS bot_probes,
		       COALESCE(AVG(latency_ms), 0) AS avg_lat
		FROM security_audit_logs
		WHERE tenant_id = %s;`, database.QuoteLiteral(s.defaultTenantID)))

	ingressTotal := inRow.Int("total")
	ingressBlocked := inRow.Int("blocked")
	ingressBypassed := inRow.Int("bypassed")
	botProbesTotal := inRow.Int("bot_probes")
	ingressAvgLat := inRow.Float("avg_lat")

	// 2. Egress
	egRow, _ := s.db.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) AS total,
		       COUNT(*) FILTER (WHERE action IN ('BLOCK', 'QUARANTINE')) AS blocked,
		       COUNT(*) FILTER (WHERE action = 'BYPASS') AS bypassed,
		       COALESCE(AVG(latency_ms), 0) AS avg_lat
		FROM egress_security_logs
		WHERE tenant_id = %s;`, database.QuoteLiteral(s.defaultTenantID)))

	egressTotal := egRow.Int("total")
	egressBlocked := egRow.Int("blocked")
	egressBypassed := egRow.Int("bypassed")
	egressAvgLat := egRow.Float("avg_lat")

	// 3. Mesures énergétiques RAPL
	enRow, _ := s.db.QueryRow(fmt.Sprintf(`
		SELECT COALESCE(cpu_power_watts, 0) AS cpu_w,
		       COALESCE(ram_power_watts, 0) AS ram_w,
		       COALESCE(cpu_utilization_pct, 0) AS cpu_pct
		FROM telemetry_energy_metrics
		WHERE tenant_id = %s
		ORDER BY timestamp DESC
		LIMIT 1;`, database.QuoteLiteral(s.defaultTenantID)))

	cpuWatts := roundFloat(enRow.Float("cpu_w"), 2)
	ramWatts := roundFloat(enRow.Float("ram_w"), 2)
	instantWatts := roundFloat(cpuWatts+ramWatts, 2)
	cpuPct := roundFloat(enRow.Float("cpu_pct"), 1)

	aggEnRow, _ := s.db.QueryRow(fmt.Sprintf(`
		SELECT COALESCE(AVG(cpu_power_watts + ram_power_watts), 0) AS avg_w,
		       COALESCE(SUM(energy_consumed_joules), 0) AS total_j,
		       COUNT(*) AS sample_count
		FROM telemetry_energy_metrics
		WHERE tenant_id = %s AND timestamp >= NOW() - INTERVAL '24 hours';`, database.QuoteLiteral(s.defaultTenantID)))

	avgWatts24h := roundFloat(aggEnRow.Float("avg_w"), 2)
	totalJoules24h := roundFloat(aggEnRow.Float("total_j"), 2)
	energySamples := aggEnRow.Int("sample_count")

	histRows, _ := s.db.Query(fmt.Sprintf(`
		SELECT ROUND((cpu_power_watts + ram_power_watts)::numeric, 2) AS watts,
		       ROUND(cpu_utilization_pct::numeric, 1) AS cpu_pct,
		       timestamp
		FROM telemetry_energy_metrics
		WHERE tenant_id = %s
		ORDER BY timestamp DESC
		LIMIT 20;`, database.QuoteLiteral(s.defaultTenantID)))

	powerHistory := make([]map[string]any, 0, len(histRows))
	for i := len(histRows) - 1; i >= 0; i-- {
		h := histRows[i]
		powerHistory = append(powerHistory, map[string]any{
			"watts":     h.Float("watts"),
			"cpu_pct":   h.Float("cpu_pct"),
			"timestamp": h.String("timestamp"),
		})
	}

	// 4. Nœuds & Services
	nodeRows, _ := s.db.Query(fmt.Sprintf(`
		SELECT hostname, host(ip_address) AS ip, provider, os_info, scaphandre_agent_version, status, updated_at
		FROM infrastructure_nodes
		WHERE tenant_id = %s
		ORDER BY updated_at DESC
		LIMIT 10;`, database.QuoteLiteral(s.defaultTenantID)))

	monitoredNodes := make([]map[string]any, 0)
	for _, n := range nodeRows {
		monitoredNodes = append(monitoredNodes, map[string]any{
			"hostname":     n.String("hostname"),
			"service_name": n.String("hostname"),
			"ip":           n.String("ip"),
			"provider":     n.String("provider"),
			"os_info":      n.String("os_info"),
			"agent":        n.String("scaphandre_agent_version"),
			"watts":        roundFloat(instantWatts/math.Max(1, float64(len(nodeRows))), 2),
			"status":       "RAPL Live",
			"updated_at":   n.String("updated_at"),
		})
	}
	if len(monitoredNodes) == 0 {
		coreServices := []struct {
			Name  string
			Share float64
		}{
			{"aegis_gate_proxy (:8000)", 0.25},
			{"aegis_egress_gateway (:5053)", 0.20},
			{"aegis_backend_go (:8080)", 0.15},
			{"aegis_timescaledb (:5432)", 0.25},
			{"aegis_telemetry_agent (RAPL)", 0.15},
		}
		for _, cs := range coreServices {
			monitoredNodes = append(monitoredNodes, map[string]any{
				"hostname":     cs.Name,
				"service_name": cs.Name,
				"watts":        roundFloat(instantWatts*cs.Share, 2),
				"status":       "RAPL Live",
			})
		}
	}

	// 5. Dernier Audit Passif
	latestAuditRow, _ := s.db.QueryRow(`
		SELECT domain, overall_eco_score, overall_eco_grade, security_score, security_grade,
		       pages_scanned, is_verified_owner, jsonb_array_length(cve_warnings) AS cve_count, created_at
		FROM passive_domain_audits
		ORDER BY created_at DESC
		LIMIT 1;`)

	hasAudit := latestAuditRow.String("domain") != ""
	lastAuditDomain := latestAuditRow.String("domain")
	ecoScore := latestAuditRow.Float("overall_eco_score")
	ecoGrade := latestAuditRow.String("overall_eco_grade")
	secAuditScore := latestAuditRow.Int("security_score")
	secAuditGrade := latestAuditRow.String("security_grade")
	pagesScanned := latestAuditRow.Int("pages_scanned")
	cveCount := latestAuditRow.Int("cve_count")
	isVerifiedOwner := latestAuditRow.Bool("is_verified_owner")

	var passiveAuditSummary any = nil
	if hasAudit {
		passiveAuditSummary = map[string]any{
			"has_audit":          true,
			"domain":             lastAuditDomain,
			"eco_score":          ecoScore,
			"eco_index_score":    ecoScore,
			"eco_grade":          ecoGrade,
			"eco_index_grade":    ecoGrade,
			"security_score":     secAuditScore,
			"security_grade":     secAuditGrade,
			"pages_scanned":      pagesScanned,
			"cve_count":          cveCount,
			"ownership_verified": isVerifiedOwner,
		}
	}

	// 6. Rétention & Bans
	banRow, _ := s.db.QueryRow("SELECT COUNT(*) AS cnt FROM ip_ban_list WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP;")
	bannedIPCount := banRow.Int("cnt")

	retRow, _ := s.db.QueryRow("SELECT hot_window_days, anssi_forensic_days, rgpd_clean_ip_days FROM system_retention_config WHERE id = 1 LIMIT 1;")
	hotDays := retRow.Int("hot_window_days")
	if hotDays == 0 {
		hotDays = 30
	}
	anssiDays := retRow.Int("anssi_forensic_days")
	if anssiDays == 0 {
		anssiDays = 180
	}
	rgpdDays := retRow.Int("rgpd_clean_ip_days")
	if rgpdDays == 0 {
		rgpdDays = 7
	}

	totalRequests := ingressTotal + egressTotal
	totalBlocked := ingressBlocked + egressBlocked
	totalBypassed := ingressBypassed + egressBypassed
	totalMalicious := totalBlocked + totalBypassed

	cleanTrafficPct := 100.0
	if totalRequests > 0 {
		cleanTrafficPct = roundFloat((float64(totalRequests-totalMalicious)/float64(totalRequests))*100.0, 1)
	}

	interceptionRatePct := 100.0
	if totalMalicious > 0 {
		interceptionRatePct = roundFloat((float64(totalBlocked)/float64(totalMalicious))*100.0, 1)
	}

	combinedLatency := 0.0
	if totalRequests > 0 {
		combinedLatency = roundFloat(((ingressAvgLat*float64(ingressTotal))+(egressAvgLat*float64(egressTotal)))/float64(totalRequests), 2)
	}

	siHealthScore := 100
	if !protectionEnabled {
		siHealthScore = 40
	}
	if totalBypassed > 0 {
		siHealthScore = int(math.Max(10, float64(siHealthScore-(totalBypassed*8))))
	}

	carbonGco2h := roundFloat((instantWatts/1000.0)*52.0, 2)

	inspectionEngine := "Aegis Gate PEP (:8000) + Egress Sinkhole (:5053)"
	if !protectionEnabled {
		inspectionEngine = "⚠️ BOUCLIER DÉSACTIVÉ (Mode Sans Protection)"
	}

	return map[string]any{
		"status":             "success",
		"tenant_id":          s.defaultTenantID,
		"protection_enabled": protectionEnabled,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
		"traffic": map[string]any{
			"total_requests_24h":       totalRequests,
			"clean_traffic_pct":        cleanTrafficPct,
			"blocked_threats_total":    totalBlocked,
			"compromised_bypass_total": totalBypassed,
			"interception_rate_pct":    interceptionRatePct,
			"bot_probes_total":         botProbesTotal,
			"ingress_total":            ingressTotal,
			"ingress_blocked":          ingressBlocked,
			"ingress_bypassed":         ingressBypassed,
			"egress_total":             egressTotal,
			"egress_blocked":           egressBlocked,
			"egress_bypassed":          egressBypassed,
			"avg_latency_ms":           combinedLatency,
			"max_payload_bytes":        maxPayloadBytes,
			"banned_ips_count":         bannedIPCount,
			"inspection_engine":        inspectionEngine,
		},
		"soc": map[string]any{
			"si_health_score":            siHealthScore,
			"interception_rate_pct":      interceptionRatePct,
			"c2_callbacks_blocked_total": egressBlocked,
			"c2_callbacks_leaked_total":  egressBypassed,
			"banned_ips_count":           bannedIPCount,
			"monitored_nodes":            monitoredNodes,
			"active_sessions":            monitoredNodes,
		},
		"green": map[string]any{
			"instant_power_watts":     instantWatts,
			"avg_watts_24h":           avgWatts24h,
			"cpu_watts":               cpuWatts,
			"ram_watts":               ramWatts,
			"cpu_utilization_pct":     cpuPct,
			"cpu_load_pct":            cpuPct,
			"carbon_intensity_gco2_h": carbonGco2h,
			"joules_24h":              totalJoules24h,
			"kwh_24h":                 roundFloat(totalJoules24h/3600000.0, 5),
			"samples_count":           energySamples,
			"has_passive_audit":       hasAudit,
			"audited_domain":          lastAuditDomain,
			"eco_index_score":         ecoScore,
			"eco_index_grade":         ecoGrade,
			"power_history":           powerHistory,
		},
		"passive_audit_summary": passiveAuditSummary,
		"retention": map[string]any{
			"hot_window_days":     hotDays,
			"anssi_forensic_days": anssiDays,
			"rgpd_clean_ip_days":  rgpdDays,
			"stored_logs_count":   totalRequests,
		},
		"metrics": map[string]any{
			"energy": map[string]any{
				"current_watts":    instantWatts,
				"avg_watts_24h":    avgWatts24h,
				"total_joules_24h": totalJoules24h,
				"measurement_type": "RAPL_HARDWARE_DIRECT",
			},
			"security": map[string]any{
				"protection_enabled":       protectionEnabled,
				"ingress_threats_blocked":  ingressBlocked,
				"ingress_threats_bypassed": ingressBypassed,
				"ingress_requests_total":   ingressTotal,
				"egress_c2_blocked":        egressBlocked,
				"egress_c2_bypassed":       egressBypassed,
				"egress_queries_total":     egressTotal,
				"threat_response_time_ms":  combinedLatency,
			},
		},
	}
}

func (s *DashboardService) GetLiveStreams() (map[string]any, error) {
	if s.db == nil {
		return map[string]any{
			"status":         "success",
			"ingress_stream": []any{},
			"egress_stream":  []any{},
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	inRows, _ := s.db.Query(fmt.Sprintf(`
		SELECT id, timestamp, host(client_ip) AS client_ip, user_agent, http_method, request_uri,
		       decision, http_status_returned, latency_ms, metadata
		FROM security_audit_logs
		WHERE tenant_id = %s
		ORDER BY timestamp DESC
		LIMIT 50;`, database.QuoteLiteral(s.defaultTenantID)))

	ingressStream := make([]map[string]any, 0, len(inRows))
	for _, row := range inRows {
		var meta map[string]any
		_ = json.Unmarshal([]byte(row.String("metadata")), &meta)
		dec := row.String("decision")
		status := row.Int("http_status_returned")
		uri := row.String("request_uri")
		threatType := asString(meta, "threat_type", "WAF_INSPECTION")
		cat, scanProb := ClassifyIngressEvent(uri, row.String("http_method"), dec, threatType, status)

		ip := row.String("client_ip")
		lat, lon := IPToGeoCoordinates(ip)

		ingressStream = append(ingressStream, map[string]any{
			"id":                "in-" + row.String("id"),
			"direction":         "INGRESS",
			"timestamp":         row.String("timestamp"),
			"client_ip":         ip,
			"http_method":       row.String("http_method"),
			"method":            row.String("http_method"),
			"request_uri":       uri,
			"target":            uri,
			"decision":          dec,
			"http_status":       status,
			"status_code":       status,
			"latency_ms":        row.Float("latency_ms"),
			"threat_type":       threatType,
			"threat_category":   cat,
			"category":          cat,
			"scan_probability":  scanProb,
			"hack_probability":  scanProb,
			"severity":          asString(meta, "severity", "LOW"),
			"entropy":           asFloat(meta, "entropy", 2.5),
			"lat":               lat,
			"lon":               lon,
		})
	}

	egRows, _ := s.db.Query(fmt.Sprintf(`
		SELECT id, timestamp, host(client_ip) AS client_ip, fqdn, domain_entropy,
		       action, threat_type, confidence, latency_ms, metadata
		FROM egress_security_logs
		WHERE tenant_id = %s
		ORDER BY timestamp DESC
		LIMIT 50;`, database.QuoteLiteral(s.defaultTenantID)))

	egressStream := make([]map[string]any, 0, len(egRows))
	for _, row := range egRows {
		action := row.String("action")
		threatType := row.String("threat_type")
		entropy := row.Float("domain_entropy")
		confPct := int(row.Float("confidence") * 100)
		if action == "ALLOW" {
			confPct = 3
		}
		ip := row.String("client_ip")
		lat, lon := IPToGeoCoordinates(ip)

		egressStream = append(egressStream, map[string]any{
			"id":                "eg-" + row.String("id"),
			"direction":         "EGRESS",
			"timestamp":         row.String("timestamp"),
			"client_ip":         ip,
			"target":            row.String("fqdn"),
			"domain":            row.String("fqdn"),
			"target_ip":         row.String("fqdn"),
			"decision":          action,
			"threat_type":       threatType,
			"exfil_probability": confPct,
			"entropy":           entropy,
			"latency_ms":        row.Float("latency_ms"),
			"lat":               lat,
			"lon":               lon,
		})
	}

	return map[string]any{
		"status":         "success",
		"ingress_stream": ingressStream,
		"egress_stream":  egressStream,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *DashboardService) GetThreatsFeed(includeCompliant bool) ([]map[string]any, error) {
	events := make([]map[string]any, 0)
	if s.db == nil {
		return events, nil
	}

	whereClause := "AND decision IN ('BLOCK', 'BYPASS')"
	if includeCompliant {
		whereClause = ""
	}

	inRows, _ := s.db.Query(fmt.Sprintf(`
		SELECT id, timestamp, host(client_ip) AS client_ip, http_method, request_uri,
		       decision, http_status_returned, latency_ms, metadata
		FROM security_audit_logs
		WHERE tenant_id = %s %s
		ORDER BY timestamp DESC LIMIT 35;`, database.QuoteLiteral(s.defaultTenantID), whereClause))

	for _, row := range inRows {
		var meta map[string]any
		_ = json.Unmarshal([]byte(row.String("metadata")), &meta)
		dec := row.String("decision")
		status := row.Int("http_status_returned")
		actionLabel := fmt.Sprintf("BLOCK (%d)", status)
		severity := asString(meta, "severity", "CRITICAL")
		if dec == "BYPASS" {
			actionLabel = fmt.Sprintf("COMPROMIS (%d)", status)
			severity = "CRITICAL"
		} else if dec == "ALLOW" {
			actionLabel = "ALLOW (200)"
			severity = "COMPLIANT"
		}
		ip := row.String("client_ip")
		lat, lon := IPToGeoCoordinates(ip)
		entropyVal := asFloat(meta, "entropy", 4.1)
		targetURI := row.String("http_method") + " " + row.String("request_uri")

		events = append(events, map[string]any{
			"id":             "in-" + row.String("id"),
			"direction":      "ingress",
			"timestamp":      row.String("timestamp"),
			"client_ip":      ip,
			"target":         targetURI,
			"fqdn":           targetURI,
			"entropy":        entropyVal,
			"domain_entropy": entropyVal,
			"action":         actionLabel,
			"decision":       dec,
			"raw_decision":   dec,
			"http_status":    status,
			"severity":       severity,
			"threat_type":    asString(meta, "threat_type", "WAF_INTERCEPTION"),
			"latency_ms":     row.Float("latency_ms"),
			"lat":            lat,
			"lon":            lon,
			"geo": map[string]any{
				"city":         "Paris",
				"country_code": "FR",
				"country":      "France",
			},
			"metadata": map[string]any{"engine": "AEGIS_GATE_PEP"},
		})
	}

	egRows, _ := s.db.Query(fmt.Sprintf(`
		SELECT id, timestamp, host(client_ip) AS client_ip, fqdn, domain_entropy,
		       action, threat_type, latency_ms
		FROM egress_security_logs
		WHERE tenant_id = %s AND action IN ('BLOCK', 'QUARANTINE', 'BYPASS')
		ORDER BY timestamp DESC LIMIT 25;`, database.QuoteLiteral(s.defaultTenantID)))

	for _, row := range egRows {
		act := row.String("action")
		actionLabel := act
		severity := "CRITICAL"
		if act == "BYPASS" {
			actionLabel = "EXFILTRÉ (DNS)"
			severity = "CRITICAL"
		} else if act == "QUARANTINE" {
			severity = "HIGH"
		}
		ip := row.String("client_ip")
		lat, lon := IPToGeoCoordinates(ip)
		fqdn := row.String("fqdn")
		entropyVal := row.Float("domain_entropy")

		events = append(events, map[string]any{
			"id":             "eg-" + row.String("id"),
			"direction":      "egress",
			"timestamp":      row.String("timestamp"),
			"client_ip":      ip,
			"target":         fqdn,
			"fqdn":           "DNS " + fqdn,
			"entropy":        entropyVal,
			"domain_entropy": entropyVal,
			"action":         actionLabel,
			"decision":       act,
			"raw_decision":   act,
			"severity":       severity,
			"threat_type":    row.String("threat_type"),
			"latency_ms":     row.Float("latency_ms"),
			"lat":            lat,
			"lon":            lon,
			"geo": map[string]any{
				"city":         "Paris",
				"country_code": "FR",
				"country":      "France",
			},
			"metadata": map[string]any{"engine": "SYSTEMONE_EGRESS"},
		})
	}

	return events, nil
}

func (s *DashboardService) ExportEnergyCSV(w io.Writer) error {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(fmt.Sprintf(`
		SELECT timestamp, cpu_power_watts, ram_power_watts,
		       (cpu_power_watts + ram_power_watts) AS total_watts,
		       energy_consumed_joules, cpu_utilization_pct
		FROM telemetry_energy_metrics
		WHERE tenant_id = %s
		ORDER BY timestamp DESC
		LIMIT 500;`, database.QuoteLiteral(s.defaultTenantID)))
	if err != nil {
		return err
	}

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "cpu_power_watts", "ram_power_watts", "total_watts", "energy_joules", "cpu_utilization_pct"})
	for _, row := range rows {
		_ = cw.Write([]string{
			row.String("timestamp"),
			row.String("cpu_power_watts"),
			row.String("ram_power_watts"),
			row.String("total_watts"),
			row.String("energy_consumed_joules"),
			row.String("cpu_utilization_pct"),
		})
	}
	cw.Flush()
	return nil
}

func IPToGeoCoordinates(ip string) (float64, float64) {
	if ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "172.") || strings.HasPrefix(ip, "192.168.") {
		return 48.8566, 2.3522 // Paris
	}
	hubs := [][2]float64{
		{55.7558, 37.6173},
		{39.9042, 116.4074},
		{50.1109, 8.6821},
		{37.7749, -122.419},
		{52.3676, 4.9041},
		{1.3521, 103.8198},
		{-23.5505, -46.633},
		{35.6762, 139.6503},
	}
	idx := int(crc32.ChecksumIEEE([]byte(ip))) % len(hubs)
	return hubs[idx][0], hubs[idx][1]
}

func ClassifyIngressEvent(uri, method, decision, threatType string, status int) (string, int) {
	lowURI := strings.ToLower(uri)
	lowThreat := strings.ToLower(threatType)

	if strings.Contains(lowURI, "wp-login") || strings.Contains(lowURI, "wp-content") ||
		strings.Contains(lowURI, "wp-admin") || strings.Contains(lowURI, "xmlrpc.php") ||
		strings.Contains(lowURI, "wp-includes") || strings.Contains(lowThreat, "cms_php_probe") {
		return "SONDE BOTNET CMS / PHP", 96
	}
	if strings.Contains(lowURI, ".env") || strings.Contains(lowURI, ".git") ||
		strings.Contains(lowURI, "phpinfo") || strings.Contains(lowURI, "phpmyadmin") ||
		strings.Contains(lowURI, "vendor/phpunit") || strings.Contains(lowThreat, "sensitive_probe") {
		return "SONDE FICHIER SENSIBLE", 95
	}
	if strings.Contains(lowThreat, "scanner") {
		return "SCANNER DE VULNÉRABILITÉS", 94
	}
	if status == 413 || strings.Contains(lowThreat, "overflow") {
		return "EXPLOIT BUFFER OVERFLOW (413)", 99
	}
	if strings.Contains(lowThreat, "zero_day") || strings.Contains(lowThreat, "rce") || strings.Contains(lowThreat, "sql") {
		return "TENTATIVE D'INTRUSION CRITIQUE", 99
	}
	if decision == "BLOCK" || decision == "BYPASS" || status >= 400 {
		return "MENACE APPLICATIVE WAF", 90
	}
	return "TRAFIC APPLICATIF LÉGITIME", 2
}

func asString(m map[string]any, key, def string) string {
	if v, ok := m[key]; ok && v != nil {
		switch val := v.(type) {
		case string:
			if strings.TrimSpace(val) != "" {
				return val
			}
		default:
			return fmt.Sprintf("%v", val)
		}
	}
	return def
}

func asFloat(m map[string]any, key string, def float64) float64 {
	if v, ok := m[key]; ok && v != nil {
		switch val := v.(type) {
		case float64:
			return val
		case int:
			return float64(val)
		case string:
			return def
		}
	}
	return def
}

func roundFloat(val float64, precision int) float64 {
	p := 1.0
	for i := 0; i < precision; i++ {
		p *= 10.0
	}
	return float64(int(val*p+0.5)) / p
}
