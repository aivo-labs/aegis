package service

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aivo-labs/aegis/backend/internal/database"
	"github.com/aivo-labs/aegis/backend/internal/domain"
)

type TelemetryService struct {
	db                *database.PgClient
	protectionService *ProtectionService
	defaultTenantID   string
}

func NewTelemetryService(db *database.PgClient, protectionService *ProtectionService, defaultTenantID string) *TelemetryService {
	return &TelemetryService{
		db:                db,
		protectionService: protectionService,
		defaultTenantID:   defaultTenantID,
	}
}

func (s *TelemetryService) IngestEnergy(t domain.EnergyTelemetry) error {
	if s.db == nil {
		return nil
	}
	tenantID := t.TenantID
	if tenantID == "" {
		tenantID = s.defaultTenantID
	}
	hostname := t.Hostname
	if hostname == "" {
		hostname = "aegis-sovereign-node"
	}
	ip := t.IPAddress
	if ip == "" {
		ip = "127.0.0.1"
	}

	provider := t.Provider
	if provider == "" {
		provider = "ovhcloud"
	}

	// Upsert node dans infrastructure_nodes
	nodeUpsertSQL := fmt.Sprintf(`
		INSERT INTO infrastructure_nodes (tenant_id, hostname, ip_address, provider, os_info, scaphandre_agent_version, status, updated_at)
		VALUES (%s, %s, %s, %s, 'Linux KVM VPS (Kernel /proc/stat & RAPL)', 'v4.3.0', 'active', CURRENT_TIMESTAMP)
		ON CONFLICT (tenant_id, hostname) DO UPDATE SET
			ip_address = EXCLUDED.ip_address,
			provider = EXCLUDED.provider,
			os_info = EXCLUDED.os_info,
			status = 'active',
			updated_at = CURRENT_TIMESTAMP
		RETURNING id;`,
		database.QuoteLiteral(tenantID),
		database.QuoteLiteral(hostname),
		database.QuoteLiteral(ip),
		database.QuoteLiteral(provider),
	)

	nodeRow, _ := s.db.QueryRow(nodeUpsertSQL)
	nodeID := ""
	if nodeRow != nil {
		nodeID = strings.TrimSpace(nodeRow.String("id"))
	}

	// 1er secours : Si RETURNING id n'a pas renvoyé de valeur, interroger par (tenant_id, hostname)
	if nodeID == "" {
		findRow, _ := s.db.QueryRow(fmt.Sprintf(
			"SELECT id FROM infrastructure_nodes WHERE tenant_id = %s AND hostname = %s LIMIT 1;",
			database.QuoteLiteral(tenantID),
			database.QuoteLiteral(hostname),
		))
		if findRow != nil {
			nodeID = strings.TrimSpace(findRow.String("id"))
		}
	}

	// 2ème secours : Chercher un nœud existant pour ce tenant
	if nodeID == "" {
		anyRow, _ := s.db.QueryRow(fmt.Sprintf(
			"SELECT id FROM infrastructure_nodes WHERE tenant_id = %s LIMIT 1;",
			database.QuoteLiteral(tenantID),
		))
		if anyRow != nil {
			nodeID = strings.TrimSpace(anyRow.String("id"))
		}
	}

	// 3ème secours : Insérer explicitement avec un UUID garanti
	if nodeID == "" {
		nodeID = "00000000-0000-0000-0000-000000000002"
		_ = s.db.Exec(fmt.Sprintf(`
			INSERT INTO infrastructure_nodes (id, tenant_id, hostname, ip_address, provider, status, updated_at)
			VALUES ('%s', %s, %s, %s, %s, 'active', CURRENT_TIMESTAMP)
			ON CONFLICT (tenant_id, hostname) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;`,
			nodeID,
			database.QuoteLiteral(tenantID),
			database.QuoteLiteral(hostname),
			database.QuoteLiteral(ip),
			database.QuoteLiteral(provider),
		))
	}

	insertSQL := fmt.Sprintf(`
		INSERT INTO telemetry_energy_metrics (
			node_id, tenant_id, cpu_power_watts, ram_power_watts, energy_consumed_joules, cpu_utilization_pct, memory_used_mb, timestamp
		) VALUES (
			'%s', %s, %f, %f, %f, %f, %d, CURRENT_TIMESTAMP
		);`,
		nodeID,
		database.QuoteLiteral(tenantID),
		t.CPUPowerWatts,
		t.RAMPowerWatts,
		t.EnergyConsumedJoules,
		t.CPUUtilizationPct,
		t.MemoryUsedMB,
	)

	return s.db.Exec(insertSQL)
}

func (s *TelemetryService) IngestIngress(t domain.IngressTelemetry) error {
	if s.db == nil {
		return nil
	}
	tenantID := t.TenantID
	if tenantID == "" {
		tenantID = s.defaultTenantID
	}
	clientIP := t.ClientIP
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	metaJSON, _ := json.Marshal(t.Metadata)
	if len(metaJSON) == 0 {
		metaJSON = []byte("{}")
	}

	insertSQL := fmt.Sprintf(`
		INSERT INTO security_audit_logs (
			tenant_id, client_ip, user_agent, http_method, request_uri, decision, http_status_returned, latency_ms, metadata, timestamp
		) VALUES (
			%s, %s, %s, %s, %s, %s, %d, %f, %s::jsonb, CURRENT_TIMESTAMP
		);`,
		database.QuoteLiteral(tenantID),
		database.QuoteLiteral(clientIP),
		database.QuoteLiteral(t.UserAgent),
		database.QuoteLiteral(t.HTTPMethod),
		database.QuoteLiteral(t.RequestURI),
		database.QuoteLiteral(t.Decision),
		t.HTTPStatusReturned,
		t.LatencyMs,
		database.QuoteLiteral(string(metaJSON)),
	)

	err := s.db.Exec(insertSQL)
	if err != nil {
		return err
	}

	// Auto-ban si seuil d'attaques dépassé (les simulations et flux auth ne déclenchent jamais d'auto-ban)
	isSimulated := false
	if t.Metadata != nil {
		if sim, ok := t.Metadata["simulated"].(bool); ok && sim {
			isSimulated = true
		}
	}
	isAuthRoute := strings.HasPrefix(t.RequestURI, "/api/auth/")
	if !isSimulated && !isAuthRoute && t.Decision == "BLOCK" && clientIP != "127.0.0.1" && clientIP != "" {
		s.checkAutoBan(clientIP, t.ThreatType)
	}

	return nil
}

func (s *TelemetryService) IngestEgress(t domain.EgressTelemetry) error {
	if s.db == nil {
		return nil
	}
	tenantID := t.TenantID
	if tenantID == "" {
		tenantID = s.defaultTenantID
	}
	clientIP := t.ClientIP
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	metaJSON, _ := json.Marshal(t.Metadata)
	if len(metaJSON) == 0 {
		metaJSON = []byte("{}")
	}

	insertSQL := fmt.Sprintf(`
		INSERT INTO egress_security_logs (
			tenant_id, client_ip, fqdn, domain_entropy, action, threat_type, confidence, latency_ms, metadata, timestamp
		) VALUES (
			%s, %s, %s, %f, %s, %s, %f, %f, %s::jsonb, CURRENT_TIMESTAMP
		);`,
		database.QuoteLiteral(tenantID),
		database.QuoteLiteral(clientIP),
		database.QuoteLiteral(t.FQDN),
		t.DomainEntropy,
		database.QuoteLiteral(t.Action),
		database.QuoteLiteral(t.ThreatType),
		t.Confidence,
		t.LatencyMs,
		database.QuoteLiteral(string(metaJSON)),
	)

	return s.db.Exec(insertSQL)
}

func isPrivateOrLoopbackIP(ip string) bool {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == "198.51.100.10" {
		return true
	}
	if strings.HasPrefix(ip, "172.17.") || strings.HasPrefix(ip, "172.18.") || strings.HasPrefix(ip, "172.19.") || strings.HasPrefix(ip, "172.20.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return true
	}
	return false
}

func (s *TelemetryService) checkAutoBan(clientIP, threatType string) {
	if s.db == nil || s.protectionService == nil || isPrivateOrLoopbackIP(clientIP) {
		return
	}
	retentionCfg, _ := s.protectionService.GetRetention()
	threshold := retentionCfg.AutoBanThreshold
	if threshold <= 0 {
		threshold = 3
	}

	row, err := s.db.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) AS block_count
		FROM security_audit_logs
		WHERE client_ip = %s AND decision = 'BLOCK' AND timestamp >= NOW() - INTERVAL '1 hour';`,
		database.QuoteLiteral(clientIP),
	))
	if err == nil && row.Int("block_count") >= threshold {
		reason := fmt.Sprintf("Auto-Ban heuristique : %d attaques critiques interceptées en 1h (%s)", row.Int("block_count"), threatType)
		_ = s.protectionService.AddBan(clientIP, reason, "AUTO_BAN_HEURISTIC", 99)
	}
}
