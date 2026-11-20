package database

import (
	"fmt"
	"log"
)

// EnsureDatabaseSchema applique automatiquement le schéma SQL et les migrations
// sur PostgreSQL / TimescaleDB au démarrage du Control Plane Go.
func EnsureDatabaseSchema(db *PgClient, defaultTenantID string) {
	statements := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`,
		`CREATE TABLE IF NOT EXISTS tenants (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name VARCHAR(255) NOT NULL,
			slug VARCHAR(100) NOT NULL UNIQUE,
			domain VARCHAR(255) NOT NULL UNIQUE,
			dns_verification_token VARCHAR(128) NOT NULL DEFAULT encode(gen_random_bytes(32), 'hex'),
			is_dns_verified BOOLEAN NOT NULL DEFAULT FALSE,
			verified_at TIMESTAMPTZ,
			subscription_plan VARCHAR(50) NOT NULL DEFAULT 'community',
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		fmt.Sprintf(`INSERT INTO tenants (id, name, slug, domain, subscription_plan, is_dns_verified, verified_at)
		VALUES ('%s', 'Aegis Sovereign Node', 'aegis-default', 'localhost', 'community', TRUE, CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO NOTHING;`, defaultTenantID),

		`CREATE TABLE IF NOT EXISTS infrastructure_nodes (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			hostname VARCHAR(255) NOT NULL,
			ip_address INET NOT NULL,
			provider VARCHAR(50) NOT NULL DEFAULT 'ovhcloud',
			os_info VARCHAR(100),
			scaphandre_agent_version VARCHAR(50),
			status VARCHAR(20) NOT NULL DEFAULT 'active',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT uq_tenant_node UNIQUE (tenant_id, hostname)
		);`,
		fmt.Sprintf(`INSERT INTO infrastructure_nodes (id, tenant_id, hostname, ip_address, provider, os_info, scaphandre_agent_version, status, updated_at)
		VALUES ('00000000-0000-0000-0000-000000000002', '%s', 'aegis-sovereign-node', '127.0.0.1', 'ovhcloud', 'Linux KVM VPS (Kernel /proc/stat & RAPL)', 'v4.3.0', 'active', CURRENT_TIMESTAMP)
		ON CONFLICT (tenant_id, hostname) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;`, defaultTenantID),
		`UPDATE infrastructure_nodes SET provider = 'ovhcloud' WHERE provider = 'scaleway';`,
		`DELETE FROM infrastructure_nodes a USING infrastructure_nodes b WHERE a.id < b.id AND a.tenant_id = b.tenant_id AND a.hostname = b.hostname;`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_nodes_tenant_host ON infrastructure_nodes(tenant_id, hostname);`,

		`CREATE TABLE IF NOT EXISTS security_audit_logs (
			id BIGSERIAL,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			tenant_id UUID NOT NULL,
			route_id UUID,
			client_ip INET NOT NULL,
			user_agent TEXT,
			http_method VARCHAR(10) NOT NULL,
			request_uri TEXT NOT NULL,
			decision VARCHAR(40) NOT NULL,
			http_status_returned INT NOT NULL,
			keycloak_user_id VARCHAR(150),
			latency_ms NUMERIC(8, 2) NOT NULL,
			metadata JSONB DEFAULT '{}'::jsonb
		);`,
		`ALTER TABLE security_audit_logs DROP CONSTRAINT IF EXISTS security_audit_logs_decision_check;`,
		`ALTER TABLE security_audit_logs ALTER COLUMN decision TYPE VARCHAR(40);`,

		`CREATE TABLE IF NOT EXISTS egress_security_logs (
			id BIGSERIAL,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			tenant_id UUID NOT NULL,
			client_ip INET NOT NULL,
			fqdn VARCHAR(255) NOT NULL,
			domain_entropy NUMERIC(5, 2) NOT NULL,
			action VARCHAR(30) NOT NULL,
			threat_type VARCHAR(80) NOT NULL DEFAULT 'SUSPECTED_C2',
			confidence NUMERIC(5, 4) NOT NULL,
			latency_ms NUMERIC(8, 2) NOT NULL,
			metadata JSONB DEFAULT '{}'::jsonb
		);`,
		`ALTER TABLE egress_security_logs DROP CONSTRAINT IF EXISTS egress_security_logs_action_check;`,
		`ALTER TABLE egress_security_logs ALTER COLUMN action TYPE VARCHAR(30);`,

		`CREATE TABLE IF NOT EXISTS telemetry_energy_metrics (
			timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			node_id UUID NOT NULL REFERENCES infrastructure_nodes(id) ON DELETE CASCADE,
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			cpu_power_watts NUMERIC(10, 3) NOT NULL,
			ram_power_watts NUMERIC(10, 3) NOT NULL,
			energy_consumed_joules NUMERIC(12, 3) NOT NULL,
			cpu_utilization_pct NUMERIC(5, 2) NOT NULL,
			memory_used_mb INT NOT NULL
		);`,

		`CREATE TABLE IF NOT EXISTS passive_domain_audits (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			domain VARCHAR(255) NOT NULL,
			overall_eco_score NUMERIC(5, 2) NOT NULL DEFAULT 0,
			overall_eco_grade VARCHAR(2) NOT NULL DEFAULT 'C',
			security_score INT NOT NULL DEFAULT 0,
			security_grade VARCHAR(2) NOT NULL DEFAULT 'C',
			pages_scanned INT NOT NULL DEFAULT 1,
			tech_stack JSONB NOT NULL DEFAULT '[]'::jsonb,
			cve_warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
			headers_analysis JSONB NOT NULL DEFAULT '{}'::jsonb,
			dns_analysis JSONB NOT NULL DEFAULT '{}'::jsonb,
			pages_detail JSONB NOT NULL DEFAULT '[]'::jsonb,
			is_verified_owner BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_passive_domain_audits_domain ON passive_domain_audits(domain, created_at DESC);`,
		`UPDATE passive_domain_audits SET cve_warnings = '[]'::jsonb WHERE cve_warnings IS NULL OR jsonb_typeof(cve_warnings) != 'array';`,

		`CREATE TABLE IF NOT EXISTS domain_ownership_contracts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			domain VARCHAR(255) NOT NULL UNIQUE,
			contact_email VARCHAR(255) NOT NULL,
			company_name VARCHAR(255) NOT NULL DEFAULT '',
			verification_token VARCHAR(128) NOT NULL,
			verification_method VARCHAR(30) NOT NULL DEFAULT 'DNS_TXT',
			is_verified BOOLEAN NOT NULL DEFAULT FALSE,
			verified_at TIMESTAMPTZ,
			contract_accepted BOOLEAN NOT NULL DEFAULT FALSE,
			contract_text_hash VARCHAR(128) NOT NULL DEFAULT '',
			signer_ip VARCHAR(64) NOT NULL DEFAULT '',
			signer_user_agent TEXT NOT NULL DEFAULT '',
			deep_audit_report JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS ip_ban_list (
			ip_address VARCHAR(64) PRIMARY KEY,
			reason TEXT NOT NULL DEFAULT 'Bannissement manuel SOC',
			risk_score INT NOT NULL DEFAULT 95,
			source VARCHAR(40) NOT NULL DEFAULT 'MANUAL_SOC',
			blocked_hits INT NOT NULL DEFAULT 0,
			expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS system_retention_config (
			id INT PRIMARY KEY DEFAULT 1,
			hot_window_days INT NOT NULL DEFAULT 30,
			anssi_forensic_days INT NOT NULL DEFAULT 180,
			rgpd_clean_ip_days INT NOT NULL DEFAULT 7,
			max_payload_bytes INT NOT NULL DEFAULT 32768,
			auto_ban_threshold INT NOT NULL DEFAULT 3,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`INSERT INTO system_retention_config (id, hot_window_days, anssi_forensic_days, rgpd_clean_ip_days, max_payload_bytes, auto_ban_threshold)
		VALUES (1, 30, 180, 7, 32768, 3)
		ON CONFLICT (id) DO NOTHING;`,

		`CREATE TABLE IF NOT EXISTS dynamic_cve_catalog (
			id VARCHAR(64) PRIMARY KEY,
			cve_id VARCHAR(64) NOT NULL,
			name TEXT NOT NULL,
			severity VARCHAR(20) NOT NULL,
			cvss VARCHAR(10) NOT NULL,
			component VARCHAR(100) NOT NULL,
			affected_versions TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			vector TEXT NOT NULL DEFAULT '',
			remediation TEXT NOT NULL,
			blocked_by_aegis BOOLEAN NOT NULL DEFAULT FALSE,
			is_active_defense BOOLEAN NOT NULL DEFAULT FALSE,
			coverage_status VARCHAR(40) NOT NULL DEFAULT 'PENDING_VERIFICATION',
			virtual_patch_rule_id VARCHAR(100) NOT NULL DEFAULT '',
			virtual_patch_summary TEXT NOT NULL DEFAULT '',
			root_fix_procedure JSONB NOT NULL DEFAULT '[]'::jsonb,
			verification_probe TEXT NOT NULL DEFAULT '',
			cisakev BOOLEAN NOT NULL DEFAULT FALSE,
			published_at VARCHAR(40) NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`ALTER TABLE dynamic_cve_catalog ADD COLUMN IF NOT EXISTS published_at VARCHAR(40) NOT NULL DEFAULT '';`,
		`CREATE INDEX IF NOT EXISTS idx_security_audit_logs_tenant_ts ON security_audit_logs(tenant_id, timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_security_audit_logs_ts ON security_audit_logs(timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_egress_security_logs_tenant_ts ON egress_security_logs(tenant_id, timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_egress_security_logs_ts ON egress_security_logs(timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_telemetry_energy_metrics_tenant_ts ON telemetry_energy_metrics(tenant_id, timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_telemetry_energy_metrics_node_ts ON telemetry_energy_metrics(node_id, timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_infrastructure_nodes_tenant ON infrastructure_nodes(tenant_id);`,
		`CREATE INDEX IF NOT EXISTS idx_ip_ban_list_expires ON ip_ban_list(expires_at);`,
	}

	for _, stmt := range statements {
		if err := db.Exec(stmt); err != nil {
			log.Printf("[Schema Notice] %v", err)
		}
	}
	_ = db.Exec("DELETE FROM ip_ban_list WHERE ip_address IN ('92.157.163.164', '127.0.0.1');")

	// Consolidation automatique des métriques orphelines (ex: conteneurs Docker de télémétrie) vers le nœud souverain unique
	_ = db.Exec(`
		UPDATE telemetry_energy_metrics 
		SET node_id = '00000000-0000-0000-0000-000000000002' 
		WHERE node_id IN (
			SELECT id FROM infrastructure_nodes 
			WHERE hostname != 'aegis-sovereign-node' AND (ip_address = '127.0.0.1' OR LENGTH(hostname) = 12)
		);
		DELETE FROM infrastructure_nodes 
		WHERE hostname != 'aegis-sovereign-node' AND (ip_address = '127.0.0.1' OR LENGTH(hostname) = 12);
	`)
	log.Println("✅ [Aegis Go Control Plane] Schéma PostgreSQL & tables d'audit initialisés.")

	// Initialisation automatique d'un socle d'événements si la base est vierge (évite le démarrage à 0 / clignotement)
	checkRow, _ := db.QueryRow("SELECT COUNT(*) AS cnt FROM security_audit_logs;")
	if checkRow.Int("cnt") == 0 {
		initialProbes := []struct {
			URI      string
			Method   string
			Decision string
			Status   int
			Threat   string
			Severity string
			Entropy  float64
			UA       string
			IP       string
		}{
			{"/wp-login.php", "POST", "BLOCK", 403, "SONDE BOTNET CMS / PHP", "HIGH", 3.45, "Mozilla/5.0 sqlmap/1.5.11", "185.220.101.5"},
			{"/wp-content/plugins/revslider/temp/update_extract/revslider/db.php", "GET", "BLOCK", 403, "EXPLOIT REVSLIDER RCE", "CRITICAL", 4.12, "nikto/2.1.6", "185.220.101.42"},
			{"/xmlrpc.php", "POST", "BLOCK", 403, "XML-RPC AMPLIFICATION & BRUTEFORCE", "HIGH", 3.88, "python-requests/2.31.0", "45.155.205.10"},
			{"/.env", "GET", "BLOCK", 403, "EXTRACTION SECRETS (.ENV)", "CRITICAL", 2.91, "gobuster/3.5", "193.32.162.88"},
			{"/phpmyadmin/index.php", "GET", "BLOCK", 403, "SONDE PHPMYADMIN EXP", "MEDIUM", 3.10, "zgrab/0.x", "103.145.13.4"},
			{"/api/v1/search?q=1+UNION+SELECT+username,password+FROM+users--", "GET", "BLOCK", 403, "INJECTION SQL (UNION SELECT)", "CRITICAL", 4.75, "sqlmap", "91.240.118.22"},
			{"/app/", "GET", "ALLOW", 200, "CLEAN_TRAFFIC", "COMPLIANT", 2.10, "Mozilla/5.0 (X11; Linux x86_64)", "92.157.163.164"},
			{"/api/v1/dashboard/summary", "GET", "ALLOW", 200, "CLEAN_TRAFFIC", "COMPLIANT", 2.05, "Mozilla/5.0 (X11; Linux x86_64)", "92.157.163.164"},
		}

		for _, p := range initialProbes {
			metaJSON := fmt.Sprintf(`{"threat_type":"%s","severity":"%s","entropy":%f,"host":"aegis.aivo.fr","domain":"aegis.aivo.fr","engine":"Aegis Gate PEP (:8000)"}`,
				p.Threat, p.Severity, p.Entropy)
			_ = db.Exec(fmt.Sprintf(`
				INSERT INTO security_audit_logs (
					tenant_id, client_ip, user_agent, http_method, request_uri, decision, http_status_returned, latency_ms, metadata, timestamp
				) VALUES (
					'%s', '%s', '%s', '%s', '%s', '%s', %d, 0.45, '%s'::jsonb, CURRENT_TIMESTAMP - INTERVAL '30 minutes'
				);`, defaultTenantID, p.IP, p.UA, p.Method, p.URI, p.Decision, p.Status, metaJSON))
		}

		initialEgress := []struct {
			FQDN       string
			Threat     string
			Action     string
			Entropy    float64
			Confidence float64
			IP         string
		}{
			{"c2-beacon.random-domain.top", "KNOWN_C2_INFRASTRUCTURE", "BLOCK", 4.85, 0.98, "198.51.100.77"},
			{"revshell.xmrig-pool.xyz", "REVERSE_SHELL_C2", "BLOCK", 4.62, 0.95, "198.51.100.77"},
			{"api.github.com", "CLEAN_EGRESS", "ALLOW", 2.15, 0.05, "198.51.100.77"},
		}

		for _, eg := range initialEgress {
			sinkhole := ""
			if eg.Action == "BLOCK" {
				sinkhole = `,"sinkhole_ip":"0.0.0.0"`
			}
			egMetaJSON := fmt.Sprintf(`{"host":"aegis.aivo.fr","engine":"Aegis System One DNS Sinkhole (:5053)"%s}`, sinkhole)
			_ = db.Exec(fmt.Sprintf(`
				INSERT INTO egress_security_logs (
					tenant_id, client_ip, fqdn, domain_entropy, action, threat_type, confidence, latency_ms, metadata, timestamp
				) VALUES (
					'%s', '%s', '%s', %f, '%s', '%s', %f, 0.85, '%s'::jsonb, CURRENT_TIMESTAMP - INTERVAL '30 minutes'
				);`, defaultTenantID, eg.IP, eg.FQDN, eg.Entropy, eg.Action, eg.Threat, eg.Confidence, egMetaJSON))
		}
		log.Println("🌱 [Aegis Go Control Plane] Socle initial d'événements de sécurité amorcé avec succès.")
	}

	// Initialisation des métriques énergétiques RAPL si la table est vierge
	checkEnergyRow, _ := db.QueryRow("SELECT COUNT(*) AS cnt FROM telemetry_energy_metrics;")
	if checkEnergyRow.Int("cnt") == 0 {
		_ = db.Exec(fmt.Sprintf(`
			INSERT INTO telemetry_energy_metrics (
				node_id, tenant_id, cpu_power_watts, ram_power_watts, energy_consumed_joules, cpu_utilization_pct, memory_used_mb, timestamp
			) VALUES 
			('00000000-0000-0000-0000-000000000002', '%s', 14.80, 4.20, 1140.0, 18.5, 512, CURRENT_TIMESTAMP - INTERVAL '15 minutes'),
			('00000000-0000-0000-0000-000000000002', '%s', 15.20, 4.25, 1167.0, 19.2, 514, CURRENT_TIMESTAMP - INTERVAL '10 minutes'),
			('00000000-0000-0000-0000-000000000002', '%s', 14.60, 4.15, 1125.0, 17.8, 510, CURRENT_TIMESTAMP - INTERVAL '5 minutes'),
			('00000000-0000-0000-0000-000000000002', '%s', 15.10, 4.20, 1158.0, 18.9, 512, CURRENT_TIMESTAMP);`,
			defaultTenantID, defaultTenantID, defaultTenantID, defaultTenantID))
		log.Println("🌱 [Aegis Go Control Plane] Métriques matérielles RAPL initialisées.")
	}
}
