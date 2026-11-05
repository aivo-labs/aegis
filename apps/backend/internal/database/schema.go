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
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			hostname VARCHAR(255) NOT NULL,
			ip_address INET NOT NULL,
			provider VARCHAR(50) NOT NULL DEFAULT 'scaleway',
			os_info VARCHAR(100),
			scaphandre_agent_version VARCHAR(50),
			status VARCHAR(20) NOT NULL DEFAULT 'active',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT uq_tenant_node UNIQUE (tenant_id, hostname)
		);`,

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
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
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

		`CREATE TABLE IF NOT EXISTS domain_ownership_contracts (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
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
	}

	for _, stmt := range statements {
		if err := db.Exec(stmt); err != nil {
			log.Printf("[Schema Notice] %v", err)
		}
	}
	log.Println("✅ [Aegis Go Control Plane] Schéma PostgreSQL & tables d'audit initialisés.")
}
