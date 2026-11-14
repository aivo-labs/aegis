-- =============================================================================
-- AEGIS BY AIVO — SCHÉMA DE BASE DE DONNÉES RELATIONNELLE & TIMESCALEDB (v1.0)
-- Socle Multi-Tenant, Zero-Trust (Aegis Gate) & Télémétrie Énergétique (Aegis Green)
-- Stack : PostgreSQL 16 + TimescaleDB + Row Level Security (RLS)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 0. EXTENSIONS POSTGRESQL & TIMESCALEDB
-- -----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "timescaledb" CASCADE;

-- -----------------------------------------------------------------------------
-- 1. GESTION DES TENANTS & INFRASTRUCTURES (CORE MULTI-TENANT)
-- -----------------------------------------------------------------------------

-- Table des Entreprises / Tenants Client
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    domain VARCHAR(255) NOT NULL UNIQUE,
    dns_verification_token VARCHAR(128) NOT NULL DEFAULT encode(gen_random_bytes(32), 'hex'),
    is_dns_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    subscription_plan VARCHAR(50) NOT NULL DEFAULT 'community' CHECK (subscription_plan IN ('community', 'managed_saas', 'enterprise')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);

-- Table des Serveurs / Nœuds d'Infrastructure Surveillés
CREATE TABLE IF NOT EXISTS infrastructure_nodes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    provider VARCHAR(50) NOT NULL DEFAULT 'scaleway' CHECK (provider IN ('scaleway', 'ovhcloud', 'on_premise', 'aws', 'other')),
    os_info VARCHAR(100),
    scaphandre_agent_version VARCHAR(50),
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'degraded', 'offline', 'maintenance')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_tenant_node UNIQUE (tenant_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_nodes_tenant ON infrastructure_nodes(tenant_id);

-- -----------------------------------------------------------------------------
-- 2. SCANS PASSIFS INSTANTANÉS (LEAD MAGNET AEGIS.FR)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS passive_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain VARCHAR(255) NOT NULL,
    contact_email VARCHAR(255) NOT NULL,
    security_score INT NOT NULL CHECK (security_score BETWEEN 0 AND 100),
    ecoindex_score NUMERIC(5, 2) NOT NULL CHECK (ecoindex_score BETWEEN 0 AND 100),
    ecoindex_grade VARCHAR(2) NOT NULL CHECK (ecoindex_grade IN ('A', 'B', 'C', 'D', 'E', 'F', 'G')),
    verification_token VARCHAR(128) NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_passive_scans_domain ON passive_scans(domain);
CREATE INDEX IF NOT EXISTS idx_passive_scans_email ON passive_scans(contact_email);

-- -----------------------------------------------------------------------------
-- 3. DÉFENSE ZERO-TRUST & PASSERELLE AEGIS GATE (AUTHORINO / ENVOY / KEYCLOAK)
-- -----------------------------------------------------------------------------

-- Table des Routes Protégées par Aegis Gate à l'Edge
CREATE TABLE IF NOT EXISTS gate_routes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    match_path_prefix VARCHAR(255) NOT NULL, -- ex: /api/v1/workorders
    upstream_target_url VARCHAR(255) NOT NULL, -- ex: http://internal-service.local:8080
    auth_required BOOLEAN NOT NULL DEFAULT TRUE,
    keycloak_realm VARCHAR(100),
    keycloak_client_id VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_tenant_route UNIQUE (tenant_id, match_path_prefix)
);

CREATE INDEX IF NOT EXISTS idx_gate_routes_tenant ON gate_routes(tenant_id);

-- Table des Règles d'Autorisation Zero-Trust (OIDC, FGA, IP Filtering, Rate Limiting)
CREATE TABLE IF NOT EXISTS gate_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    route_id UUID NOT NULL REFERENCES gate_routes(id) ON DELETE CASCADE,
    policy_name VARCHAR(100) NOT NULL,
    policy_type VARCHAR(50) NOT NULL CHECK (policy_type IN ('oidc_jwt', 'open_fga', 'ip_allowlist', 'rate_limit', 'custom_rego')),
    rule_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    priority INT NOT NULL DEFAULT 100,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gate_policies_route ON gate_policies(route_id);

-- Table d'Audit des Événements Cyber & Blocages à l'Edge (SÉRIES TEMPORELLES)
CREATE TABLE IF NOT EXISTS security_audit_logs (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tenant_id UUID NOT NULL,
    route_id UUID REFERENCES gate_routes(id) ON DELETE SET NULL,
    client_ip INET NOT NULL,
    user_agent TEXT,
    http_method VARCHAR(10) NOT NULL,
    request_uri TEXT NOT NULL,
    decision VARCHAR(30) NOT NULL CHECK (decision IN ('ALLOW', 'BLOCK', 'QUARANTINE', 'BYPASS', 'DENY_UNAUTHENTICATED', 'DENY_FORBIDDEN', 'RATE_LIMITED', 'BLOCKED_PROBE')),
    http_status_returned INT NOT NULL, -- 200, 401, 403, 413, 429
    keycloak_user_id VARCHAR(150),
    latency_ms NUMERIC(8, 2) NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb
);

SELECT create_hypertable('security_audit_logs', 'timestamp', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_security_audit_tenant_time ON security_audit_logs(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_audit_decision ON security_audit_logs(decision, timestamp DESC);

-- Table d'Audit des Événements & Blocages Sortants (AEGIS EGRESS / HYPERTABLE TIMESCALEDB)
CREATE TABLE IF NOT EXISTS egress_security_logs (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_ip INET NOT NULL,
    fqdn VARCHAR(255) NOT NULL,
    domain_entropy NUMERIC(5, 2) NOT NULL,
    action VARCHAR(20) NOT NULL CHECK (action IN ('ALLOW', 'BLOCK', 'QUARANTINE', 'BYPASS')),
    threat_type VARCHAR(80) NOT NULL DEFAULT 'SUSPECTED_C2',
    confidence NUMERIC(5, 4) NOT NULL,
    latency_ms NUMERIC(8, 2) NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb
);

SELECT create_hypertable('egress_security_logs', 'timestamp', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_egress_logs_tenant_time ON egress_security_logs(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_egress_logs_action ON egress_security_logs(action, timestamp DESC);

-- -----------------------------------------------------------------------------
-- 4. TÉLÉMÉTRIE ÉNERGÉTIQUE & SOBRIÉTÉ NUMÉRIQUE (AEGIS GREEN / SCAPHANDRE)
-- -----------------------------------------------------------------------------

-- Métriques de Consommation Électrique Serveur (HYPERTABLE TIMESCALEDB)
CREATE TABLE IF NOT EXISTS telemetry_energy_metrics (
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    node_id UUID NOT NULL REFERENCES infrastructure_nodes(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cpu_power_watts NUMERIC(10, 3) NOT NULL,
    ram_power_watts NUMERIC(10, 3) NOT NULL,
    total_power_watts NUMERIC(10, 3) GENERATED ALWAYS AS (cpu_power_watts + ram_power_watts) STORED,
    energy_consumed_joules NUMERIC(12, 3) NOT NULL,
    cpu_utilization_pct NUMERIC(5, 2) NOT NULL CHECK (cpu_utilization_pct BETWEEN 0 AND 100),
    memory_used_mb INT NOT NULL
);

SELECT create_hypertable('telemetry_energy_metrics', 'timestamp', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_energy_metrics_node_time ON telemetry_energy_metrics(node_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_energy_metrics_tenant_time ON telemetry_energy_metrics(tenant_id, timestamp DESC);

-- Table des Audits Passifs Web (EcoIndex, RGESN & Norme VS / ex-VSME)
CREATE TABLE IF NOT EXISTS web_green_audits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_url VARCHAR(255) NOT NULL,
    eco_index_score NUMERIC(5, 2) NOT NULL CHECK (eco_index_score BETWEEN 0 AND 100),
    eco_index_grade VARCHAR(2) NOT NULL CHECK (eco_index_grade IN ('A', 'B', 'C', 'D', 'E', 'F', 'G')),
    dom_elements_count INT NOT NULL,
    http_requests_count INT NOT NULL,
    page_weight_kb NUMERIC(10, 2) NOT NULL,
    gco2_eq_per_visit NUMERIC(8, 4) NOT NULL,
    vsme_e3_compliant BOOLEAN NOT NULL DEFAULT FALSE,
    rgesn_compliance_pct NUMERIC(5, 2) DEFAULT 0.00,
    audited_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_green_audits_tenant ON web_green_audits(tenant_id, audited_at DESC);

-- -----------------------------------------------------------------------------
-- 5. POLITIQUES DE SÉCURITÉ ROW LEVEL SECURITY (RLS) POSTGRESQL
-- -----------------------------------------------------------------------------

ALTER TABLE infrastructure_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE gate_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE web_green_audits ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_infrastructure_nodes ON infrastructure_nodes;
CREATE POLICY tenant_isolation_infrastructure_nodes ON infrastructure_nodes
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_gate_routes ON gate_routes;
CREATE POLICY tenant_isolation_gate_routes ON gate_routes
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_web_green_audits ON web_green_audits;
CREATE POLICY tenant_isolation_web_green_audits ON web_green_audits
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- -----------------------------------------------------------------------------
-- 6. VUES D'AGRÉGATION CONTINUES (TIMESCALEDB CONTINUOUS AGGREGATES)
-- -----------------------------------------------------------------------------

CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_tenant_energy_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS bucket,
    tenant_id,
    AVG(total_power_watts) AS avg_power_watts,
    MAX(total_power_watts) AS peak_power_watts,
    SUM(energy_consumed_joules) AS total_joules_consumed,
    COUNT(*) as metrics_sample_count
FROM telemetry_energy_metrics
GROUP BY bucket, tenant_id;

SELECT add_continuous_aggregate_policy('hourly_tenant_energy_summary',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE);

-- -----------------------------------------------------------------------------
-- 7. INITIALISATION DU TENANT PAR DÉFAUT (COMMUNITY / BANC D'ESSAI LOCAL & VPS)
-- -----------------------------------------------------------------------------
INSERT INTO tenants (id, name, slug, domain, subscription_plan, is_dns_verified, verified_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Aegis Sovereign Node',
    'aegis-default',
    'localhost',
    'community',
    TRUE,
    CURRENT_TIMESTAMP
)
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- FIN DU SCHÉMA
-- =============================================================================
