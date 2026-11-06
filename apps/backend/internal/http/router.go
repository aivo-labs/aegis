package http

import (
	"net/http"

	"github.com/aivo-labs/aegis/backend/internal/http/handlers"
)

type RouterParams struct {
	HealthHandler     *handlers.HealthHandler
	TelemetryHandler  *handlers.TelemetryHandler
	ProtectionHandler *handlers.ProtectionHandler
	DashboardHandler  *handlers.DashboardHandler
	AuditHandler      *handlers.AuditHandler
	CveHandler        *handlers.CveHandler
	AgentHandler      *handlers.AgentHandler
}

// NewRouter initialise et configure toutes les routes de l'API Aegis Control Plane.
func NewRouter(p RouterParams) *http.ServeMux {
	mux := http.NewServeMux()

	// 1. Health & Installer
	mux.HandleFunc("/health", p.HealthHandler.Health)
	mux.HandleFunc("/install.sh", p.HealthHandler.InstallScript)

	// 2. Télémétrie
	mux.HandleFunc("/api/v1/gate/telemetry/energy", p.TelemetryHandler.IngestEnergy)
	mux.HandleFunc("/api/v1/gate/telemetry/ingress", p.TelemetryHandler.IngestIngress)
	mux.HandleFunc("/api/v1/gate/telemetry/egress", p.TelemetryHandler.IngestEgress)

	// 3. Bouclier & Protection
	mux.HandleFunc("/api/v1/dashboard/protection", p.ProtectionHandler.Protection)
	mux.HandleFunc("/api/v1/protection/status", p.ProtectionHandler.Protection)
	mux.HandleFunc("/api/v1/protection/toggle", p.ProtectionHandler.Protection)
	mux.HandleFunc("/api/v1/dashboard/reset", p.ProtectionHandler.Reset)
	mux.HandleFunc("/api/v1/dashboard/bans", p.ProtectionHandler.Bans)
	mux.HandleFunc("/api/v1/dashboard/retention", p.ProtectionHandler.Retention)
	mux.HandleFunc("/api/v1/dashboard/retention/purge", p.ProtectionHandler.RetentionPurge)

	// 4. Cockpit & Indicateurs
	mux.HandleFunc("/api/v1/dashboard/summary", p.DashboardHandler.Summary)
	mux.HandleFunc("/api/v1/dashboard/live-streams", p.DashboardHandler.LiveStreams)
	mux.HandleFunc("/api/v1/dashboard/egress-threats", p.DashboardHandler.ThreatsFeed)
	mux.HandleFunc("/api/v1/dashboard/triage", p.DashboardHandler.ThreatsFeed)
	mux.HandleFunc("/api/v1/dashboard/energy/export", p.DashboardHandler.EnergyExport)
	mux.HandleFunc("/api/v1/dashboard/energy/telemetry", p.DashboardHandler.EnergyTelemetry)
	mux.HandleFunc("/api/v1/dashboard/telemetry/energy", p.DashboardHandler.EnergyTelemetry)
	mux.HandleFunc("/api/v1/dashboard/actions/execute", p.DashboardHandler.ExecuteAction)
	mux.HandleFunc("/api/v1/nodes", p.DashboardHandler.Nodes)

	// 5. Diagnostic Passif & Mandat Légal
	mux.HandleFunc("/api/v1/audit/passive-scan", p.AuditHandler.PassiveScan)
	mux.HandleFunc("/api/v1/audit/latest", p.AuditHandler.Latest)
	mux.HandleFunc("/api/v1/audit/request-verification", p.AuditHandler.RequestVerification)
	mux.HandleFunc("/api/v1/audit/verify-ownership", p.AuditHandler.VerifyOwnership)

	// 6. Alertes & Renseignement CVE
	mux.HandleFunc("/api/v1/cve/feed", p.CveHandler.Feed)

	// 7. Enrôlement Agent
	mux.HandleFunc("/api/v1/dashboard/enroll/token", p.AgentHandler.Token)
	mux.HandleFunc("/api/v1/enroll/token", p.AgentHandler.Token)
	mux.HandleFunc("/api/v1/agent/enroll", p.AgentHandler.Enroll)

	// 8. Cibles de simulation (Honeypot sandboxé)
	RegisterHoneypotRoutes(mux)

	return mux
}
