package http

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

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

// requireInternalAuth protège les routes de mutation du Control Plane (Correctif P0).
// Lorsque AEGIS_INTERNAL_TOKEN est configuré, toute requête mutatrice (POST/PUT/PATCH/DELETE)
// doit présenter un en-tête X-Aegis-Internal-Token valide (comparaison en temps constant).
func requireInternalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next(w, r)
			return
		}
		expected := strings.TrimSpace(os.Getenv("AEGIS_INTERNAL_TOKEN"))
		if expected != "" {
			provided := strings.TrimSpace(r.Header.Get("X-Aegis-Internal-Token"))
			if provided == "" {
				auth := strings.TrimSpace(r.Header.Get("Authorization"))
				if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
					provided = strings.TrimSpace(auth[7:])
				}
			}
			if len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"status":"error","error":"Unauthorized — X-Aegis-Internal-Token required"}`))
				return
			}
		}
		next(w, r)
	}
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

	// 3. Bouclier & Protection (Mutations protégées par requireInternalAuth)
	mux.HandleFunc("/api/v1/dashboard/protection", requireInternalAuth(p.ProtectionHandler.Protection))
	mux.HandleFunc("/api/v1/protection/status", requireInternalAuth(p.ProtectionHandler.Protection))
	mux.HandleFunc("/api/v1/protection/toggle", requireInternalAuth(p.ProtectionHandler.Protection))
	mux.HandleFunc("/api/v1/dashboard/reset", requireInternalAuth(p.ProtectionHandler.Reset))
	mux.HandleFunc("/api/v1/dashboard/bans", requireInternalAuth(p.ProtectionHandler.Bans))
	mux.HandleFunc("/api/v1/dashboard/retention", requireInternalAuth(p.ProtectionHandler.Retention))
	mux.HandleFunc("/api/v1/dashboard/retention/purge", requireInternalAuth(p.ProtectionHandler.RetentionPurge))

	// 4. Cockpit & Indicateurs
	mux.HandleFunc("/api/v1/dashboard/summary", p.DashboardHandler.Summary)
	mux.HandleFunc("/api/v1/dashboard/live-streams", p.DashboardHandler.LiveStreams)
	mux.HandleFunc("/api/v1/dashboard/simulate", requireInternalAuth(p.DashboardHandler.Simulate))
	mux.HandleFunc("/api/v1/dashboard/egress-threats", p.DashboardHandler.ThreatsFeed)
	mux.HandleFunc("/api/v1/dashboard/triage", p.DashboardHandler.ThreatsFeed)
	mux.HandleFunc("/api/v1/dashboard/energy/export", p.DashboardHandler.EnergyExport)
	mux.HandleFunc("/api/v1/dashboard/energy/telemetry", p.DashboardHandler.EnergyTelemetry)
	mux.HandleFunc("/api/v1/dashboard/telemetry/energy", p.DashboardHandler.EnergyTelemetry)
	mux.HandleFunc("/api/v1/dashboard/actions/execute", requireInternalAuth(p.DashboardHandler.ExecuteAction))
	mux.HandleFunc("/api/v1/nodes", p.DashboardHandler.Nodes)

	// 5. Diagnostic Passif & Mandat Légal
	mux.HandleFunc("/api/v1/audit/passive-scan", p.AuditHandler.PassiveScan)
	mux.HandleFunc("/api/v1/audit/latest", p.AuditHandler.Latest)
	mux.HandleFunc("/api/v1/audit/schedule", p.AuditHandler.Schedule)
	mux.HandleFunc("/api/v1/audit/request-verification", p.AuditHandler.RequestVerification)
	mux.HandleFunc("/api/v1/audit/verify-ownership", p.AuditHandler.VerifyOwnership)

	// 6. Alertes & Renseignement CVE
	mux.HandleFunc("/api/v1/cve/feed", p.CveHandler.Feed)
	mux.HandleFunc("/api/v1/cve/sync/certfr", requireInternalAuth(p.CveHandler.SyncCertFr))

	// 7. Enrôlement Agent
	mux.HandleFunc("/api/v1/dashboard/enroll/token", requireInternalAuth(p.AgentHandler.Token))
	mux.HandleFunc("/api/v1/enroll/token", requireInternalAuth(p.AgentHandler.Token))
	mux.HandleFunc("/api/v1/agent/enroll", p.AgentHandler.Enroll)

	// 8. Cibles de simulation (Honeypot sandboxé)
	RegisterHoneypotRoutes(mux)

	return mux
}
