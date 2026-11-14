package app

import (
	"log"
	"net/http"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/config"
	"github.com/aivo-labs/aegis/backend/internal/database"
	internalHttp "github.com/aivo-labs/aegis/backend/internal/http"
	"github.com/aivo-labs/aegis/backend/internal/http/handlers"
	"github.com/aivo-labs/aegis/backend/internal/service"
)

// Run initialise et démarre le serveur Control Plane Aegis.
func Run() {
	cfg := config.Load()
	pgCfg := database.ParseDatabaseURL(cfg.DatabaseURL)
	db := database.NewPgClient(pgCfg)

	// Attente de PostgreSQL avec retries
	for i := 0; i < 10; i++ {
		if err := db.Exec("SELECT 1;"); err == nil {
			break
		}
		log.Printf("⏳ Attente de PostgreSQL (%s:%s)...", pgCfg.Host, pgCfg.Port)
		time.Sleep(1500 * time.Millisecond)
	}
	database.EnsureDatabaseSchema(db, cfg.DefaultTenantID)

	// Services métier
	protectionSvc := service.NewProtectionService(
		db,
		cfg.GateProxyURL,
		cfg.EgressGatewayURL,
		cfg.DefaultProtection,
		cfg.DefaultMaxPayloadBytes,
	)
	telemetrySvc := service.NewTelemetryService(db, protectionSvc, cfg.DefaultTenantID)
	auditSvc := service.NewAuditService(db)
	cveSvc := service.NewCveService()
	dashboardSvc := service.NewDashboardService(db, protectionSvc, cfg.DefaultTenantID)

	// Initialisation des contrôleurs HTTP
	router := internalHttp.NewRouter(internalHttp.RouterParams{
		HealthHandler:     handlers.NewHealthHandler(protectionSvc, cfg.Port),
		TelemetryHandler:  handlers.NewTelemetryHandler(telemetrySvc),
		ProtectionHandler: handlers.NewProtectionHandler(protectionSvc),
		DashboardHandler:  handlers.NewDashboardHandler(dashboardSvc, protectionSvc),
		AuditHandler:      handlers.NewAuditHandler(auditSvc),
		CveHandler:        handlers.NewCveHandler(cveSvc),
		AgentHandler:      handlers.NewAgentHandler(cfg.DefaultTenantID),
	})

	log.Printf("🚀 [Aegis Go Control Plane] Démarré sur :%s (Architecture SOLID & Clean Architecture)", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, router); err != nil {
		log.Fatalf("Erreur fatale Control Plane Go: %v", err)
	}
}
