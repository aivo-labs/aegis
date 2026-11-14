package handlers

import (
	"net/http"
	"os"

	"github.com/aivo-labs/aegis/backend/internal/httputil"
	"github.com/aivo-labs/aegis/backend/internal/service"
)

type HealthHandler struct {
	protectionService *service.ProtectionService
	port              string
}

func NewHealthHandler(protectionService *service.ProtectionService, port string) *HealthHandler {
	return &HealthHandler{
		protectionService: protectionService,
		port:              port,
	}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":              "healthy",
		"service":             "aegis-backend-go",
		"version":             "4.3.0",
		"engine":              "Go 1.22+ Standard Library (Zéro-Dépendance)",
		"port":                h.port,
		"protection_enabled":  h.protectionService.IsProtectionEnabled(),
		"scanner_concurrency": "5 goroutines",
		"database":            "PostgreSQL / TimescaleDB (Wire Protocol Natif)",
	})
}

func (h *HealthHandler) InstallScript(w http.ResponseWriter, r *http.Request) {
	scriptPath := "/app/public/install.sh"
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		data, err = os.ReadFile("public/install.sh")
	}
	if err != nil {
		http.Error(w, "Script d'installation indisponible", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
