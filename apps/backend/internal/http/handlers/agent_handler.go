package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/httputil"
)

type AgentHandler struct {
	defaultTenantID string
}

func NewAgentHandler(defaultTenantID string) *AgentHandler {
	return &AgentHandler{defaultTenantID: defaultTenantID}
}

func (h *AgentHandler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	randB := make([]byte, 12)
	_, _ = rand.Read(randB)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":       "success",
		"tenant_id":    h.defaultTenantID,
		"enroll_token": "aegis_tok_live_" + hex.EncodeToString(randB),
		"expires_in":   86400,
		"created_at":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *AgentHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	body := httputil.ReadJSONBody(r)
	serverID := httputil.AsString(body, "server_id", "vps-node-01")
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":                      "enrolled",
		"tenant_id":                   h.defaultTenantID,
		"server_id":                   serverID,
		"egress_upstream_dns":         "127.0.0.1:5053",
		"energy_scrape_interval_secs": 5,
		"created_at":                  time.Now().UTC().Format(time.RFC3339),
	})
}
