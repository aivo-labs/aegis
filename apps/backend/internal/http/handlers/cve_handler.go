package handlers

import (
	"net/http"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/httputil"
	"github.com/aivo-labs/aegis/backend/internal/service"
)

type CveHandler struct {
	cveService *service.CveService
}

func NewCveHandler(cveService *service.CveService) *CveHandler {
	return &CveHandler{cveService: cveService}
}

func (h *CveHandler) Feed(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	feed := h.cveService.GetFeed()
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":                         "success",
		"count":                          len(feed),
		"cves":                           feed,
		"catalog_cves":                   feed,
		"active_rules_count":             len(feed),
		"blocked_by_virtual_patch_count": 0,
		"updated_at":                     time.Now().UTC().Format(time.RFC3339),
		"source":                         "Aegis SOC Threat Intel Feed",
	})
}
