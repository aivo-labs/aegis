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

	lang := httputil.ResolveLocale(r, "fr")
	feed := h.cveService.GetFeed(lang)
	coverageReport := h.cveService.VerifyCoverage(lang)
	activeRules := h.cveService.GetActiveRules(lang)
	lastSync := h.cveService.GetLastSyncReport()

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":                         "success",
		"lang":                           lang,
		"count":                          len(feed),
		"cves":                           feed,
		"catalog_cves":                   feed,
		"active_rules_count":             len(activeRules),
		"active_rules":                   activeRules,
		"blocked_by_virtual_patch_count": coverageReport.CoveredVirtualPatchCount + coverageReport.MitigatedEgressOnlyCount,
		"coverage_report":                coverageReport,
		"last_sync_report":               lastSync,
		"updated_at":                     time.Now().UTC().Format(time.RFC3339),
		"source":                         "Aegis SOC Threat Intel & Coverage Verification Engine (ANSSI CERT-FR + Curated Catalog)",
	})
}

// SyncCertFr déclenche la synchronisation souveraine à la demande depuis le flux RSS officiel de l'ANSSI / CERT-FR.
func (h *CveHandler) SyncCertFr(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}

	lang := httputil.ResolveLocale(r, "fr")
	report, err := h.cveService.SyncCertFr(r.Context(), lang)
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	feed := h.cveService.GetFeed(lang)
	coverageReport := h.cveService.VerifyCoverage(lang)

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":          "success",
		"sync_report":     report,
		"total_cves":      len(feed),
		"coverage_report": coverageReport,
	})
}
