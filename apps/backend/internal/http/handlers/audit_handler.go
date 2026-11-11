package handlers

import (
	"net/http"

	"github.com/aivo-labs/aegis/backend/internal/httputil"
	"github.com/aivo-labs/aegis/backend/internal/service"
)

type AuditHandler struct {
	auditService *service.AuditService
}

func NewAuditHandler(auditService *service.AuditService) *AuditHandler {
	return &AuditHandler{auditService: auditService}
}

func (h *AuditHandler) PassiveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	rawDomain := r.URL.Query().Get("domain")
	if rawDomain == "" {
		body := httputil.ReadJSONBody(r)
		rawDomain = httputil.AsString(body, "domain", "localhost")
	}
	res := h.auditService.RunScan(rawDomain)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"audit":  res,
	})
}

func (h *AuditHandler) Latest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	domainName := r.URL.Query().Get("domain")
	res, err := h.auditService.GetLatest(domainName)
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	hasAudit := res != nil && res.Domain != ""
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":    "success",
		"has_audit": hasAudit,
		"audit":     res,
	})
}

func (h *AuditHandler) RequestVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	body := httputil.ReadJSONBody(r)
	domainName := httputil.AsString(body, "domain", "")
	email := httputil.AsString(body, "email", "")
	company := httputil.AsString(body, "company", "")

	res, err := h.auditService.RequestVerification(domainName, email, company)
	if err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"error":   err.Error(),
			"message": err.Error(),
		})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, res)
}

func (h *AuditHandler) VerifyOwnership(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	body := httputil.ReadJSONBody(r)
	domainName := httputil.AsString(body, "domain", "")
	email := httputil.AsString(body, "email", "")
	contractAccepted := httputil.AsBool(body, "contract_accepted", false)
	signerIP := r.RemoteAddr
	userAgent := r.UserAgent()

	res, err := h.auditService.VerifyOwnership(domainName, email, contractAccepted, signerIP, userAgent)
	if err != nil {
		httputil.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":   err.Error(),
			"message": err.Error(),
		})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, res)
}
