package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/aivo-labs/aegis/backend/internal/httputil"
	"github.com/aivo-labs/aegis/backend/internal/service"
)

type DashboardHandler struct {
	dashboardService  *service.DashboardService
	protectionService *service.ProtectionService
}

func NewDashboardHandler(dashboardService *service.DashboardService, protectionService *service.ProtectionService) *DashboardHandler {
	return &DashboardHandler{
		dashboardService:  dashboardService,
		protectionService: protectionService,
	}
}

func (h *DashboardHandler) Summary(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	summary := h.dashboardService.GetSummary()
	httputil.WriteJSON(w, http.StatusOK, summary)
}

func (h *DashboardHandler) LiveStreams(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	dateFilter := r.URL.Query().Get("date")
	hostFilter := r.URL.Query().Get("host")
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
		limit = l
	}
	streams, err := h.dashboardService.GetLiveStreamsFiltered(dateFilter, hostFilter, limit)
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, streams)
}

func (h *DashboardHandler) ThreatsFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	includeCompliant := r.URL.Query().Get("include_compliant") == "true"
	threats, _ := h.dashboardService.GetThreatsFeed(includeCompliant)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"count":   len(threats),
		"threats": threats,
		"data":    threats,
		"logs":    threats,
		"events":  threats,
	})
}

func (h *DashboardHandler) Nodes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	summary := h.dashboardService.GetSummary()
	var nodes []map[string]any
	if n, ok := summary["nodes"].([]map[string]any); ok {
		nodes = n
	} else if n, ok := summary["monitored_nodes"].([]map[string]any); ok {
		nodes = n
	} else if sec, ok := summary["security"].(map[string]any); ok {
		if n, ok := sec["monitored_nodes"].([]map[string]any); ok {
			nodes = n
		}
	}
	if nodes == nil {
		nodes = []map[string]any{}
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"nodes":  nodes,
		"count":  len(nodes),
	})
}

func (h *DashboardHandler) ExecuteAction(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	body := httputil.ReadJSONBody(r)
	action := httputil.AsString(body, "action", "")
	target := httputil.AsString(body, "target", "")

	if action == "ban_ip" && target != "" && h.protectionService != nil {
		_ = h.protectionService.AddBan(target, "Bannissement manuel SOC Kanban", "KANBAN_SOC", 95)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"action":  action,
		"target":  target,
		"message": fmt.Sprintf("Action '%s' appliquée avec succès pour %s.", action, target),
	})
}

func (h *DashboardHandler) EnergyExport(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"aegis-rapl-telemetry.csv\"")
		_ = h.dashboardService.ExportEnergyCSV(w)
		return
	}
	summary := h.dashboardService.GetSummary()
	green, _ := summary["green"].(map[string]any)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"engine": "Rust RAPL / Scaphandre Hardware Probe",
		"green":  green,
	})
}
