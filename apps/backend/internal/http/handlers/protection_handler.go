package handlers

import (
	"net/http"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/httputil"
	"github.com/aivo-labs/aegis/backend/internal/service"
)

type ProtectionHandler struct {
	protectionService *service.ProtectionService
}

func NewProtectionHandler(protectionService *service.ProtectionService) *ProtectionHandler {
	return &ProtectionHandler{protectionService: protectionService}
}

func (h *ProtectionHandler) Protection(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	if r.Method == http.MethodPost {
		payload := httputil.ReadJSONBody(r)
		enabled := httputil.AsBool(payload, "protection_enabled", true)
		msg := h.protectionService.SetProtection(enabled)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":             "success",
			"protection_enabled": enabled,
			"message":            msg,
			"timestamp":          time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":             "success",
		"protection_enabled": h.protectionService.IsProtectionEnabled(),
		"max_payload_bytes":  h.protectionService.GetMaxPayloadBytes(),
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *ProtectionHandler) Reset(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	_ = h.protectionService.ResetAll()
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":    "success",
		"message":   "Compteurs, journaux d'attaques et liste de bannissement réinitialisés à 0.",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *ProtectionHandler) Bans(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	if r.Method == http.MethodPost {
		body := httputil.ReadJSONBody(r)
		ip := httputil.AsString(body, "ip_address", "")
		maxBytes := httputil.AsInt(body, "max_payload_bytes", 0)

		if ip == "" && maxBytes >= 1024 {
			ret, _ := h.protectionService.GetRetention()
			ret.MaxPayloadBytes = maxBytes
			_ = h.protectionService.UpdateRetention(ret)
			httputil.WriteJSON(w, http.StatusOK, map[string]any{
				"status":            "success",
				"max_payload_bytes": maxBytes,
				"message":           "Seuil volumétrique maximal mis à jour.",
			})
			return
		}
		if ip == "" {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "ip_address requis"})
			return
		}
		reason := httputil.AsString(body, "reason", "Bannissement manuel SOC")
		source := httputil.AsString(body, "source", "MANUAL_SOC")
		risk := httputil.AsInt(body, "risk_score", 95)
		_ = h.protectionService.AddBan(ip, reason, source, risk)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":     "success",
			"ip_address": ip,
			"message":    "Adresse IP ajoutée à la liste noire et synchronisée avec Gate Proxy",
		})
		return
	}

	if r.Method == http.MethodDelete {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			body := httputil.ReadJSONBody(r)
			ip = httputil.AsString(body, "ip_address", "")
		}
		if ip == "" {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "ip requis"})
			return
		}
		_ = h.protectionService.RemoveBan(ip)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":     "success",
			"ip_address": ip,
			"message":    "Adresse IP retirée de la liste noire",
		})
		return
	}

	bans, _ := h.protectionService.ListBans()
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":            "success",
		"count":             len(bans),
		"bans":              bans,
		"max_payload_bytes": h.protectionService.GetMaxPayloadBytes(),
	})
}

func (h *ProtectionHandler) Retention(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	if r.Method == http.MethodPost {
		body := httputil.ReadJSONBody(r)
		cfg, _ := h.protectionService.GetRetention()
		if v := httputil.AsInt(body, "hot_window_days", 0); v > 0 {
			cfg.HotWindowDays = v
		}
		if v := httputil.AsInt(body, "anssi_forensic_days", 0); v > 0 {
			cfg.AnssiForensicDays = v
		}
		if v := httputil.AsInt(body, "rgpd_clean_ip_days", 0); v > 0 {
			cfg.RgpdCleanIPDays = v
		}
		if v := httputil.AsInt(body, "max_payload_bytes", 0); v >= 1024 {
			cfg.MaxPayloadBytes = v
		}
		if v := httputil.AsInt(body, "auto_ban_threshold", 0); v > 0 {
			cfg.AutoBanThreshold = v
		}
		_ = h.protectionService.UpdateRetention(cfg)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":    "success",
			"message":   "Politique de rétention mise à jour et synchronisée.",
			"retention": cfg,
		})
		return
	}

	cfg, _ := h.protectionService.GetRetention()
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":    "success",
		"retention": cfg,
	})
}

func (h *ProtectionHandler) RetentionPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		httputil.WriteJSON(w, http.StatusNoContent, nil)
		return
	}
	res, _ := h.protectionService.RunRetentionPurge()
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"purged":  res,
		"message": "Purge de rétention ANSSI/RGPD exécutée avec succès.",
	})
}
