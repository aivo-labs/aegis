package domain

import "time"

// ProtectionState représente l'état courant du bouclier Aegis.
type ProtectionState struct {
	Enabled         bool   `json:"protection_enabled"`
	MaxPayloadBytes int    `json:"max_payload_bytes"`
	Message         string `json:"message,omitempty"`
	Timestamp       string `json:"timestamp"`
}

// IPBanEntry modélise une adresse IP interdite par le SOC ou par auto-ban.
type IPBanEntry struct {
	IPAddress   string     `json:"ip_address"`
	Reason      string     `json:"reason"`
	RiskScore   int        `json:"risk_score"`
	Source      string     `json:"source"`
	BlockedHits int        `json:"blocked_hits"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// RetentionConfig définit les fenêtres de rétention de logs selon les normes ANSSI/RGPD.
type RetentionConfig struct {
	HotWindowDays     int `json:"hot_window_days"`
	AnssiForensicDays int `json:"anssi_forensic_days"`
	RgpdCleanIPDays   int `json:"rgpd_clean_ip_days"`
	MaxPayloadBytes   int `json:"max_payload_bytes"`
	AutoBanThreshold  int `json:"auto_ban_threshold"`
}
