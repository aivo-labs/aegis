package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/database"
	"github.com/aivo-labs/aegis/backend/internal/domain"
)

type ProtectionService struct {
	db                *database.PgClient
	gateProxyURL      string
	egressGatewayURL  string
	mu                sync.RWMutex
	protectionEnabled bool
	maxPayloadBytes   int
}

func NewProtectionService(db *database.PgClient, gateProxyURL, egressGatewayURL string, defaultProtection bool, defaultMaxPayload int) *ProtectionService {
	s := &ProtectionService{
		db:                db,
		gateProxyURL:      gateProxyURL,
		egressGatewayURL:  egressGatewayURL,
		protectionEnabled: defaultProtection,
		maxPayloadBytes:   defaultMaxPayload,
	}
	if db != nil {
		if row, err := db.QueryRow("SELECT max_payload_bytes FROM system_retention_config WHERE id = 1 LIMIT 1"); err == nil {
			if v := row.Int("max_payload_bytes"); v >= 1024 {
				s.maxPayloadBytes = v
			}
		}
	}
	return s
}

func (s *ProtectionService) IsProtectionEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.protectionEnabled
}

func (s *ProtectionService) GetMaxPayloadBytes() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxPayloadBytes
}

func (s *ProtectionService) SetProtection(enabled bool) string {
	s.mu.Lock()
	s.protectionEnabled = enabled
	s.mu.Unlock()
	s.Propagate()

	if enabled {
		return "🛡️ Bouclier Aegis ACTIF : Interception Ingress WAF (403/413) & Sinkhole Egress (0.0.0.0) opérationnels."
	}
	return "⚠️ Bouclier Aegis DÉSACTIVÉ : Le serveur cible est exposé (les attaques et exfiltrations passent en mode BYPASS)."
}

func (s *ProtectionService) SetMaxPayloadBytes(bytes int) {
	s.mu.Lock()
	if bytes >= 1024 {
		s.maxPayloadBytes = bytes
	}
	s.mu.Unlock()
	s.Propagate()
}

func (s *ProtectionService) Propagate() {
	s.mu.RLock()
	enabled := s.protectionEnabled
	maxBytes := s.maxPayloadBytes
	s.mu.RUnlock()

	var bannedIPs []string
	if s.db != nil {
		rows, err := s.db.Query("SELECT ip_address FROM ip_ban_list WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP")
		if err == nil {
			for _, r := range rows {
				if ip := r.String("ip_address"); ip != "" {
					bannedIPs = append(bannedIPs, ip)
				}
			}
		}
	}

	payload, _ := json.Marshal(map[string]any{
		"protection_enabled": enabled,
		"max_payload_bytes":  maxBytes,
		"banned_ips":         bannedIPs,
	})

	client := &http.Client{Timeout: 1200 * time.Millisecond}
	endpoints := []string{
		fmt.Sprintf("%s/_aegis/mode", s.gateProxyURL),
		fmt.Sprintf("%s/mode", s.egressGatewayURL),
	}
	for _, ep := range endpoints {
		req, err := http.NewRequest("POST", ep, bytes.NewReader(payload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			if resp, errDo := client.Do(req); errDo == nil {
				_ = resp.Body.Close()
			}
		}
	}
}

func (s *ProtectionService) ListBans() ([]domain.IPBanEntry, error) {
	if s.db == nil {
		return []domain.IPBanEntry{}, nil
	}
	rows, err := s.db.Query("SELECT ip_address, reason, risk_score, source, blocked_hits, created_at, expires_at FROM ip_ban_list WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP ORDER BY created_at DESC;")
	if err != nil {
		return nil, err
	}
	bans := make([]domain.IPBanEntry, 0, len(rows))
	for _, r := range rows {
		created, _ := time.Parse(time.RFC3339, r.String("created_at"))
		var expPtr *time.Time
		if expStr := r.String("expires_at"); expStr != "" {
			if exp, errP := time.Parse(time.RFC3339, expStr); errP == nil {
				expPtr = &exp
			}
		}
		bans = append(bans, domain.IPBanEntry{
			IPAddress:   r.String("ip_address"),
			Reason:      r.String("reason"),
			RiskScore:   r.Int("risk_score"),
			Source:      r.String("source"),
			BlockedHits: r.Int("blocked_hits"),
			ExpiresAt:   expPtr,
			CreatedAt:   created,
		})
	}
	return bans, nil
}

func (s *ProtectionService) AddBan(ip, reason, source string, riskScore int, ttlMinutes ...int) error {
	if s.db == nil {
		return nil
	}
	if reason == "" {
		reason = "Bannissement manuel SOC"
	}
	if source == "" {
		source = "MANUAL_SOC"
	}
	if riskScore <= 0 {
		riskScore = 95
	}
	expiresExpr := "NULL"
	if len(ttlMinutes) > 0 && ttlMinutes[0] > 0 {
		expiresExpr = fmt.Sprintf("CURRENT_TIMESTAMP + INTERVAL '%d minutes'", ttlMinutes[0])
	} else if source == "AUTO_JAIL_WAF" {
		expiresExpr = "CURRENT_TIMESTAMP + INTERVAL '15 minutes'"
	}

	err := s.db.Exec(fmt.Sprintf(`
		INSERT INTO ip_ban_list (ip_address, reason, risk_score, source, expires_at, created_at)
		VALUES (%s, %s, %d, %s, %s, CURRENT_TIMESTAMP)
		ON CONFLICT (ip_address) DO UPDATE SET
			reason = EXCLUDED.reason,
			risk_score = EXCLUDED.risk_score,
			source = EXCLUDED.source,
			expires_at = EXCLUDED.expires_at,
			blocked_hits = ip_ban_list.blocked_hits + 1,
			created_at = CURRENT_TIMESTAMP;`,
		database.QuoteLiteral(ip),
		database.QuoteLiteral(reason),
		riskScore,
		database.QuoteLiteral(source),
		expiresExpr,
	))
	if err == nil {
		s.Propagate()
	}
	return err
}

func (s *ProtectionService) RemoveBan(ip string) error {
	if s.db == nil {
		return nil
	}
	err := s.db.Exec(fmt.Sprintf("DELETE FROM ip_ban_list WHERE ip_address = %s;", database.QuoteLiteral(ip)))
	if err == nil {
		s.Propagate()
	}
	return err
}

func (s *ProtectionService) GetRetention() (domain.RetentionConfig, error) {
	cfg := domain.RetentionConfig{
		HotWindowDays:     30,
		AnssiForensicDays: 180,
		RgpdCleanIPDays:   7,
		MaxPayloadBytes:   32768,
		AutoBanThreshold:  3,
	}
	if s.db == nil {
		return cfg, nil
	}
	row, err := s.db.QueryRow("SELECT hot_window_days, anssi_forensic_days, rgpd_clean_ip_days, max_payload_bytes, auto_ban_threshold FROM system_retention_config WHERE id = 1 LIMIT 1;")
	if err != nil {
		return cfg, nil
	}
	if v := row.Int("hot_window_days"); v > 0 {
		cfg.HotWindowDays = v
	}
	if v := row.Int("anssi_forensic_days"); v > 0 {
		cfg.AnssiForensicDays = v
	}
	if v := row.Int("rgpd_clean_ip_days"); v > 0 {
		cfg.RgpdCleanIPDays = v
	}
	if v := row.Int("max_payload_bytes"); v >= 1024 {
		cfg.MaxPayloadBytes = v
	}
	if v := row.Int("auto_ban_threshold"); v > 0 {
		cfg.AutoBanThreshold = v
	}
	return cfg, nil
}

func (s *ProtectionService) UpdateRetention(cfg domain.RetentionConfig) error {
	if s.db == nil {
		return nil
	}
	err := s.db.Exec(fmt.Sprintf(`
		UPDATE system_retention_config
		SET hot_window_days = %d,
		    anssi_forensic_days = %d,
		    rgpd_clean_ip_days = %d,
		    max_payload_bytes = %d,
		    auto_ban_threshold = %d,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = 1;`,
		cfg.HotWindowDays,
		cfg.AnssiForensicDays,
		cfg.RgpdCleanIPDays,
		cfg.MaxPayloadBytes,
		cfg.AutoBanThreshold,
	))
	if err == nil {
		s.SetMaxPayloadBytes(cfg.MaxPayloadBytes)
	}
	return err
}

func (s *ProtectionService) RunRetentionPurge() (map[string]int, error) {
	purged := map[string]int{
		"ingress_purged": 0,
		"egress_purged":  0,
		"energy_purged":  0,
	}
	if s.db == nil {
		return purged, nil
	}
	cfg, _ := s.GetRetention()
	_ = s.db.Exec(fmt.Sprintf("DELETE FROM security_audit_logs WHERE timestamp < NOW() - INTERVAL '%d days';", cfg.AnssiForensicDays))
	_ = s.db.Exec(fmt.Sprintf("DELETE FROM egress_security_logs WHERE timestamp < NOW() - INTERVAL '%d days';", cfg.AnssiForensicDays))
	_ = s.db.Exec("DELETE FROM telemetry_energy_metrics WHERE timestamp < NOW() - INTERVAL '90 days';")
	return purged, nil
}

func (s *ProtectionService) ResetAll() error {
	if s.db == nil {
		return nil
	}
	err := s.db.Exec("TRUNCATE TABLE security_audit_logs, egress_security_logs, ip_ban_list RESTART IDENTITY CASCADE;")
	s.Propagate()
	return err
}
