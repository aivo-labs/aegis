package config

import (
	"os"
	"strconv"
)

// Config centralise les paramètres d'exécution du Control Plane Go.
type Config struct {
	Port                   string
	DatabaseURL            string
	DefaultTenantID        string
	GateProxyURL           string
	EgressGatewayURL       string
	DefaultMaxPayloadBytes int
	DefaultProtection      bool
}

// Load charge la configuration depuis l'environnement.
func Load() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgresql://aegis_user:aegis_dev_password@timescaledb:5432/aegis_db"
	}

	gateProxyURL := os.Getenv("GATE_PROXY_URL")
	if gateProxyURL == "" {
		gateProxyURL = "http://gate-proxy:8000"
	}

	egressGatewayURL := os.Getenv("EGRESS_GATEWAY_URL")
	if egressGatewayURL == "" {
		egressGatewayURL = "http://egress-gateway:5053"
	}

	maxPayload := 32768
	if envMax := os.Getenv("AEGIS_MAX_PAYLOAD_BYTES"); envMax != "" {
		if v, err := strconv.Atoi(envMax); err == nil && v >= 1024 {
			maxPayload = v
		}
	}

	return &Config{
		Port:                   port,
		DatabaseURL:            dbURL,
		DefaultTenantID:        "00000000-0000-0000-0000-000000000001",
		GateProxyURL:           gateProxyURL,
		EgressGatewayURL:       egressGatewayURL,
		DefaultMaxPayloadBytes: maxPayload,
		DefaultProtection:      os.Getenv("AEGIS_PROTECTION_ENABLED") != "false",
	}
}
