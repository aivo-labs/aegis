package scanner

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

const (
	// CurveX25519MLKEM768 est le groupe hybride post-quantique standardisé NIST FIPS 203 (0x11ec).
	CurveX25519MLKEM768 = tls.X25519MLKEM768
	// CurveX25519Kyber768Draft00 est le groupe pré-standard IETF Kyber768 (0x6399).
	CurveX25519Kyber768Draft00 = tls.CurveID(0x6399)
)

// DefaultPQCRemediationSnippets fournit les configurations prêtes au copier-coller pour activer X25519MLKEM768.
func DefaultPQCRemediationSnippets() map[string]string {
	return map[string]string{
		"traefik": "tls:\n  options:\n    default:\n      minVersion: VersionTLS13\n      curvePreferences:\n        - X25519MLKEM768\n        - X25519\n        - CurveP256",
		"nginx":   "ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;",
		"caddy":   "tls {\n    protocols tls1.3\n    curves x25519mlkem768 x25519 secp256r1\n}",
		"go_tls":  "tlsConfig := &tls.Config{\n    MinVersion: tls.VersionTLS13,\n    CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},\n}",
	}
}

// formatCurveID retourne le nom lisible du groupe d'échange de clés TLS négocié.
func formatCurveID(id tls.CurveID) string {
	switch id {
	case CurveX25519MLKEM768:
		return "X25519MLKEM768 (0x11ec)"
	case CurveX25519Kyber768Draft00:
		return "X25519Kyber768Draft00 (0x6399)"
	case tls.X25519:
		return "X25519 (0x001d)"
	case tls.CurveP256:
		return "P-256 (0x0017)"
	case tls.CurveP384:
		return "P-384 (0x0018)"
	case tls.CurveP521:
		return "P-521 (0x0019)"
	case 0:
		return "UNKNOWN"
	default:
		return id.String()
	}
}

// EvaluateTLSConnectionState évalue si un état de connexion TLS utilise un échange de clés hybride post-quantique.
func EvaluateTLSConnectionState(state tls.ConnectionState) domain.PQCAnalysis {
	tlsVer := tls.VersionName(state.Version)
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	curveName := formatCurveID(state.CurveID)

	switch state.CurveID {
	case CurveX25519MLKEM768:
		return domain.PQCAnalysis{
			PostQuantumReady: true,
			TLSVersion:       tlsVer,
			CipherSuite:      cipherName,
			NegotiatedCurve:  curveName,
			Standard:         "NIST FIPS 203 (X25519MLKEM768)",
			HNDLRisk:         "LOW — Protégé contre les attaques Harvest Now, Decrypt Later (HNDL) via encapsulation hybride X25519 + ML-KEM-768.",
		}
	case CurveX25519Kyber768Draft00:
		return domain.PQCAnalysis{
			PostQuantumReady:    true,
			TLSVersion:          tlsVer,
			CipherSuite:         cipherName,
			NegotiatedCurve:     curveName,
			Standard:            "IETF Draft (X25519Kyber768Draft00 — Migration FIPS 203 recommandée)",
			HNDLRisk:            "MODERATE — Hybride post-quantique pré-standard détecté ; migrer vers X25519MLKEM768 (FIPS 203).",
			RemediationSnippets: DefaultPQCRemediationSnippets(),
		}
	default:
		return domain.PQCAnalysis{
			PostQuantumReady:    false,
			TLSVersion:          tlsVer,
			CipherSuite:         cipherName,
			NegotiatedCurve:     curveName,
			Standard:            "Classical ECDHE (Non-PQC)",
			HNDLRisk:            "HIGH — Échange de clés elliptique classique vulnérable à la collecte rétroactive Harvest Now, Decrypt Later (HNDL).",
			RemediationSnippets: DefaultPQCRemediationSnippets(),
		}
	}
}

// InspectDomainPQC effectue un handshake TLS 1.3 passif en proposant X25519MLKEM768 pour vérifier la maturité post-quantique.
func InspectDomainPQC(domainName string) domain.PQCAnalysis {
	host := strings.TrimSpace(domainName)
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "web" {
		return domain.PQCAnalysis{
			PostQuantumReady:    false,
			TLSVersion:          "NONE",
			CipherSuite:         "NONE",
			NegotiatedCurve:     "NONE",
			Standard:            "Non-TLS / Local Target",
			HNDLRisk:            "HIGH — Aucun canal TLS post-quantique détecté sur la cible locale.",
			RemediationSnippets: DefaultPQCRemediationSnippets(),
		}
	}

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Audit passif de la couche cryptographique quel que soit l'état du certificat X.509
		MinVersion:         tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			CurveX25519MLKEM768,
			CurveX25519Kyber768Draft00,
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	})
	if err != nil {
		return domain.PQCAnalysis{
			PostQuantumReady:    false,
			TLSVersion:          "UNREACHABLE",
			CipherSuite:         "NONE",
			NegotiatedCurve:     "NONE",
			Standard:            "TLS Handshake Failed",
			HNDLRisk:            "HIGH — Impossible d'établir un handshake TLS 1.3 post-quantique sur le port 443.",
			RemediationSnippets: DefaultPQCRemediationSnippets(),
		}
	}
	defer conn.Close()

	return EvaluateTLSConnectionState(conn.ConnectionState())
}
