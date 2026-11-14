package scanner

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvaluateTLSConnectionState_PQCReady(t *testing.T) {
	state := tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		CurveID:     tls.X25519MLKEM768,
	}

	res := EvaluateTLSConnectionState(state)
	if !res.PostQuantumReady {
		t.Fatalf("expected PostQuantumReady=true for X25519MLKEM768, got false")
	}
	if res.Standard != "NIST FIPS 203 (X25519MLKEM768)" {
		t.Errorf("unexpected Standard: %s", res.Standard)
	}
	if !strings.Contains(res.NegotiatedCurve, "X25519MLKEM768") {
		t.Errorf("expected NegotiatedCurve to contain X25519MLKEM768, got %s", res.NegotiatedCurve)
	}
	if len(res.RemediationSnippets) != 0 {
		t.Errorf("expected no RemediationSnippets when PQC is already enabled, got %d", len(res.RemediationSnippets))
	}
}

func TestEvaluateTLSConnectionState_ClassicalECDHE(t *testing.T) {
	state := tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_256_GCM_SHA384,
		CurveID:     tls.X25519,
	}

	res := EvaluateTLSConnectionState(state)
	if res.PostQuantumReady {
		t.Fatalf("expected PostQuantumReady=false for classical X25519, got true")
	}
	if res.Standard != "Classical ECDHE (Non-PQC)" {
		t.Errorf("unexpected Standard: %s", res.Standard)
	}
	if !strings.Contains(res.HNDLRisk, "HIGH") {
		t.Errorf("expected HIGH HNDLRisk for classical X25519, got %s", res.HNDLRisk)
	}
	for _, key := range []string{"traefik", "nginx", "caddy", "go_tls"} {
		if snippet, ok := res.RemediationSnippets[key]; !ok || !strings.Contains(snippet, "X25519MLKEM768") && !strings.Contains(snippet, "x25519mlkem768") {
			t.Errorf("expected valid remediation snippet for %s, got %q", key, snippet)
		}
	}
}

func TestLiveTLS13Handshake_NegotiatesX25519MLKEM768(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
	}
	srv.StartTLS()
	defer srv.Close()

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
	})
	if err != nil {
		t.Fatalf("failed to dial local TLS 1.3 server: %v", err)
	}
	defer conn.Close()

	analysis := EvaluateTLSConnectionState(conn.ConnectionState())
	if !analysis.PostQuantumReady {
		t.Fatalf("expected live Go 1.24+ TLS 1.3 handshake to negotiate X25519MLKEM768, got curve=%s", analysis.NegotiatedCurve)
	}
}
