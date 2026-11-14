package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://Aegis.Aivo.FR/", "aegis.aivo.fr"},
		{"http://example.com/some/path", "example.com"},
		{"  sub.domain.org/   ", "sub.domain.org"},
		{"LOCALHOST", "localhost"},
		{"", ""},
	}

	for _, c := range cases {
		if got := NormalizeDomain(c.input); got != c.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestCreateOwnershipVerification(t *testing.T) {
	// Erreur si domaine ou email vide
	_, err := CreateOwnershipVerification(nil, "", "", "")
	if err == nil {
		t.Error("attendu erreur pour domaine et email vides")
	}

	// Succès génération jeton DNS TXT
	res, err := CreateOwnershipVerification(nil, "https://mon-entreprise.fr", "security@mon-entreprise.fr", "Entreprise SAS")
	if err != nil {
		t.Fatalf("erreur inattendue: %v", err)
	}

	if res["domain"] != "mon-entreprise.fr" {
		t.Errorf("domaine incorrect: %v", res["domain"])
	}
	token, ok := res["dns_record_value"].(string)
	if !ok || !strings.HasPrefix(token, "aegis-site-verification=aegis_verify_") {
		t.Errorf("format du jeton DNS TXT invalide: %v", token)
	}
}

func TestVerifyDomainAndRunDeepAudit_LocalSandbox(t *testing.T) {
	// Sans mandat légal accepté -> Erreur obligatoire (Art. 323-1 CP)
	_, err := VerifyDomainAndRunDeepAudit(nil, "localhost", "admin@local", false, "127.0.0.1", "TestAgent")
	if err == nil {
		t.Error("attendu rejet si mandat légal non accepté")
	}

	// Avec mandat légal accepté sur localhost -> Validé
	res, err := VerifyDomainAndRunDeepAudit(nil, "localhost", "admin@local", true, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("erreur inattendue: %v", err)
	}

	if res["verified"] != true {
		t.Errorf("domaine localhost non vérifié: %v", res)
	}
	hash, ok := res["contract_sha256"].(string)
	if !ok || len(hash) != 64 {
		t.Errorf("empreinte contractuelle SHA-256 invalide: %v", hash)
	}
	findings, ok := res["deep_findings"].([]map[string]any)
	if !ok || len(findings) == 0 {
		t.Errorf("sondes niveau 2 attendues, obtenu: %v", findings)
	}
}

func TestVerifyDomainAndRunDeepAudit_PublicDomainRejectsWithoutDNS(t *testing.T) {
	// Un domaine public sans enregistrement DNS TXT ni fichier /.well-known/aegis-verify.txt
	// doit être strictement rejeté même si le mandat légal est coché.
	_, err := VerifyDomainAndRunDeepAudit(nil, "unverified-domain-example.invalid", "admin@example.invalid", true, "127.0.0.1", "TestAgent")
	if err == nil {
		t.Error("attendu rejet strict pour un domaine public sans jeton DNS TXT ni fichier .well-known")
	}
}

func TestPassiveAuditJSONSlices_NonNull(t *testing.T) {
	res := RunPassiveDomainScan(nil, "localhost")
	enrichAuditResult(&res)

	cveJSON, err := json.Marshal(res.CVEWarnings)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if string(cveJSON) == "null" {
		t.Errorf("CVEWarnings serialized to 'null', want '[]' to avoid TimescaleDB scalar array length errors")
	}
	if string(cveJSON) != "[]" && !strings.HasPrefix(string(cveJSON), "[") {
		t.Errorf("expected JSON array, got: %s", string(cveJSON))
	}
}

