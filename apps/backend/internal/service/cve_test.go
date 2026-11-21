package service

import (
	"strings"
	"testing"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

func TestCveService_GetFeed(t *testing.T) {
	svc := NewCveService()

	// 1. Test FR par défaut
	feedFR := svc.GetFeed()
	if len(feedFR) == 0 {
		t.Fatalf("GetFeed() returned empty slice")
	}

	var php2ShellFR *domain.CVEWarning
	for _, cve := range feedFR {
		if cve.ID == "CVE-2026-109618" {
			found := cve
			php2ShellFR = &found
			break
		}
	}
	if php2ShellFR == nil {
		t.Fatalf("Expected CVE-2026-109618 in FR feed")
	}
	if php2ShellFR.Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL severity, got %s", php2ShellFR.Severity)
	}
	if !php2ShellFR.BlockedByAegis {
		t.Errorf("Expected BlockedByAegis = true")
	}
	if !strings.Contains(php2ShellFR.Title, "Dépassement de tampon") {
		t.Errorf("Expected French title for CVE-2026-109618, got %q", php2ShellFR.Title)
	}
	if !strings.Contains(php2ShellFR.Remediation, "Activer le coupe-circuit") {
		t.Errorf("Expected French remediation for CVE-2026-109618, got %q", php2ShellFR.Remediation)
	}

	// 2. Test EN explicite
	feedEN := svc.GetFeed("en")
	if len(feedEN) != len(feedFR) {
		t.Errorf("Expected same count for EN feed (%d vs %d)", len(feedEN), len(feedFR))
	}

	var php2ShellEN *domain.CVEWarning
	for _, cve := range feedEN {
		if cve.ID == "CVE-2026-109618" {
			found := cve
			php2ShellEN = &found
			break
		}
	}
	if php2ShellEN == nil {
		t.Fatalf("Expected CVE-2026-109618 in EN feed")
	}
	if !strings.Contains(php2ShellEN.Title, "Volumetric Buffer/Heap Overflow") {
		t.Errorf("Expected English title for CVE-2026-109618, got %q", php2ShellEN.Title)
	}
	if !strings.Contains(php2ShellEN.Remediation, "Enable Aegis Gate 32 KB") {
		t.Errorf("Expected English remediation for CVE-2026-109618, got %q", php2ShellEN.Remediation)
	}
	if len(php2ShellEN.RootFixProcedure) == 0 || !strings.Contains(php2ShellEN.RootFixProcedure[0], "Upgrade PHP packages") {
		t.Errorf("Expected English root fix procedure, got %+v", php2ShellEN.RootFixProcedure)
	}

	// 3. Test VerifyCoverage
	report := svc.VerifyCoverage("en")
	if !report.AllProceduresDocumented {
		t.Errorf("Expected all CVEs in catalog to have RootFixProcedure and VerificationProbe documented")
	}
	if report.CoveredVirtualPatchCount < 6 {
		t.Errorf("Expected at least 6 CVEs covered by Virtual Patch, got %d", report.CoveredVirtualPatchCount)
	}
	if report.HostPatchRequiredCount < 1 {
		t.Errorf("Expected at least 1 CVE classified as HOST_PATCH_REQUIRED, got %d", report.HostPatchRequiredCount)
	}

	// 4. Test Active Rules
	rulesEN := svc.GetActiveRules("en")
	if !strings.Contains(rulesEN["WAF-413-VOLUMETRIC"], "volumetric circuit-breaker") {
		t.Errorf("Expected English text for WAF-413-VOLUMETRIC, got %q", rulesEN["WAF-413-VOLUMETRIC"])
	}
	rulesFR := svc.GetActiveRules("fr")
	if !strings.Contains(rulesFR["WAF-413-VOLUMETRIC"], "Coupe-circuit volumétrique") {
		t.Errorf("Expected French text for WAF-413-VOLUMETRIC, got %q", rulesFR["WAF-413-VOLUMETRIC"])
	}
}

func TestCveService_SyncCertFrFromReader(t *testing.T) {
	svc := NewCveService()

	// Mock RSS 2.0 CERT-FR
	mockXML := `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Alertes de sécurité CERT-FR</title>
    <lastBuildDate>Wed, 18 Nov 2026 18:00:00 +0100</lastBuildDate>
    <item>
      <title>[CERTFR-2026-ALE-016] Vulnérabilité dans Keycloak (Java4Shell CVE-2026-114938)</title>
      <link>https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-016/</link>
      <description>Une vulnérabilité critique CVE-2026-114938 a été identifiée.</description>
      <pubDate>Wed, 18 Nov 2026 12:00:00 +0100</pubDate>
    </item>
    <item>
      <title>[CERTFR-2026-ALE-099] Multiples vulnérabilités dans ExempleLib (CVE-2026-99999)</title>
      <link>https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-099/</link>
      <description>Exécution de code arbitraire critique dans ExempleLib sous condition réseau.</description>
      <pubDate>Wed, 18 Nov 2026 14:00:00 +0100</pubDate>
    </item>
  </channel>
</rss>`

	report, err := svc.SyncCertFrFromReader(strings.NewReader(mockXML), "fr")
	if err != nil {
		t.Fatalf("SyncCertFrFromReader failed: %v", err)
	}

	if report.AlertsParsed != 2 {
		t.Errorf("Expected 2 alerts parsed, got %d", report.AlertsParsed)
	}
	if report.AlreadyCurated < 1 {
		t.Errorf("Expected at least 1 already curated CVE (CVE-2026-114938), got %d", report.AlreadyCurated)
	}
	if report.NewIngested != 1 {
		t.Errorf("Expected 1 new ingested CVE (CVE-2026-99999), got %d", report.NewIngested)
	}

	// Vérifier l'apparition dans GetFeed
	feed := svc.GetFeed("fr")
	var newCve *domain.CVEWarning
	for _, c := range feed {
		if c.ID == "CVE-2026-99999" {
			found := c
			newCve = &found
			break
		}
	}

	if newCve == nil {
		t.Fatalf("Expected CVE-2026-99999 in feed after sync")
	}
	if newCve.CoverageStatus != "PENDING_VERIFICATION" {
		t.Errorf("Expected CoverageStatus PENDING_VERIFICATION, got %s", newCve.CoverageStatus)
	}
	if !strings.Contains(newCve.VirtualPatchSummary, "Procédure en cours de vérification") {
		t.Errorf("Expected summary mentioning procedure en cours de vérification, got %q", newCve.VirtualPatchSummary)
	}
	if newCve.Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL severity, got %s", newCve.Severity)
	}

	// Vérifier CoverageReport
	covReport := svc.VerifyCoverage("fr")
	if covReport.PendingVerificationCount != 1 {
		t.Errorf("Expected 1 pending verification, got %d", covReport.PendingVerificationCount)
	}
}

func TestAuditService_DriftAndRemediation(t *testing.T) {
	prev := domain.PassiveAuditResult{
		Domain:        "aegis.aivo.fr",
		SecurityScore: 95,
		SecurityGrade: "A",
		PostQuantum: domain.PQCAnalysis{
			PostQuantumReady: true,
			NegotiatedCurve:  "X25519MLKEM768 (0x11ec)",
		},
		HeadersAnalysis: []domain.HeaderCheck{
			{Header: "Strict-Transport-Security", Present: true},
			{Header: "Content-Security-Policy", Present: true},
		},
	}

	curr := domain.PassiveAuditResult{
		Domain:        "aegis.aivo.fr",
		SecurityScore: 68,
		SecurityGrade: "C",
		PostQuantum: domain.PQCAnalysis{
			PostQuantumReady: false,
			NegotiatedCurve:  "X25519",
		},
		HeadersAnalysis: []domain.HeaderCheck{
			{Header: "Strict-Transport-Security", Present: true},
			{Header: "Content-Security-Policy", Present: false},
		},
		CVEWarnings: []domain.CVEWarning{
			{ID: "CVE-2026-109618", Severity: "CRITICAL"},
		},
	}

	drifts := EvaluatePostureDrift(prev, curr)
	if len(drifts) < 3 {
		t.Fatalf("Expected at least 3 drift alerts (score, PQC, header, CVE), got %d: %+v", len(drifts), drifts)
	}

	snippets := GenerateGuidedRemediationSnippets(curr)
	for _, key := range []string{"traefik", "nginx", "caddy", "apache_php"} {
		if !strings.Contains(snippets[key], "X-Content-Type-Options") && !strings.Contains(snippets[key], "contentTypeNosniff") {
			t.Errorf("Expected security headers in snippet %s", key)
		}
	}

	auditSvc := NewAuditService(nil)
	cfg := auditSvc.UpdateScheduleConfig(true, "aegis.aivo.fr", 6)
	if !cfg.Enabled || cfg.IntervalHours != 6 || cfg.TargetDomain != "aegis.aivo.fr" {
		t.Errorf("Unexpected schedule config: %+v", cfg)
	}
}
