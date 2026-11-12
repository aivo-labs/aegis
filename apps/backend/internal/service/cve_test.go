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
