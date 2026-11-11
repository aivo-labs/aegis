package service

import (
	"testing"
)

func TestCveService_GetFeed(t *testing.T) {
	svc := NewCveService()
	feed := svc.GetFeed()

	if len(feed) == 0 {
		t.Fatalf("GetFeed() returned empty slice")
	}

	foundPHP2Shell := false
	for _, cve := range feed {
		if cve.ID == "CVE-2026-109618" {
			foundPHP2Shell = true
			if cve.Severity != "CRITICAL" {
				t.Errorf("Expected CRITICAL severity for CVE-2026-109618, got %s", cve.Severity)
			}
			if !cve.BlockedByAegis {
				t.Errorf("Expected BlockedByAegis = true for CVE-2026-109618")
			}
		}
	}

	if !foundPHP2Shell {
		t.Errorf("Expected CVE-2026-109618 in feed")
	}

	report := svc.VerifyCoverage()
	if !report.AllProceduresDocumented {
		t.Errorf("Expected all CVEs in catalog to have RootFixProcedure and VerificationProbe documented")
	}
	if report.CoveredVirtualPatchCount < 6 {
		t.Errorf("Expected at least 6 CVEs covered by Virtual Patch, got %d", report.CoveredVirtualPatchCount)
	}
	if report.HostPatchRequiredCount < 1 {
		t.Errorf("Expected at least 1 CVE classified as HOST_PATCH_REQUIRED (e.g. regreSSHion), got %d", report.HostPatchRequiredCount)
	}
}
