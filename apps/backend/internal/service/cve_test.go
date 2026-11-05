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
}
