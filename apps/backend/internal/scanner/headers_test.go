package scanner

import (
	"net/http"
	"testing"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

func TestAnalyzeSecurityHeaders(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")

	dns := domain.DNSAnalysis{
		HasSPF:   true,
		HasDMARC: true,
	}

	var cves []domain.CVEWarning
	checks, score := AnalyzeSecurityHeaders(headers, true, dns, &cves)

	if score != 100 {
		t.Errorf("AnalyzeSecurityHeaders() expected score 100 with all headers, got %d", score)
	}
	if len(checks) != 5 {
		t.Errorf("AnalyzeSecurityHeaders() expected 5 header checks, got %d", len(checks))
	}

	// Test missing headers and no HTTPS
	emptyHeaders := make(http.Header)
	emptyDNS := domain.DNSAnalysis{HasSPF: false, HasDMARC: false}
	var emptyCVEs []domain.CVEWarning
	_, degradedScore := AnalyzeSecurityHeaders(emptyHeaders, false, emptyDNS, &emptyCVEs)

	if degradedScore >= 100 {
		t.Errorf("AnalyzeSecurityHeaders() expected lower score for missing headers, got %d", degradedScore)
	}
	if len(emptyCVEs) == 0 {
		t.Errorf("AnalyzeSecurityHeaders() expected CVE warnings for missing SPF/DMARC and CSP")
	}

	// Test 3: Site avec en-têtes parfaits mais 3 CVEs critiques (cas homebox.fr)
	// Doit déduire 3 * 15 = 45 points -> score 55/100
	cveWarnings := []domain.CVEWarning{
		{ID: "CVE-2024-4577", Severity: "CRITICAL", CVSS: "9.8"},
		{ID: "CVE-2026-109618", Severity: "CRITICAL", CVSS: "9.8"},
		{ID: "CVE-2025-29927", Severity: "CRITICAL", CVSS: "9.1"},
	}
	_, cveScore := AnalyzeSecurityHeaders(headers, true, dns, &cveWarnings)
	if cveScore != 55 {
		t.Errorf("AnalyzeSecurityHeaders() expected score 55 with 3 CRITICAL CVEs, got %d", cveScore)
	}
}
