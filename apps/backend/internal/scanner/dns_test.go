package scanner

import (
	"reflect"
	"testing"
)

func TestGetParentDomains(t *testing.T) {
	tests := []struct {
		domain   string
		expected []string
	}{
		{"baud.dev", nil},
		{"aivo.fr", nil},
		{"test.baud.dev", []string{"baud.dev"}},
		{"sub.test.baud.dev", []string{"test.baud.dev", "baud.dev"}},
		{"a.b.c.baud.dev", []string{"b.c.baud.dev", "c.baud.dev", "baud.dev"}},
		{"localhost", nil},
		{"", nil},
		{"sub.domain.co.uk", []string{"domain.co.uk", "co.uk"}},
	}

	for _, tt := range tests {
		result := getParentDomains(tt.domain)
		if !reflect.DeepEqual(result, tt.expected) {
			t.Errorf("getParentDomains(%q) = %v; want %v", tt.domain, result, tt.expected)
		}
	}
}

func TestInspectDomainDNS_RealApex(t *testing.T) {
	// Test de non-régression sur un domaine public connu (google.com)
	res := InspectDomainDNS("google.com")
	if len(res.ResolvedIPs) == 0 {
		t.Logf("DNS lookup for google.com returned no IPs (possibly offline/sandboxed)")
	}
	// HasSPF and HasDMARC shouldn't crash
	t.Logf("google.com: HasSPF=%v, HasDMARC=%v", res.HasSPF, res.HasDMARC)
}
