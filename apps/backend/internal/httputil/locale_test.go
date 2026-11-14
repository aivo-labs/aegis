package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveLocale(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		header        string
		defaultLocale string
		expected      string
	}{
		{
			name:     "default fallback without header or query",
			query:    "",
			header:   "",
			expected: "fr",
		},
		{
			name:          "custom default fallback",
			query:         "",
			header:        "",
			defaultLocale: "en",
			expected:      "en",
		},
		{
			name:     "query parameter lang=en",
			query:    "?lang=en",
			header:   "fr-FR,fr;q=0.9",
			expected: "en",
		},
		{
			name:     "query parameter locale=fr",
			query:    "?locale=fr",
			header:   "en-US,en;q=0.9",
			expected: "fr",
		},
		{
			name:     "accept-language en-US header",
			query:    "",
			header:   "en-US,en;q=0.9,fr;q=0.8",
			expected: "en",
		},
		{
			name:     "accept-language fr header",
			query:    "",
			header:   "fr-FR,fr;q=0.9",
			expected: "fr",
		},
		{
			name:     "unsupported language fallback to default",
			query:    "?lang=de",
			header:   "es-ES,es;q=0.8",
			expected: "fr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := "/api/v1/cve/feed" + tt.query
			req := httptest.NewRequest(http.MethodGet, target, nil)
			if tt.header != "" {
				req.Header.Set("Accept-Language", tt.header)
			}

			var got string
			if tt.defaultLocale != "" {
				got = ResolveLocale(req, tt.defaultLocale)
			} else {
				got = ResolveLocale(req)
			}

			if got != tt.expected {
				t.Errorf("ResolveLocale() = %q, expected %q", got, tt.expected)
			}
		})
	}
}
