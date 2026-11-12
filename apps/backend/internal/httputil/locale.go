package httputil

import (
	"net/http"
	"strings"
)

// SupportedLocales liste les langues prises en charge par le backend Aegis.
var SupportedLocales = map[string]bool{
	"fr": true,
	"en": true,
}

// ResolveLocale extrait la langue demandée ('fr' ou 'en') selon les priorités suivantes :
// 1. Paramètre query "?lang=" ou "?locale=" (ex: ?lang=en)
// 2. En-tête HTTP "Accept-Language" (ex: "en-US,en;q=0.9,fr;q=0.8")
// 3. Langue par défaut fournie (ou "fr" par défaut si non spécifiée).
func ResolveLocale(r *http.Request, defaultLocale ...string) string {
	def := "fr"
	if len(defaultLocale) > 0 && defaultLocale[0] != "" {
		def = strings.ToLower(strings.TrimSpace(defaultLocale[0]))
	}

	if r == nil {
		return def
	}

	// 1. Query parameter
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang"))); q != "" {
		if normalizeLocale(q) != "" {
			return normalizeLocale(q)
		}
	}
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("locale"))); q != "" {
		if normalizeLocale(q) != "" {
			return normalizeLocale(q)
		}
	}

	// 2. Accept-Language header
	if accept := r.Header.Get("Accept-Language"); accept != "" {
		for _, part := range strings.Split(accept, ",") {
			tag := strings.TrimSpace(strings.Split(part, ";")[0])
			if loc := normalizeLocale(tag); loc != "" {
				return loc
			}
		}
	}

	return def
}

func normalizeLocale(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if len(tag) >= 2 {
		prefix := tag[:2]
		if SupportedLocales[prefix] {
			return prefix
		}
	}
	return ""
}
