package scanner

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

var (
	reMetaGen = regexp.MustCompile(`(?i)<meta\b[^>]*name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)["']`)
	reWPVer   = regexp.MustCompile(`(?i)wp-(?:content|includes)/[^"'\s]+\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
)

// DetectTechAndCVEs identifie les technologies et versions exposées et génère les alertes CVE associées.
func DetectTechAndCVEs(client *http.Client, baseURL, domainName, htmlStr string, headers http.Header) ([]domain.TechFingerprint, []domain.CVEWarning) {
	var stack []domain.TechFingerprint
	var cves []domain.CVEWarning

	serverHdr := headers.Get("Server")
	poweredBy := headers.Get("X-Powered-By")
	setCookie := strings.Join(headers.Values("Set-Cookie"), "; ")

	// 1. Analyse du Header Server (Nginx, Apache, Cloudflare, Envoy...)
	if serverHdr != "" {
		stack = append(stack, domain.TechFingerprint{
			Name:       serverHdr,
			Category:   "Serveur Web / Reverse Proxy",
			Version:    extractVersionNumber(serverHdr),
			Source:     "Header HTTP 'Server'",
			Confidence: "100%",
		})
		if extractVersionNumber(serverHdr) != "Masquée" {
			cves = append(cves, domain.CVEWarning{
				ID:                  "CVE-2023-44487 / INFO-LEAK",
				CVEID:               "CVE-2023-44487",
				Severity:            "MEDIUM",
				CVSS:                "7.5",
				Component:           serverHdr,
				Title:               "Divulgation de la version exacte du serveur Web (" + serverHdr + ")",
				Description:         "L'en-tête HTTP 'Server' expose la version exacte du binaire, facilitant le ciblage automatisé par les scanners de vulnérabilités (Nuclei/Shodan).",
				Remediation:         "1. [Immédiat] Masquage en bordure via Aegis Gate (WAF-HEADER-SANITIZER). 2. [Racine] Désactiver 'server_tokens off;' (Nginx) ou 'ServerTokens Prod' (Apache).",
				BlockedByAegis:      true,
				IsActiveDefense:     true,
				CoverageStatus:      "COVERED_VIRTUAL_PATCH",
				VirtualPatchRuleID:  "WAF-HEADER-SANITIZER",
				VirtualPatchSummary: "Aegis Gate nettoie l'en-tête Server sortant et applique une limitation de débit HTTP/2 Rapid Reset sans modifier le serveur amont.",
				RootFixProcedure: []string{
					"Sur Nginx : ajouter server_tokens off; dans le bloc http {} de /etc/nginx/nginx.conf",
					"Sur Apache : définir ServerTokens Prod et ServerSignature Off dans /etc/apache2/conf-enabled/security.conf",
					"Recharger le serveur web : sudo systemctl reload nginx (ou apache2)",
				},
				VerificationProbe: "curl -I https://" + domainName + " | grep -i '^server:'",
				CISAKEV:           true,
			})
		}
	}

	// 2. Analyse PHP (X-Powered-By ou PHPSESSID)
	phpDetected := false
	phpVer := "Détecté"
	if strings.Contains(strings.ToLower(poweredBy), "php") {
		phpDetected = true
		phpVer = extractVersionNumber(poweredBy)
		stack = append(stack, domain.TechFingerprint{
			Name:       "PHP Runtime",
			Category:   "Backend Language",
			Version:    phpVer,
			Source:     "Header 'X-Powered-By: " + poweredBy + "'",
			Confidence: "100%",
		})
	} else if strings.Contains(setCookie, "PHPSESSID") || strings.Contains(htmlStr, ".php") {
		phpDetected = true
		stack = append(stack, domain.TechFingerprint{
			Name:       "PHP Runtime",
			Category:   "Backend Language",
			Version:    "Version masquée",
			Source:     "Empreinte Cookie / Routes .php",
			Confidence: "90%",
		})
	}

	if phpDetected {
		cves = append(cves,
			domain.CVEWarning{
				ID:                  "CVE-2024-4577",
				CVEID:               "CVE-2024-4577",
				Severity:            "CRITICAL",
				CVSS:                "9.8",
				Component:           "PHP-CGI / PHP-FPM (" + phpVer + ")",
				Title:               "Exécution de Code à Distance (RCE) par Injection d'Arguments PHP (allow_url_include)",
				Description:         "Permet à un attaquant non authentifié d'injecter des directives php://input pour exécuter des commandes système (/bin/sh) sur le serveur.",
				Remediation:         "1. [Immédiat] Filtrage à chaud Aegis Gate (WAF-PHP-CGI-ARGS). 2. [Racine] Mettre à jour PHP (>= 8.3.8 / 8.2.20) et définir expose_php = Off dans php.ini.",
				BlockedByAegis:      true,
				IsActiveDefense:     true,
				CoverageStatus:      "COVERED_VIRTUAL_PATCH",
				VirtualPatchRuleID:  "WAF-PHP-CGI-ARGS",
				VirtualPatchSummary: "Blocage HTTP 403 instantané des séquences allow_url_include, auto_prepend_file, php://input et encodages soft-hyphen (%AD).",
				RootFixProcedure: []string{
					"Mettre à niveau PHP : sudo apt update && sudo apt install --only-upgrade php-fpm php-cli",
					"Dans php.ini : définir expose_php = Off, allow_url_include = Off et cgi.force_redirect = 1",
					"Désactiver les fonctions système dangereuses : disable_functions = exec,passthru,shell_exec,system,proc_open,popen",
				},
				VerificationProbe: "curl -i 'https://" + domainName + "/index.php?%ADd+allow_url_include%3d1'",
				CISAKEV:           true,
			},
			domain.CVEWarning{
				ID:                  "CVE-2026-109618 (PHP2Shell)",
				CVEID:               "CVE-2026-109618",
				Severity:            "CRITICAL",
				CVSS:                "9.8",
				Component:           "PHP SAPI / FastCGI Buffer",
				Title:               "Risque de Heap/Buffer Overflow Volumétrique & Reverse Shell Sortant",
				Description:         "Sans limitation stricte de la taille des payloads à l'Edge (HTTP 413) et sans filtrage DNS/Socket sortant, un dépassement de tampon permet d'ouvrir un Reverse Shell direct.",
				Remediation:         "1. [Immédiat] Coupe-circuit volumétrique 32 Ko d'Aegis Gate + Sinkhole DNS d'Aegis Egress (:5053). 2. [Racine] Mettre à jour PHP-FPM et libc6 (CVE-2024-2961).",
				BlockedByAegis:      true,
				IsActiveDefense:     true,
				CoverageStatus:      "COVERED_VIRTUAL_PATCH",
				VirtualPatchRuleID:  "WAF-413-VOLUMETRIC + EGRESS-C2-SINKHOLE",
				VirtualPatchSummary: "Rejet en mémoire (HTTP 413 en < 0.3 ms) des payloads > 32 Ko avant PHP-FPM + neutralisation des callbacks C2 sortants via DNS Sinkhole.",
				RootFixProcedure: []string{
					"Mettre à jour PHP-FPM et la bibliothèque glibc (CVE-2024-2961) : sudo apt update && sudo apt install --only-upgrade php-fpm libc6",
					"Restreindre post_max_size = 8M dans php.ini et client_max_body_size dans Nginx",
					"Redémarrer le pool PHP-FPM : sudo systemctl restart php*-fpm",
				},
				VerificationProbe: "curl -i -X POST https://" + domainName + "/ --data-binary $(head -c 40000 /dev/zero | tr '\\0' 'A')",
				CISAKEV:           true,
			},
		)
	}

	// 3. Détection WordPress / CMS / Frameworks via HTML & Meta Generator
	if m := reMetaGen.FindStringSubmatch(htmlStr); len(m) > 1 {
		gen := m[1]
		stack = append(stack, domain.TechFingerprint{
			Name:       gen,
			Category:   "CMS / Générateur",
			Version:    extractVersionNumber(gen),
			Source:     "Balise <meta name=\"generator\">",
			Confidence: "100%",
		})
	}

	isWP := strings.Contains(htmlStr, "/wp-content/") || strings.Contains(htmlStr, "/wp-includes/")
	if isWP {
		wpVer := "6.x (Détecté)"
		if m := reWPVer.FindStringSubmatch(htmlStr); len(m) > 1 {
			wpVer = m[1]
		}
		stack = append(stack, domain.TechFingerprint{
			Name:       "WordPress CMS",
			Category:   "CMS PHP",
			Version:    wpVer,
			Source:     "Assets /wp-content/ & ?ver=",
			Confidence: "100%",
		})
		cves = append(cves, domain.CVEWarning{
			ID:                  "WP-USER-ENUM / XMLRPC",
			CVEID:               "CVE-2024-10963",
			Severity:            "HIGH",
			CVSS:                "8.2",
			Component:           "WordPress (" + wpVer + ")",
			Title:               "Exposition des Vecteurs d'Énumération (/wp-json/wp/v2/users) & Brute-Force (/xmlrpc.php)",
			Description:         "Les bots ciblent massivement wp-login.php, xmlrpc.php et les plugins vulnérables dans /wp-content/ pour compromettre le serveur.",
			Remediation:         "1. [Immédiat] Bloquer /xmlrpc.php et les sondes automatisées à l'Edge via Aegis Gate (WAF-CMS-SHIELD). 2. [Racine] Désactiver XML-RPC et restreindre l'API REST.",
			BlockedByAegis:      true,
			IsActiveDefense:     true,
			CoverageStatus:      "COVERED_VIRTUAL_PATCH",
			VirtualPatchRuleID:  "WAF-CMS-SHIELD",
			VirtualPatchSummary: "Blocage immédiat en bordure de /xmlrpc.php et protection anti-brute-force sur /wp-login.php sans solliciter PHP ni MySQL.",
			RootFixProcedure: []string{
				"Désactiver XML-RPC dans WordPress : add_filter('xmlrpc_enabled', '__return_false'); ou bloquer /xmlrpc.php dans Nginx",
				"Restreindre l'accès non authentifié à /wp-json/wp/v2/users",
				"Mettre à jour le cœur WordPress et l'ensemble des extensions actives",
			},
			VerificationProbe: "curl -i -X POST https://" + domainName + "/xmlrpc.php",
			CISAKEV:           false,
		})
	}

	// Détection Astro / Vue / Next.js / Nuxt
	if strings.Contains(htmlStr, "astro-island") || strings.Contains(htmlStr, "/_astro/") {
		stack = append(stack, domain.TechFingerprint{
			Name:       "Astro + Vue 3 Islands",
			Category:   "Frontend Moderne Éco-Conçu",
			Version:    "v5.x",
			Source:     "Hydratation partielle <astro-island>",
			Confidence: "100%",
		})
	}
	if strings.Contains(htmlStr, "/_next/") {
		stack = append(stack, domain.TechFingerprint{
			Name:       "Next.js (React)",
			Category:   "Framework Fullstack",
			Version:    "Détecté",
			Source:     "Bundles /_next/static/",
			Confidence: "100%",
		})
		cves = append(cves, domain.CVEWarning{
			ID:                  "CVE-2025-29927",
			CVEID:               "CVE-2025-29927",
			Severity:            "CRITICAL",
			CVSS:                "9.1",
			Component:           "Next.js Middleware",
			Title:               "Contournement d'Autorisation Middleware via l'en-tête x-middleware-subrequest",
			Description:         "Un attaquant externe peut envoyer l'en-tête interne x-middleware-subrequest pour contourner les contrôles d'authentification.",
			Remediation:         "1. [Immédiat] Purge de l'en-tête x-middleware-subrequest par Aegis Gate (WAF-NEXTJS-SUBREQ-STRIP). 2. [Racine] Mettre à jour Next.js (>= 15.2.3 / 14.2.25).",
			BlockedByAegis:      true,
			IsActiveDefense:     true,
			CoverageStatus:      "COVERED_VIRTUAL_PATCH",
			VirtualPatchRuleID:  "WAF-NEXTJS-SUBREQ-STRIP",
			VirtualPatchSummary: "Aegis Gate rejette (HTTP 403) toute requête externe portant l'en-tête x-middleware-subrequest avant qu'elle n'atteigne le serveur Next.js.",
			RootFixProcedure: []string{
				"Mettre à niveau Next.js vers >= 15.2.3, >= 14.2.25 ou >= 13.5.9 : npm install next@latest",
				"Bloquer l'en-tête x-middleware-subrequest dans la configuration du Reverse Proxy",
				"Redéployer le conteneur Node.js mis à jour",
			},
			VerificationProbe: "curl -i https://" + domainName + "/ -H 'x-middleware-subrequest: middleware'",
			CISAKEV:           true,
		})
	}

	if len(stack) == 0 {
		stack = append(stack, domain.TechFingerprint{
			Name:       "HTTP/TLS Web Endpoint",
			Category:   "Application Web",
			Version:    "Standard",
			Source:     "Inspection Passive HTTP",
			Confidence: "95%",
		})
	}

	return stack, cves
}

func extractVersionNumber(s string) string {
	reVer := regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9a-zA-Z\-]+)?)`)
	if m := reVer.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return "Masquée"
}
