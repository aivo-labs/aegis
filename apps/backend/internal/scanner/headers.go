package scanner

import (
	"net/http"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

// AnalyzeSecurityHeaders évalue la présence et la robustesse des en-têtes HTTP de sécurité (HSTS, CSP, X-Frame-Options, etc.).
func AnalyzeSecurityHeaders(headers http.Header, isHTTPS bool, dns domain.DNSAnalysis, cves *[]domain.CVEWarning) ([]domain.HeaderCheck, int) {
	score := 100
	checks := make([]domain.HeaderCheck, 0)

	check := func(name, descMissing string, penalty int, severity string) {
		val := headers.Get(name)
		if val != "" {
			checks = append(checks, domain.HeaderCheck{
				Header:  name,
				Present: true,
				Value:   val,
				Status:  "OK",
				Impact:  "Protection active conforme aux recommandations ANSSI",
			})
		} else {
			score -= penalty
			checks = append(checks, domain.HeaderCheck{
				Header:  name,
				Present: false,
				Value:   "Manquant",
				Status:  severity,
				Impact:  descMissing,
			})
		}
	}

	check("Strict-Transport-Security", "Risque d'attaque Man-in-the-Middle / SSL Stripping (HSTS absent)", 12, "WARNING")
	check("Content-Security-Policy", "Surface d'attaque Cross-Site Scripting (XSS) et injection de scripts tiers non restreinte", 15, "CRITICAL")
	check("X-Frame-Options", "Vulnérable au détournement de clic (Clickjacking via iframe)", 8, "WARNING")
	check("X-Content-Type-Options", "Risque de MIME-Sniffing sur les fichiers téléversés (nosniff manquant)", 6, "WARNING")
	check("Referrer-Policy", "Fuite potentielle d'URLs sensibles dans l'en-tête Referer", 4, "WARNING")

	if !isHTTPS {
		score -= 20
	}
	if !dns.HasSPF || !dns.HasDMARC {
		score -= 8
		*cves = append(*cves, domain.CVEWarning{
			ID:             "DNS-SPOOFING-RISK",
			Severity:       "HIGH",
			CVSS:           "7.4",
			Component:      "Configuration DNS (SPF / DMARC)",
			Title:          "Domaine vulnérable à l'usurpation d'identité email (Phishing / Spoofing)",
			Description:    "L'absence d'enregistrement DMARC ou SPF strict permet à un tiers d'envoyer des emails en usurpant votre nom de domaine.",
			Remediation:    "Ajouter un enregistrement TXT _dmarc et v=spf1 dans votre zone DNS.",
			BlockedByAegis: false,
		})
	}

	if headers.Get("Content-Security-Policy") == "" {
		*cves = append(*cves, domain.CVEWarning{
			ID:             "OWASP-A03-XSS-CSP",
			Severity:       "HIGH",
			CVSS:           "7.8",
			Component:      "En-têtes HTTP (CSP Manquante)",
			Title:          "Absence de politique Content-Security-Policy (CSP) contre l'injection XSS et l'exfiltration navigateur",
			Description:    "Sans en-tête CSP, tout script injecté peut exfiltrer les jetons de session (document.cookie) vers un domaine externe.",
			Remediation:    "Injecter les en-têtes de sécurité CSP et HSTS automatiquement via Aegis Gate.",
			BlockedByAegis: true,
		})
	}

	// 3. Pénalisation composite des vulnérabilités applicatives et logicielles (CVEs)
	// Déduction proportionnelle à la sévérité CVSS pour refléter le risque réel (RCE, buffer overflow, bypass...).
	// On ignore DNS-SPOOFING-RISK et OWASP-A03-XSS-CSP pour ne pas doubler les pénalités d'en-têtes/DNS déjà déduites ci-dessus.
	if cves != nil {
		for _, cve := range *cves {
			if cve.ID == "DNS-SPOOFING-RISK" || cve.ID == "OWASP-A03-XSS-CSP" {
				continue
			}
			switch cve.Severity {
			case "CRITICAL":
				score -= 15
			case "HIGH":
				score -= 10
			case "MEDIUM":
				score -= 5
			case "LOW":
				score -= 2
			default:
				score -= 5
			}
		}
	}

	if score < 0 {
		score = 0
	}
	return checks, score
}
