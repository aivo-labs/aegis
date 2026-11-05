package service

import "github.com/aivo-labs/aegis/backend/internal/domain"

type CveService struct{}

func NewCveService() *CveService {
	return &CveService{}
}

func (s *CveService) GetFeed() []domain.CVEWarning {
	return []domain.CVEWarning{
		{
			ID:             "CVE-2026-109618",
			CVEID:          "CVE-2026-109618",
			Severity:       "CRITICAL",
			CVSS:           "9.8",
			Component:      "PHP SAPI / FastCGI Buffer Engine (PHP2Shell)",
			Title:          "Dépassement de tampon volumétrique (Buffer/Heap Overflow) & Reverse Shell",
			Description:    "Exploitation par injection de payloads excédant les tampons mémoires des processus PHP-FPM, détournant le pointeur d'instruction pour forger un shell interactif.",
			Remediation:    "Activer le coupe-circuit volumétrique 32 Ko d'Aegis Gate (HTTP 413) et le Sinkhole DNS Egress pour neutraliser l'exfiltration.",
			BlockedByAegis: true,
		},
		{
			ID:             "CVE-2026-109619",
			CVEID:          "CVE-2026-109619",
			Severity:       "HIGH",
			CVSS:           "8.5",
			Component:      "TeamViewer & RMM Outbound Protocols",
			Title:          "Détournement de session RMM & Exfiltration furtive par tunneling",
			Description:    "Canaux de télémaintenance détournés pour exfiltrer des flux chiffrés hors du périmètre réseau autorisé.",
			Remediation:    "Bloquer les FQDNs non homologués et le trafic sortant non autorisé via Aegis Egress Gateway.",
			BlockedByAegis: true,
		},
		{
			ID:             "CVE-2024-4577",
			CVEID:          "CVE-2024-4577",
			Severity:       "CRITICAL",
			CVSS:           "9.8",
			Component:      "PHP-CGI Windows / Linux Argument Injection",
			Title:          "Exécution de code à distance (RCE) par injection de directives de flux",
			Description:    "Contournement des protections CGI permettant d'injecter allow_url_include=1 et auto_prepend_file=php://input.",
			Remediation:    "Filtrage à chaud via le moteur de Virtual Patching d'Aegis Gate.",
			BlockedByAegis: true,
		},
		{
			ID:             "CVE-2021-44228",
			CVEID:          "CVE-2021-44228",
			Severity:       "CRITICAL",
			CVSS:           "10.0",
			Component:      "Apache Log4j2 JNDI Lookup",
			Title:          "Exécution de code à distance Log4Shell via JNDI/LDAP",
			Description:    "Injection de motifs ${jndi:ldap:...} dans les en-têtes HTTP déclenchant un chargement de classe Java externe.",
			Remediation:    "Interception immédiate par signature heuristique Aegis Gate.",
			BlockedByAegis: true,
		},
		{
			ID:             "CVE-2025-29927",
			CVEID:          "CVE-2025-29927",
			Severity:       "CRITICAL",
			CVSS:           "9.1",
			Component:      "Next.js Middleware Routing",
			Title:          "Bypass d'autorisation par manipulation d'en-tête interne",
			Description:    "L'utilisation de x-middleware-subrequest permet de contourner les règles d'accès du middleware Next.js.",
			Remediation:    "Suppression des en-têtes internes non autorisés en bordure avec Aegis Gate PEP.",
			BlockedByAegis: true,
		},
	}
}
