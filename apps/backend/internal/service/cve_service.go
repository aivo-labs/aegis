package service

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

// CoverageVerificationReport synthétise l'état de couverture et de vérification du catalogue CVE.
type CoverageVerificationReport struct {
	CheckedAt                 string           `json:"checked_at"`
	TotalCatalogCVEs          int              `json:"total_catalog_cves"`
	CoveredVirtualPatchCount  int              `json:"covered_virtual_patch_count"`
	MitigatedEgressOnlyCount  int              `json:"mitigated_egress_only_count"`
	HostPatchRequiredCount    int              `json:"host_patch_required_count"`
	PendingVerificationCount  int              `json:"pending_verification_count"`
	AllProceduresDocumented   bool             `json:"all_procedures_documented"`
	ActiveGateRulesRegistered []string         `json:"active_gate_rules_registered"`
	RuleVerificationMatrix    []map[string]any `json:"rule_verification_matrix"`
}

type CveService struct {
	mu             sync.RWMutex
	dynamicCves    []domain.CVEWarning
	certFrURL      string
	httpClient     *http.Client
	lastSyncReport *CertFrSyncReport
}

func NewCveService() *CveService {
	return &CveService{
		certFrURL:  DefaultCertFrFeedURL,
		httpClient: &http.Client{Timeout: 8 * time.Second},
	}
}

// GetLastSyncReport renvoie le rapport de la dernière synchronisation CERT-FR effectuée.
func (s *CveService) GetLastSyncReport() *CertFrSyncReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSyncReport
}

// ActiveAegisRules répertorie les règles chargées en mémoire dans Aegis Gate PEP et Aegis Egress Sinkhole (version par défaut).
var ActiveAegisRules = map[string]string{
	"WAF-413-VOLUMETRIC":      "Coupe-circuit volumétrique 32 Ko (HTTP 413 Payload Too Large) + protection Heap/Buffer PHP-FPM",
	"WAF-PHP-CGI-ARGS":        "Filtrage pré-compilé des directives CGI/FastCGI (allow_url_include, auto_prepend_file, php://input, %AD)",
	"WAF-PHP-FILTER-CHAIN":    "Blocage des chaînes iconv/convert.iconv.* (CNEXT CVE-2024-2961) dans les paramètres et corps HTTP",
	"WAF-NEXTJS-SUBREQ-STRIP": "Suppression et blocage de l'en-tête interne x-middleware-subrequest en bordure Ingress",
	"WAF-LOG4J-JNDI":          "Interception heuristique des motifs ${jndi:ldap/rmi/dns:...} dans les URI, en-têtes et payloads",
	"WAF-CMS-SHIELD":          "Verrouillage de /xmlrpc.php, /wp-json/wp/v2/users, /.env, /.git/config et brute-force /wp-login.php",
	"WAF-HEADER-SANITIZER":    "Masquage des bannières Server / X-Powered-By et protection HTTP/2 Rapid Reset",
	"WAF-SQLI-AST-FILTER":     "Détection d'injections SQL et variables d'environnement malveillantes",
	"K8S-AEGIS-GATE-INGRESS":  "Isolation de l'Admission Webhook Kubernetes et filtrage des annotations Ingress-NGINX",
	"EGRESS-C2-SINKHOLE":      "Sinkhole DNS :5053 (0.0.0.0) + Calculateur d'Entropie de Shannon (H > 4.2 bits) + coupure TCP sortante",
}

// GetActiveRules retourne le dictionnaire des règles traduites dans la langue demandée ('fr' ou 'en').
func (s *CveService) GetActiveRules(lang ...string) map[string]string {
	l := "fr"
	if len(lang) > 0 && strings.TrimSpace(lang[0]) != "" {
		l = strings.ToLower(strings.TrimSpace(lang[0]))
	}

	out := make(map[string]string, len(LocalizedRules))
	for k, v := range LocalizedRules {
		out[k] = v.Get(l)
	}
	return out
}

// GetFeed génère le catalogue complet des alertes de vulnérabilités dans la langue demandée ('fr' ou 'en').
// Rétrocompatible : s'il est appelé sans argument, il utilise la langue par défaut "fr".
func (s *CveService) GetFeed(lang ...string) []domain.CVEWarning {
	l := "fr"
	if len(lang) > 0 && strings.TrimSpace(lang[0]) != "" {
		l = strings.ToLower(strings.TrimSpace(lang[0]))
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	feed := make([]domain.CVEWarning, 0, len(CatalogDefinitions)+len(s.dynamicCves))
	for _, def := range CatalogDefinitions {
		feed = append(feed, def.ToWarning(l))
	}
	for _, dyn := range s.dynamicCves {
		feed = append(feed, dyn)
	}
	return feed
}

// VerifyCoverage exécute la procédure de vérification interne sur l'ensemble du catalogue CVE
// afin de certifier quelles failles sont couvertes par Virtual Patching, lesquelles sont mitigées en Egress
// et si chaque faille dispose bien de sa procédure de remédiation racine documentée.
func (s *CveService) VerifyCoverage(lang ...string) CoverageVerificationReport {
	l := "fr"
	if len(lang) > 0 && strings.TrimSpace(lang[0]) != "" {
		l = strings.ToLower(strings.TrimSpace(lang[0]))
	}

	feed := s.GetFeed(l)
	coveredVP := 0
	mitigatedEgress := 0
	hostPatch := 0
	pendingVerification := 0
	allDocumented := true
	var matrix []map[string]any

	for _, cve := range feed {
		switch cve.CoverageStatus {
		case "COVERED_VIRTUAL_PATCH":
			coveredVP++
		case "MITIGATED_EGRESS_ONLY":
			mitigatedEgress++
		case "PENDING_VERIFICATION":
			pendingVerification++
		default:
			hostPatch++
		}

		hasRootSteps := len(cve.RootFixProcedure) > 0
		hasProbe := cve.VerificationProbe != ""
		if (!hasRootSteps || !hasProbe) && cve.CoverageStatus != "PENDING_VERIFICATION" {
			allDocumented = false
		}

		matrix = append(matrix, map[string]any{
			"cve_id":             cve.ID,
			"component":          cve.Component,
			"coverage_status":    cve.CoverageStatus,
			"virtual_patch_rule": cve.VirtualPatchRuleID,
			"root_steps_count":   len(cve.RootFixProcedure),
			"verification_probe": cve.VerificationProbe,
			"procedure_complete": hasRootSteps && hasProbe && cve.CoverageStatus != "PENDING_VERIFICATION",
		})
	}

	rulesList := make([]string, 0, len(LocalizedRules))
	for k := range LocalizedRules {
		rulesList = append(rulesList, k)
	}

	return CoverageVerificationReport{
		CheckedAt:                 time.Now().UTC().Format(time.RFC3339),
		TotalCatalogCVEs:          len(feed),
		CoveredVirtualPatchCount:  coveredVP,
		MitigatedEgressOnlyCount:  mitigatedEgress,
		HostPatchRequiredCount:    hostPatch,
		PendingVerificationCount:  pendingVerification,
		AllProceduresDocumented:   allDocumented,
		ActiveGateRulesRegistered: rulesList,
		RuleVerificationMatrix:    matrix,
	}
}
