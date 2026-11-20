package service

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/database"
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
	db             *database.PgClient
}

func NewCveService(db ...*database.PgClient) *CveService {
	var pg *database.PgClient
	if len(db) > 0 {
		pg = db[0]
	}
	s := &CveService{
		certFrURL:  DefaultCertFrFeedURL,
		httpClient: &http.Client{Timeout: 8 * time.Second},
		db:         pg,
	}
	if s.db != nil {
		s.loadPersistedCves()
	}
	return s
}

// loadPersistedCves restaure les CVE dynamiques enregistrées en base (ex: issues de synchronisations CERT-FR antérieures).
func (s *CveService) loadPersistedCves() {
	if s.db == nil {
		return
	}
	rows, err := s.db.Query(`
		SELECT id, cve_id, name, severity, cvss, component, affected_versions, 
		       title, description, vector, remediation, blocked_by_aegis, 
		       is_active_defense, coverage_status, virtual_patch_rule_id, 
		       virtual_patch_summary, root_fix_procedure, verification_probe, 
		       cisakev, published_at
		FROM dynamic_cve_catalog
		ORDER BY created_at DESC;
	`)
	if err != nil {
		log.Printf("⚠️ [CVE Service] Erreur lors du chargement des CVE persistées: %v", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	loaded := make([]domain.CVEWarning, 0, len(rows))
	for _, row := range rows {
		var rootSteps []string
		if procJSON := row.String("root_fix_procedure"); procJSON != "" {
			_ = json.Unmarshal([]byte(procJSON), &rootSteps)
		}

		loaded = append(loaded, domain.CVEWarning{
			ID:                  row.String("id"),
			CVEID:               row.String("cve_id"),
			Name:                row.String("name"),
			Severity:            row.String("severity"),
			CVSS:                row.String("cvss"),
			Component:           row.String("component"),
			AffectedVersions:    row.String("affected_versions"),
			Title:               row.String("title"),
			Description:         row.String("description"),
			Vector:              row.String("vector"),
			Remediation:         row.String("remediation"),
			BlockedByAegis:      row.Bool("blocked_by_aegis"),
			IsActiveDefense:     row.Bool("is_active_defense"),
			CoverageStatus:      row.String("coverage_status"),
			VirtualPatchRuleID:  row.String("virtual_patch_rule_id"),
			VirtualPatchSummary: row.String("virtual_patch_summary"),
			RootFixProcedure:    rootSteps,
			VerificationProbe:   row.String("verification_probe"),
			CISAKEV:             row.Bool("cisakev"),
			PublishedAt:         row.String("published_at"),
		})
	}

	s.dynamicCves = loaded
	log.Printf("🛡️ [CVE Service] %d alertes CVE dynamiques restaurées depuis PostgreSQL.", len(loaded))
}

// PersistDynamicCve sauvegarde une alerte CVE dynamique dans la base de données PostgreSQL.
func (s *CveService) PersistDynamicCve(warn domain.CVEWarning) error {
	if s.db == nil {
		return nil
	}

	procBytes, _ := json.Marshal(warn.RootFixProcedure)
	procJSON := string(procBytes)
	if procJSON == "" {
		procJSON = "[]"
	}

	query := fmt.Sprintf(`
		INSERT INTO dynamic_cve_catalog (
			id, cve_id, name, severity, cvss, component, affected_versions,
			title, description, vector, remediation, blocked_by_aegis,
			is_active_defense, coverage_status, virtual_patch_rule_id,
			virtual_patch_summary, root_fix_procedure, verification_probe,
			cisakev, published_at
		) VALUES (
			%s, %s, %s, %s, %s, %s, %s,
			%s, %s, %s, %s, %t,
			%t, %s, %s,
			%s, %s::jsonb, %s,
			%t, %s
		)
		ON CONFLICT (id) DO UPDATE SET
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			remediation = EXCLUDED.remediation,
			coverage_status = EXCLUDED.coverage_status,
			virtual_patch_summary = EXCLUDED.virtual_patch_summary,
			published_at = EXCLUDED.published_at;
	`,
		database.QuoteLiteral(warn.ID),
		database.QuoteLiteral(warn.CVEID),
		database.QuoteLiteral(warn.Name),
		database.QuoteLiteral(warn.Severity),
		database.QuoteLiteral(warn.CVSS),
		database.QuoteLiteral(warn.Component),
		database.QuoteLiteral(warn.AffectedVersions),
		database.QuoteLiteral(warn.Title),
		database.QuoteLiteral(warn.Description),
		database.QuoteLiteral(warn.Vector),
		database.QuoteLiteral(warn.Remediation),
		warn.BlockedByAegis,
		warn.IsActiveDefense,
		database.QuoteLiteral(warn.CoverageStatus),
		database.QuoteLiteral(warn.VirtualPatchRuleID),
		database.QuoteLiteral(warn.VirtualPatchSummary),
		database.QuoteLiteral(procJSON),
		database.QuoteLiteral(warn.VerificationProbe),
		warn.CISAKEV,
		database.QuoteLiteral(warn.PublishedAt),
	)

	return s.db.Exec(query)
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
