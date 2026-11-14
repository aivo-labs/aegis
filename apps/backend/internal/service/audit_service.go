package service

import (
	"encoding/json"
	"fmt"

	"github.com/aivo-labs/aegis/backend/internal/database"
	"github.com/aivo-labs/aegis/backend/internal/domain"
	"github.com/aivo-labs/aegis/backend/internal/scanner"
)

type AuditService struct {
	db *database.PgClient
}

func NewAuditService(db *database.PgClient) *AuditService {
	return &AuditService{db: db}
}

func (s *AuditService) RunScan(rawDomain string) domain.PassiveAuditResult {
	return scanner.RunPassiveDomainScan(s.db, rawDomain)
}

func (s *AuditService) GetLatest(rawDomain string) (*domain.PassiveAuditResult, error) {
	domainName := scanner.NormalizeDomain(rawDomain)
	if domainName == "" {
		domainName = "localhost"
	}

	if s.db == nil {
		res := scanner.RunPassiveDomainScan(nil, domainName)
		return &res, nil
	}

	row, err := s.db.QueryRow(fmt.Sprintf(`
		SELECT id, domain, overall_eco_score, overall_eco_grade, security_score, security_grade,
		       pages_scanned, tech_stack, cve_warnings, headers_analysis, dns_analysis, pages_detail,
		       is_verified_owner, created_at
		FROM passive_domain_audits
		WHERE domain = %s
		ORDER BY created_at DESC
		LIMIT 1;`,
		database.QuoteLiteral(domainName),
	))
	if err != nil || row.String("domain") == "" {
		res := scanner.RunPassiveDomainScan(s.db, domainName)
		return &res, nil
	}

	res := domain.PassiveAuditResult{
		AuditID:         row.String("id"),
		Domain:          row.String("domain"),
		ScannedAt:       row.String("created_at"),
		OverallEcoScore: row.Float("overall_eco_score"),
		OverallEcoGrade: row.String("overall_eco_grade"),
		SecurityScore:   row.Int("security_score"),
		SecurityGrade:   row.String("security_grade"),
		PagesScanned:    row.Int("pages_scanned"),
		IsVerifiedOwner: row.Bool("is_verified_owner"),
	}

	_ = json.Unmarshal([]byte(row.String("tech_stack")), &res.TechStack)
	_ = json.Unmarshal([]byte(row.String("cve_warnings")), &res.CVEWarnings)
	_ = json.Unmarshal([]byte(row.String("headers_analysis")), &res.HeadersAnalysis)
	_ = json.Unmarshal([]byte(row.String("dns_analysis")), &res.DNS)
	_ = json.Unmarshal([]byte(row.String("pages_detail")), &res.PagesDetail)

	res.EcoIndexScore = res.OverallEcoScore
	res.EcoIndexGrade = res.OverallEcoGrade
	res.AvgGCO2ePerVisit = 1.35
	res.AvgGCO2Grams = 1.35
	res.AvgWaterCL = 2.05
	res.DetectedTech = res.TechStack
	res.Pages = res.PagesDetail
	res.OwnershipVerified = res.IsVerifiedOwner

	return &res, nil
}

func (s *AuditService) RequestVerification(domainName, email, company string) (map[string]any, error) {
	return scanner.CreateOwnershipVerification(s.db, domainName, email, company)
}

func (s *AuditService) VerifyOwnership(domainName, email string, contractAccepted bool, signerIP, userAgent string) (map[string]any, error) {
	return scanner.VerifyDomainAndRunDeepAudit(s.db, domainName, email, contractAccepted, signerIP, userAgent)
}
