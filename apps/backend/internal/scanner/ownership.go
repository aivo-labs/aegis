package scanner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/database"
)

const LegalAuditContractText = "Je certifie sur l'honneur être le propriétaire légitime ou l'administrateur dûment habilité du domaine cible, et mandate expressément Aegis (AIVO) pour exécuter une analyse approfondie de sécurité et d'éco-conception sur ce périmètre (Conformité Article 323-1 du Code pénal)."

// NormalizeDomain nettoie l'entrée utilisateur (ex: "https://Mon-Site.fr/test" -> "mon-site.fr").
func NormalizeDomain(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx != -1 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func isLocalSandboxDomain(domainName string) bool {
	return domainName == "localhost" ||
		strings.HasPrefix(domainName, "127.0.0.1") ||
		strings.HasSuffix(domainName, ".local") ||
		strings.HasSuffix(domainName, ".test") ||
		strings.HasSuffix(domainName, ".internal")
}

// CreateOwnershipVerification génère un jeton DNS TXT unique pour prouver la propriété du domaine.
func CreateOwnershipVerification(db *database.PgClient, rawDomain, email, company string) (map[string]any, error) {
	domainName := NormalizeDomain(rawDomain)
	if domainName == "" || email == "" {
		return nil, fmt.Errorf("domaine et adresse email professionnelle requis")
	}

	randBytes := make([]byte, 12)
	_, _ = rand.Read(randBytes)
	token := "aegis-site-verification=aegis_verify_" + hex.EncodeToString(randBytes)

	if db != nil {
		existing, err := db.QueryRow(fmt.Sprintf(
			"SELECT verification_token, is_verified FROM domain_ownership_contracts WHERE domain = %s LIMIT 1",
			database.QuoteLiteral(domainName),
		))
		if err == nil && existing.String("verification_token") != "" {
			token = existing.String("verification_token")
		} else {
			upsertSQL := fmt.Sprintf(`
				INSERT INTO domain_ownership_contracts (domain, contact_email, company_name, verification_token)
				VALUES (%s, %s, %s, %s)
				ON CONFLICT (domain) DO UPDATE SET
					contact_email = EXCLUDED.contact_email,
					company_name = EXCLUDED.company_name,
					updated_at = CURRENT_TIMESTAMP;`,
				database.QuoteLiteral(domainName),
				database.QuoteLiteral(email),
				database.QuoteLiteral(company),
				database.QuoteLiteral(token),
			)
			_ = db.Exec(upsertSQL)
		}
	}

	return map[string]any{
		"status":             "pending_verification",
		"domain":             domainName,
		"contact_email":      email,
		"dns_record_type":    "TXT",
		"dns_record_host":    "@ (ou " + domainName + " / _aegis-challenge." + domainName + ")",
		"dns_record_value":   token,
		"verification_token": token,
		"well_known_path":    "https://" + domainName + "/.well-known/aegis-verify.txt",
		"well_known_content": token,
		"legal_contract":     LegalAuditContractText,
		"offer_model":        "Open-Core Éthique : 1er Audit Approfondi & Export Complet 100% Offert après validation DNS ou HTTP /.well-known",
	}, nil
}

// lookupTXTWithPublicFallback interroge d'abord le résolveur système puis les résolveurs publics (1.1.1.1, 8.8.8.8)
// afin d'éviter les délais de cache DNS négatif lorsque l'utilisateur vient tout juste d'ajouter son enregistrement TXT.
func lookupTXTWithPublicFallback(host, expectedToken string) bool {
	hostsToCheck := []string{host, "_aegis-challenge." + host}

	// 1. Résolveur système standard
	for _, h := range hostsToCheck {
		if txts, err := net.LookupTXT(h); err == nil {
			for _, t := range txts {
				if strings.Contains(strings.TrimSpace(t), expectedToken) {
					return true
				}
			}
		}
	}

	// 2. Fallback sur résolveurs DNS publics (Cloudflare 1.1.1.1 & Google 8.8.8.8)
	publicResolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	for _, resolverAddr := range publicResolvers {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2000 * time.Millisecond}
				return d.DialContext(ctx, "udp", resolverAddr)
			},
		}
		for _, h := range hostsToCheck {
			ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
			txts, err := r.LookupTXT(ctx, h)
			cancel()
			if err == nil {
				for _, t := range txts {
					if strings.Contains(strings.TrimSpace(t), expectedToken) {
						return true
					}
				}
			}
		}
	}

	return false
}

// checkWellKnownFile vérifie la présence éventuelle du jeton dans https://<domain>/.well-known/aegis-verify.txt
func checkWellKnownFile(domainName, expectedToken string) bool {
	client := &http.Client{Timeout: 2500 * time.Millisecond}
	url := "https://" + domainName + "/.well-known/aegis-verify.txt"
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(bodyBytes)), expectedToken)
}

// VerifyDomainAndRunDeepAudit vérifie strictement l'enregistrement DNS TXT (ou /.well-known/aegis-verify.txt)
// et enregistre le mandat légal signé avant de lancer les sondes Niveau 2.
func VerifyDomainAndRunDeepAudit(db *database.PgClient, rawDomain, email string, contractAccepted bool, signerIP, userAgent string) (map[string]any, error) {
	domainName := NormalizeDomain(rawDomain)
	if domainName == "" {
		return nil, fmt.Errorf("nom de domaine requis pour la vérification")
	}
	if !contractAccepted {
		return nil, fmt.Errorf("vous devez accepter et signer le mandat d'autorisation d'audit pour débloquer l'analyse approfondie")
	}

	expectedToken := ""
	if db != nil {
		row, err := db.QueryRow(fmt.Sprintf(
			"SELECT verification_token FROM domain_ownership_contracts WHERE domain = %s LIMIT 1",
			database.QuoteLiteral(domainName),
		))
		if err == nil {
			expectedToken = row.String("verification_token")
		}
	}
	if expectedToken == "" {
		info, _ := CreateOwnershipVerification(db, domainName, email, "")
		expectedToken, _ = info["dns_record_value"].(string)
	}

	// Vérification stricte de propriété (DNS TXT ou HTTP /.well-known/aegis-verify.txt)
	verifiedMethod := ""
	if isLocalSandboxDomain(domainName) {
		verifiedMethod = "LOCAL_SANDBOX_AUTO_VERIFIED"
	} else if lookupTXTWithPublicFallback(domainName, expectedToken) {
		verifiedMethod = "DNS_TXT_RECORD_VERIFIED"
	} else if checkWellKnownFile(domainName, expectedToken) {
		verifiedMethod = "HTTP_WELL_KNOWN_VERIFIED"
	} else if os.Getenv("AEGIS_ALLOW_SANDBOX_MANDATE") == "true" {
		verifiedMethod = "SIGNED_MANDATE_SANDBOX_MODE"
	} else {
		return nil, fmt.Errorf(
			"vérification de propriété échouée pour %s : l'enregistrement DNS TXT '%s' (ou le fichier https://%s/.well-known/aegis-verify.txt) n'a pas encore été détecté. Ajoutez cet enregistrement dans votre zone DNS puis réessayez après propagation",
			domainName,
			expectedToken,
			domainName,
		)
	}

	signedPayload := fmt.Sprintf("%s|%s|%s|%s|%s", domainName, email, signerIP, time.Now().UTC().Format(time.RFC3339), LegalAuditContractText)
	hash := sha256.Sum256([]byte(signedPayload))
	contractHash := hex.EncodeToString(hash[:])

	deepFindings := runLevel2DeepChecks(domainName)
	deepJSON, _ := json.Marshal(deepFindings)

	if db != nil {
		updateSQL := fmt.Sprintf(`
			UPDATE domain_ownership_contracts
			SET is_verified = TRUE,
			    verification_method = %s,
			    verified_at = CURRENT_TIMESTAMP,
			    contract_accepted = TRUE,
			    contract_text_hash = %s,
			    signer_ip = %s,
			    signer_user_agent = %s,
			    deep_audit_report = %s::jsonb,
			    updated_at = CURRENT_TIMESTAMP
			WHERE domain = %s;`,
			database.QuoteLiteral(verifiedMethod),
			database.QuoteLiteral(contractHash),
			database.QuoteLiteral(signerIP),
			database.QuoteLiteral(userAgent),
			database.QuoteLiteral(string(deepJSON)),
			database.QuoteLiteral(domainName),
		)
		_ = db.Exec(updateSQL)

		_ = db.Exec(fmt.Sprintf(
			"UPDATE passive_domain_audits SET is_verified_owner = TRUE WHERE domain = %s;",
			database.QuoteLiteral(domainName),
		))
	}

	// Relancer un scan actualisé
	auditRes := RunPassiveDomainScan(db, domainName)
	auditRes.IsVerifiedOwner = true
	auditRes.OwnershipVerified = true
	auditRes.DeepProbes = deepFindings
	auditRes.ContractHash = contractHash
	auditRes.VerifiedAt = time.Now().UTC().Format(time.RFC3339)

	return map[string]any{
		"status":              "verified_and_unlocked",
		"verified":            true,
		"domain":              domainName,
		"verification_method": verifiedMethod,
		"contract_sha256":     contractHash,
		"signed_at":           auditRes.VerifiedAt,
		"signer_ip":           signerIP,
		"audit":               auditRes,
		"deep_findings":       deepFindings,
		"message":             fmt.Sprintf("✅ Propriété du domaine %s vérifiée (%s) & Mandat d'Audit enregistré (SHA-256 : %s...). Niveau 2 débloqué !", domainName, verifiedMethod, contractHash[:12]),
	}, nil
}

func runLevel2DeepChecks(domainName string) []map[string]any {
	baseURL := "https://" + domainName
	if domainName == "localhost" || strings.HasPrefix(domainName, "127.0.0.1") {
		baseURL = "http://gate-proxy:8000"
	}

	client := &http.Client{Timeout: 2500 * time.Millisecond}
	probes := []struct {
		Path string
		Name string
		Risk string
	}{
		{"/.env", "Exposition du fichier de secrets /.env", "CRITICAL"},
		{"/.git/config", "Exposition du dépôt source /.git/config", "CRITICAL"},
		{"/wp-login.php", "Surface d'authentification WordPress /wp-login.php", "MEDIUM"},
		{"/xmlrpc.php", "Interface d'amplification XML-RPC /xmlrpc.php", "HIGH"},
		{"/phpinfo.php", "Fuite de configuration système /phpinfo.php", "CRITICAL"},
	}

	var results []map[string]any
	for _, p := range probes {
		status := 0
		resp, err := client.Get(baseURL + p.Path)
		if err == nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
		}
		state := "PROTÉGÉ (Non exposé / Filtré)"
		if status == 200 {
			state = "EXPOSÉ (HTTP 200 — Risque élevé)"
		} else if status == 403 {
			state = "BLOQUÉ À L'EDGE (HTTP 403)"
		}
		results = append(results, map[string]any{
			"path":        p.Path,
			"check_name":  p.Name,
			"http_status": status,
			"severity":    p.Risk,
			"verdict":     state,
		})
	}
	return results
}
