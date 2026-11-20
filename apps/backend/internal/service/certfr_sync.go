package service

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

const DefaultCertFrFeedURL = "https://www.cert.cyber.gouv.fr/alerte/feed/"

var (
	cveRegex   = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	alertRegex = regexp.MustCompile(`CERTFR-\d{4}-ALE-\d{3}`)
)

// CertFrRss modélise la racine du flux RSS 2.0 XML émis par l'ANSSI / CERT-FR.
type CertFrRss struct {
	XMLName xml.Name      `xml:"rss"`
	Channel CertFrChannel `xml:"channel"`
}

type CertFrChannel struct {
	Title     string       `xml:"title"`
	LastBuild string       `xml:"lastBuildDate"`
	Items     []CertFrItem `xml:"item"`
}

type CertFrItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	Guid        string `xml:"guid"`
}

// CertFrSyncReport résume l'exécution d'une synchronisation CERT-FR souveraine.
type CertFrSyncReport struct {
	SyncedAt       string `json:"synced_at"`
	FeedSource     string `json:"feed_source"`
	AlertsParsed   int    `json:"alerts_parsed"`
	NewIngested    int    `json:"new_ingested"`
	AlreadyCurated int    `json:"already_curated"`
	DurationMs     int64  `json:"duration_ms"`
}

// SyncCertFrFromReader parse un flux XML CERT-FR depuis n'importe quel io.Reader (testable sans réseau).
func (s *CveService) SyncCertFrFromReader(r io.Reader, lang string) (*CertFrSyncReport, error) {
	start := time.Now()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("lecture flux XML CERT-FR échouée: %w", err)
	}

	var rss CertFrRss
	if err := xml.Unmarshal(data, &rss); err != nil {
		return nil, fmt.Errorf("désérialisation XML CERT-FR échouée: %w", err)
	}

	curatedSet := make(map[string]bool, len(CatalogDefinitions))
	for _, def := range CatalogDefinitions {
		curatedSet[def.ID] = true
		curatedSet[def.CVEID] = true
	}

	s.mu.Lock()

	existingDynamic := make(map[string]bool, len(s.dynamicCves))
	for _, d := range s.dynamicCves {
		existingDynamic[d.ID] = true
		existingDynamic[d.CVEID] = true
	}

	newIngested := 0
	alreadyCurated := 0
	var newIngestedList []domain.CVEWarning

	for _, item := range rss.Channel.Items {
		cves := cveRegex.FindAllString(item.Title+" "+item.Description, -1)
		alertRef := alertRegex.FindString(item.Title + " " + item.Link)
		if alertRef == "" {
			alertRef = "CERT-FR"
		}

		if len(cves) == 0 {
			// Si aucun identifiant CVE explicite n'apparaît, on référence sous l'identifiant d'alerte CERT-FR
			cves = []string{alertRef}
		}

		cleanDesc := strings.TrimSpace(item.Description)
		cleanDesc = strings.ReplaceAll(cleanDesc, `\[`, "")
		cleanDesc = strings.ReplaceAll(cleanDesc, `\]`, "")
		cleanDesc = strings.ReplaceAll(cleanDesc, `**`, "")
		cleanDesc = strings.ReplaceAll(cleanDesc, `*`, "")

		pubDate := time.Now().Format("2006-01-02")
		if item.PubDate != "" {
			if parsedT, err := time.Parse(time.RFC1123, item.PubDate); err == nil {
				pubDate = parsedT.Format("2006-01-02")
			} else if parsedT, err := time.Parse(time.RFC1123Z, item.PubDate); err == nil {
				pubDate = parsedT.Format("2006-01-02")
			}
		}

		severity := "HIGH"
		if strings.Contains(strings.ToLower(item.Title+" "+cleanDesc), "critique") ||
			strings.Contains(strings.ToLower(cleanDesc), "code arbitraire") ||
			strings.Contains(strings.ToLower(cleanDesc), "rce") {
			severity = "CRITICAL"
		}

		for _, cveID := range cves {
			cveID = strings.TrimSpace(cveID)
			if curatedSet[cveID] {
				alreadyCurated++
				continue
			}
			if existingDynamic[cveID] {
				continue
			}

			newWarn := domain.CVEWarning{
				ID:               cveID,
				CVEID:            cveID,
				Name:             item.Title,
				Severity:         severity,
				CVSS:             "9.0",
				Component:        fmt.Sprintf("CERT-FR ANSSI (%s)", alertRef),
				AffectedVersions: "Consulter l'alerte officielle " + alertRef,
				Title:            item.Title,
				Description:      cleanDesc,
				Vector:           "RÉSEAU / Alerte CERT-FR (" + item.Link + ")",
				Remediation: func() string {
					if strings.ToLower(lang) == "en" {
						return "Official CERT-FR (ANSSI) advisory. Remediation procedure under qualification in Aegis Lab: " + item.Link
					}
					return "Alerte officielle CERT-FR (ANSSI). Procédure de remédiation en cours de qualification dans Aegis Lab : " + item.Link
				}(),
				BlockedByAegis:      false,
				IsActiveDefense:     false,
				CoverageStatus:      "PENDING_VERIFICATION",
				VirtualPatchRuleID:  "QUALIFICATION-EN-COURS",
				VirtualPatchSummary: func() string {
					if strings.ToLower(lang) == "en" {
						return "Procedure under verification (Aegis Lab). Impact analysis and Virtual Patch currently being formulated."
					}
					return "Procédure en cours de vérification (Aegis Lab). Analyse d'impact et Virtual Patch en cours de formulation."
				}(),
				RootFixProcedure: func() []string {
					if strings.ToLower(lang) == "en" {
						return []string{
							"Review official CERT-FR advisory: " + item.Link,
							"Apply vendor patches or workarounds as recommended by CERT-FR.",
							"Detailed Aegis Virtual Patch and verification procedure currently under qualification in Aegis Lab.",
						}
					}
					return []string{
						"Consulter l'avis officiel du CERT-FR : " + item.Link,
						"Appliquer les préconisations du CERT-FR ou les correctifs éditeurs dès disponibilité.",
						"Procédure détaillée et règle Virtual Patch en cours de vérification par les ingénieurs Aegis.",
					}
				}(),
				VerificationProbe: func() string {
					if strings.ToLower(lang) == "en" {
						return "# Verification probe currently being drafted in Aegis Lab for " + cveID
					}
					return "# Sonde de vérification en cours d'élaboration dans Aegis Lab pour " + cveID
				}(),
				CISAKEV:     false,
				PublishedAt: pubDate,
			}

			s.dynamicCves = append(s.dynamicCves, newWarn)
			existingDynamic[cveID] = true
			newIngested++
			newIngestedList = append(newIngestedList, newWarn)
		}
	}

	report := &CertFrSyncReport{
		SyncedAt:       time.Now().UTC().Format(time.RFC3339),
		FeedSource:     DefaultCertFrFeedURL,
		AlertsParsed:   len(rss.Channel.Items),
		NewIngested:    newIngested,
		AlreadyCurated: alreadyCurated,
		DurationMs:     time.Since(start).Milliseconds(),
	}

	s.lastSyncReport = report
	s.mu.Unlock()

	// Persistance asynchrone / post-verrou en base de données
	for _, warn := range newIngestedList {
		if err := s.PersistDynamicCve(warn); err != nil {
			log.Printf("⚠️ [CVE Service] Erreur de persistance SQL pour %s: %v", warn.ID, err)
		}
	}

	return report, nil
}

// SyncCertFr télécharge en direct le flux RSS CERT-FR depuis cert.cyber.gouv.fr avec gestion de timeout et de fallback.
func (s *CveService) SyncCertFr(ctx context.Context, lang string) (*CertFrSyncReport, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.certFrURL, nil)
	if err != nil {
		return nil, fmt.Errorf("création requête CERT-FR échouée: %w", err)
	}
	req.Header.Set("User-Agent", "Aegis-SOC-ThreatIntel/1.1 (ANSSI-CERT-FR Sovereign Ingestion)")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("⚠️ [Aegis CERT-FR Sync] Requête réseau échouée (%v). Utilisation du catalogue local.", err)
		return &CertFrSyncReport{
			SyncedAt:       time.Now().UTC().Format(time.RFC3339),
			FeedSource:     s.certFrURL,
			AlertsParsed:   0,
			NewIngested:    0,
			AlreadyCurated: len(CatalogDefinitions),
			DurationMs:     0,
		}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("réponse HTTP CERT-FR invalide: %s", resp.Status)
	}

	return s.SyncCertFrFromReader(resp.Body, lang)
}
