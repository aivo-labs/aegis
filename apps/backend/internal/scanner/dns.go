package scanner

import (
	"net"
	"strings"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

// InspectDomainDNS effectue l'inspection DNS passive du domaine cible (Résolution A/AAAA, SPF, DMARC)
// avec support de la traversée hiérarchique RFC 7489 (DMARC) et des wildcards RFC 7208 (SPF).
func InspectDomainDNS(domainName string) domain.DNSAnalysis {
	domainName = strings.TrimSpace(strings.ToLower(domainName))
	res := domain.DNSAnalysis{
		ResolvedIPs: []string{},
	}

	// 1. Résolution des adresses IP (A / AAAA)
	if ips, err := net.LookupHost(domainName); err == nil {
		for i, ip := range ips {
			if i >= 4 {
				break
			}
			res.ResolvedIPs = append(res.ResolvedIPs, ip)
		}
	}

	// 2. Recherche SPF direct sur le domaine
	if txts, err := net.LookupTXT(domainName); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				res.HasSPF = true
				res.SPFRecord = t
				break
			}
		}
	}

	// 3. Recherche DMARC direct sur _dmarc.<domaine>
	if dmarcs, err := net.LookupTXT("_dmarc." + domainName); err == nil {
		for _, t := range dmarcs {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				res.HasDMARC = true
				res.DMARCRecord = t
				break
			}
		}
	}

	// 4. Traversée hiérarchique pour les sous-domaines (RFC 7489 & RFC 7208)
	// Si le sous-domaine n'a pas ses propres enregistrements explicites, on interroge les domaines parents
	parents := getParentDomains(domainName)
	for _, parent := range parents {
		// Fallback SPF : Vérifier si le parent publie un enregistrement SPF wildcard (*.parent)
		if !res.HasSPF {
			if wildTxts, err := net.LookupTXT("*." + parent); err == nil {
				for _, t := range wildTxts {
					if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
						res.HasSPF = true
						res.SPFRecord = t + " (via *." + parent + ")"
						break
					}
				}
			}
		}

		// Fallback DMARC (RFC 7489 Section 6.6.3) :
		// Si le sous-domaine n'a pas de DMARC propre, interroger le domaine organisationnel parent (_dmarc.parent)
		if !res.HasDMARC {
			if parentDmarcs, err := net.LookupTXT("_dmarc." + parent); err == nil {
				for _, t := range parentDmarcs {
					lower := strings.ToLower(t)
					if strings.HasPrefix(lower, "v=dmarc1") {
						// Vérifier que la politique ne désactive pas explicitement les sous-domaines (sp=none)
						if !strings.Contains(lower, "sp=none") {
							res.HasDMARC = true
							res.DMARCRecord = t + " (hérité de _dmarc." + parent + ")"
							break
						}
					}
				}
			}
		}

		// Si les deux sont satisfaits, pas besoin de remonter plus haut
		if res.HasSPF && res.HasDMARC {
			break
		}
	}

	return res
}

// getParentDomains extrait les domaines parents successifs dans l'ordre hiérarchique.
// Exemples :
// "sub.test.baud.dev" -> ["test.baud.dev", "baud.dev"]
// "test.baud.dev"     -> ["baud.dev"]
// "baud.dev"          -> nil
func getParentDomains(d string) []string {
	parts := strings.Split(strings.Trim(d, "."), ".")
	if len(parts) <= 2 {
		return nil
	}

	var parents []string
	for i := 1; i < len(parts)-1; i++ {
		parents = append(parents, strings.Join(parts[i:], "."))
	}
	return parents
}
