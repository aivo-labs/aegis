package scanner

import (
	"net"
	"strings"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

// InspectDomainDNS effectue l'inspection DNS passive du domaine cible (Résolution A/AAAA, SPF, DMARC).
func InspectDomainDNS(domainName string) domain.DNSAnalysis {
	res := domain.DNSAnalysis{
		ResolvedIPs: []string{},
	}
	if ips, err := net.LookupHost(domainName); err == nil {
		for i, ip := range ips {
			if i >= 4 {
				break
			}
			res.ResolvedIPs = append(res.ResolvedIPs, ip)
		}
	}
	if txts, err := net.LookupTXT(domainName); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				res.HasSPF = true
				res.SPFRecord = t
			}
		}
	}
	if dmarcs, err := net.LookupTXT("_dmarc." + domainName); err == nil {
		for _, t := range dmarcs {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				res.HasDMARC = true
				res.DMARCRecord = t
			}
		}
	}
	return res
}
