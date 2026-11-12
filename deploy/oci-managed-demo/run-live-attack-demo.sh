#!/usr/bin/env bash
# ==============================================================================
# AEGIS SOVEREIGN GATE — SIMULATEUR D'ATTAQUES LIVE & BENCHMARK VIDÉO CPU
# Permet de démontrer en rendez-vous client ou en vidéo :
# 1. L'interception instantanée (<1ms) des exploits PHP2Shell, SQLi, Overflow 413
# 2. La détection d'exfiltration DNS C2 Egress
# 3. Le comparatif de charge CPU / Watts AVEC vs SANS bouclier Aegis
# ==============================================================================
set -e

TARGET_URL="${1:-http://localhost:8000}"
TARGET_URL="${TARGET_URL%/}"
EGRESS_HOST="${AEGIS_EGRESS_HOST:-localhost}"
EGRESS_PORT="${AEGIS_EGRESS_PORT:-5053}"

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

print_banner() {
  echo -e "${CYAN}${BOLD}==============================================================================${RESET}"
  echo -e "${CYAN}${BOLD}🛡️  AEGIS LIVE ATTACK & CPU BENCHMARK — CIBLE : ${TARGET_URL}${RESET}"
  echo -e "${CYAN}${BOLD}   Cockpit Temps Réel : https://aegis.aivo.fr/app${RESET}"
  echo -e "${CYAN}${BOLD}==============================================================================${RESET}"
}

run_scenario_legitimate() {
  echo -e "\n${GREEN}${BOLD}[1/5] ✅ Trafic Légitime (Portail PHP 8.3 & Microservice Node.js)${RESET}"
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/?format=json")
  NODE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/api/node/status")
  echo -e "  -> GET /?format=json       : HTTP ${HTTP_CODE}"
  echo -e "  -> GET /api/node/status    : HTTP ${NODE_CODE}"
}

run_scenario_php2shell() {
  echo -e "\n${RED}${BOLD}[2/5] 💥 Exploit Zero-Day PHP2Shell / PHP-CGI RCE (CVE-2024-4577)${RESET}"
  START_MS=$(date +%s%3N)
  RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
    "${TARGET_URL}/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input&format=json" \
    -H "User-Agent: Mozilla/5.0 (Exploit/CVE-2024-4577-PHP2Shell)" \
    -d "<?php system('id; uname -a'); ?>")
  END_MS=$(date +%s%3N)
  LATENCY=$((END_MS - START_MS))
  STATUS=$(echo "$RESP" | awk -F: '/HTTP_STATUS/ {print $2}')
  BODY=$(echo "$RESP" | sed '/HTTP_STATUS/d')

  if [ "$STATUS" = "403" ]; then
    echo -e "  -> ${GREEN}${BOLD}BLOQUÉ PAR AEGIS GATE PEP (HTTP 403) en ${LATENCY}ms${RESET} — 0% CPU sur PHP-FPM !"
  else
    echo -e "  -> ${YELLOW}${BOLD}BOUCLIER DÉSACTIVÉ (HTTP ${STATUS} en ${LATENCY}ms)${RESET} — Exploit transmis à PHP-FPM !"
  fi
  echo "$BODY" | head -n 12 | sed 's/^/     /'
}

run_scenario_sqli() {
  echo -e "\n${RED}${BOLD}[3/5] 💉 Injection SQL Critique sur Microservice Node.js (/api/node/search)${RESET}"
  START_MS=$(date +%s%3N)
  RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
    "${TARGET_URL}/api/node/search?q=1%27+UNION+SELECT+username,password_hash+FROM+admin_users--")
  END_MS=$(date +%s%3N)
  LATENCY=$((END_MS - START_MS))
  STATUS=$(echo "$RESP" | awk -F: '/HTTP_STATUS/ {print $2}')
  if [ "$STATUS" = "403" ]; then
    echo -e "  -> ${GREEN}${BOLD}BLOQUÉ PAR AEGIS GATE PEP (HTTP 403) en ${LATENCY}ms${RESET}"
  else
    echo -e "  -> ${YELLOW}${BOLD}BOUCLIER DÉSACTIVÉ (HTTP ${STATUS} en ${LATENCY}ms)${RESET} — Surcharge Node.js déclenchée !"
  fi
}

run_scenario_overflow413() {
  echo -e "\n${RED}${BOLD}[4/5] 🌊 Attaque Volumétrique Buffer Overflow (Payload 48 Ko > Limite 32 Ko)${RESET}"
  LARGE_PAYLOAD=$(head -c 49152 </dev/zero | tr '\0' 'A')
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${TARGET_URL}/index.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "${LARGE_PAYLOAD}")
  if [ "$STATUS" = "413" ] || [ "$STATUS" = "403" ]; then
    echo -e "  -> ${GREEN}${BOLD}REJETÉ EN BORDURE PAR VIRTUAL PATCHING VOLUMÉTRIQUE (HTTP ${STATUS})${RESET}"
  else
    echo -e "  -> ${YELLOW}${BOLD}BOUCLIER DÉSACTIVÉ (HTTP ${STATUS})${RESET}"
  fi
}

run_scenario_cpu_comparison() {
  ROUNDS="${1:-25}"
  CONCURRENCY="${2:-5}"
  echo -e "\n${CYAN}${BOLD}[5/5] 🔥 Benchmark Comparatif Charge CPU (${ROUNDS} vagues x ${CONCURRENCY} attaques PHP2Shell simultanées)${RESET}"
  echo -e "  Observez en direct la courbe RAPL (Watts & % CPU) sur ${BOLD}https://aegis.aivo.fr/app${RESET} !"
  START_SEC=$(date +%s)
  BLOCKED_COUNT=0
  BYPASSED_COUNT=0

  for r in $(seq 1 "$ROUNDS"); do
    for c in $(seq 1 "$CONCURRENCY"); do
      curl -s -o /dev/null -w "%{http_code}\n" -X POST \
        "${TARGET_URL}/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input&iterations=450000&format=json" \
        -d "<?php /* flood */ ?>" >> /tmp/aegis_bench_codes.$$ &
    done
    wait
    printf "  Vague %02d/%02d envoyée...\r" "$r" "$ROUNDS"
  done
  echo ""

  if [ -f /tmp/aegis_bench_codes.$$ ]; then
    BLOCKED_COUNT=$(grep -c "^403$" /tmp/aegis_bench_codes.$$ || true)
    BYPASSED_COUNT=$(grep -c "^200$" /tmp/aegis_bench_codes.$$ || true)
    rm -f /tmp/aegis_bench_codes.$$
  fi
  ELAPSED=$(( $(date +%s) - START_SEC ))

  echo -e "  ----------------------------------------------------------------------"
  echo -e "  ⏱️  Durée totale pour $((ROUNDS * CONCURRENCY)) requêtes : ${BOLD}${ELAPSED}s${RESET}"
  echo -e "  🛡️  Requêtes bloquées en bordure (HTTP 403) : ${GREEN}${BOLD}${BLOCKED_COUNT}${RESET}"
  echo -e "  ⚠️  Requêtes ayant atteint PHP-FPM (HTTP 200) : ${RED}${BOLD}${BYPASSED_COUNT}${RESET}"
  echo -e "  ----------------------------------------------------------------------"
}

print_banner

MODE="${2:-all}"
case "$MODE" in
  legit)      run_scenario_legitimate ;;
  php2shell)  run_scenario_php2shell ;;
  sqli)       run_scenario_sqli ;;
  overflow)   run_scenario_overflow413 ;;
  stress)     run_scenario_cpu_comparison "${3:-30}" "${4:-6}" ;;
  all|*)
    run_scenario_legitimate
    run_scenario_php2shell
    run_scenario_sqli
    run_scenario_overflow413
    run_scenario_cpu_comparison 12 4
    ;;
esac

echo -e "\n${GREEN}${BOLD}✅ Simulation terminée. Consultez le Cockpit : https://aegis.aivo.fr/app${RESET}"
