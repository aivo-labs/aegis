#!/usr/bin/env bash
# ==============================================================================
# AEGIS SOVEREIGN GATE — INSTALLATEUR CLÉ EN MAIN VM ORACLE CLOUD (OCI)
# Configure le pare-feu local OCI (iptables), installe Docker si requis,
# enrôle le serveur auprès de https://aegis.aivo.fr et démarre la stack Multi-Langages.
# ==============================================================================
set -e

CONTROL_PLANE_URL="${AEGIS_CONTROL_PLANE_URL:-https://aegis.aivo.fr}"
SERVER_ID="${AEGIS_SERVER_ID:-oci-managed-client-01}"
ENROLL_TOKEN="${AEGIS_ENROLL_TOKEN:-ag_live_oci_managed_demo}"
OCI_HTTP_PORT="${OCI_HTTP_PORT:-80}"

echo "=============================================================================="
echo "🛡️  AEGIS SOVEREIGN GATE — DÉPLOIEMENT CLIENT MANAGED SUR ORACLE CLOUD (OCI)"
echo "=============================================================================="
echo "📡 Control Plane Cible : ${CONTROL_PLANE_URL}"
echo "🖥️  Identifiant Nœud    : ${SERVER_ID}"
echo "🌐 Port HTTP Exposé    : ${OCI_HTTP_PORT} (et :8000)"
echo "------------------------------------------------------------------------------"

# 1. Détection de l'IP publique de la VM Oracle Cloud
PUBLIC_IP=$(curl -s --max-time 4 https://ifconfig.me || echo "127.0.0.1")
echo "✅ Adresse IP Publique détectée : ${PUBLIC_IP}"

# 2. Ouverture des ports 80, 443 et 8000 dans iptables (spécificité des images Ubuntu Oracle Cloud)
if command -v iptables >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
  echo "🔓 Configuration du pare-feu local Oracle Cloud (iptables ports 80, 443, 8000)..."
  iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
  iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
  iptables -I INPUT 1 -p tcp --dport 8000 -j ACCEPT 2>/dev/null || true
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  fi
fi

# 3. Vérification / Installation de Docker & Docker Compose
if ! command -v docker >/dev/null 2>&1; then
  echo "📦 Docker non détecté — installation automatique en cours..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker || true
fi

# 4. Handshake d'enrôlement initial avec le Control Plane Aegis
echo "🤝 Enrôlement du nœud ${SERVER_ID} auprès de ${CONTROL_PLANE_URL}..."
OS_INFO="$(uname -sr 2>/dev/null || echo 'Linux 6.8 OCI')"
curl -s -X POST "${CONTROL_PLANE_URL}/api/v1/agent/enroll" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"${ENROLL_TOKEN}\",\"server_id\":\"${SERVER_ID}\",\"hostname\":\"${SERVER_ID}\",\"ip_address\":\"${PUBLIC_IP}\",\"provider\":\"Oracle Cloud (OCI)\",\"os_info\":\"${OS_INFO}\"}" || true
echo ""

# 5. Génération du fichier .env local
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cat > "${SCRIPT_DIR}/.env" <<EOF
AEGIS_CONTROL_PLANE_URL=${CONTROL_PLANE_URL}
AEGIS_SERVER_ID=${SERVER_ID}
AEGIS_ENROLL_TOKEN=${ENROLL_TOKEN}
AEGIS_PROVIDER=Oracle Cloud (OCI)
OCI_PUBLIC_IP=${PUBLIC_IP}
OCI_HTTP_PORT=${OCI_HTTP_PORT}
EOF

# 6. Construction et démarrage des conteneurs
echo "🚀 Construction et lancement de la stack cliente multi-langages (Nginx + PHP-FPM 8.3 + Node.js 20 + Aegis PEP)..."
cd "${SCRIPT_DIR}"
docker compose -f docker-compose.oci-client.yml up -d --build

echo ""
echo "=============================================================================="
echo "✅ DÉPLOIEMENT ORACLE CLOUD TERMINÉ AVEC SUCCÈS !"
echo "=============================================================================="
echo "🌐 Portail Client Protégé : http://${PUBLIC_IP}:${OCI_HTTP_PORT}"
echo "🛡️  Cockpit SOC Central    : ${CONTROL_PLANE_URL}/app"
echo "🎯 Lancer une démo live   : ./run-live-attack-demo.sh http://${PUBLIC_IP}:${OCI_HTTP_PORT}"
echo "=============================================================================="
