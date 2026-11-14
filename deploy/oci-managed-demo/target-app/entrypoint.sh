#!/usr/bin/env bash
set -e

echo "🚀 Démarrage de la stack cliente de référence (Nginx + PHP-FPM 8.3 + Node.js)..."
php-fpm83 -D
node /app/node/node-service.mjs &
exec nginx -g "daemon off;"
