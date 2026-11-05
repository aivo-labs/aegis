# =============================================================================
# AEGIS GATE PEP & WAF — PASSERELLE D'INTERCEPTION INGRESS LÉGÈRE (< 25 MB RAM)
# =============================================================================

FROM node:22-alpine

WORKDIR /app

COPY package.json ./
COPY src/ ./src/
COPY dist/ ./dist/

EXPOSE 8000

ENV NODE_ENV=production
ENV GATE_PORT=8000

CMD ["node", "dist/src/index.js"]
