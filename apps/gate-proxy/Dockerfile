# =============================================================================
# AEGIS GATE PEP & WAF — PASSERELLE D'INTERCEPTION INGRESS LÉGÈRE (< 25 MB RAM)
# =============================================================================

FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json tsconfig.json ./
RUN npm install

COPY src/ ./src/
RUN npx tsc -p tsconfig.json

FROM node:22-alpine AS runner

WORKDIR /app

COPY package.json ./
COPY --from=builder /app/dist ./dist

EXPOSE 8000

ENV NODE_ENV=production
ENV GATE_PORT=8000

CMD ["node", "dist/src/index.js"]
