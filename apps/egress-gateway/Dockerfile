# =============================================================================
# AEGIS EGRESS GATEWAY — FILTRAGE DNS SORTANT & INFERENCE IA
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
RUN npm install --omit=dev

COPY --from=builder /app/dist ./dist

EXPOSE 5053/udp
EXPOSE 5053/tcp

CMD ["node", "dist/src/index.js"]
