# =============================================================================
# AEGIS DOCUMENTATION — ASTRO STARLIGHT (< 15 MB RAM)
# =============================================================================

FROM node:22-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9 --activate

COPY package.json ./
RUN pnpm install --frozen-lockfile=false

COPY . ./
RUN pnpm build

FROM nginx:alpine AS runner

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
