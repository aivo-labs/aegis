# =============================================================================
# AEGIS CONTROL PLANE API — GO RUNTIME (ZÉRO-MOCK, MULTI-STAGE BUILD)
# =============================================================================
FROM golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod ./
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o aegis-backend ./cmd/server/main.go

# =============================================================================
# RUNTIME IMAGE (ALPINE MINIMALE AVEC CA-CERTIFICATES & CURL)
# =============================================================================
FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl tzdata

WORKDIR /app

COPY --from=builder /build/aegis-backend /app/aegis-backend
COPY --from=builder /build/public/install.sh /app/public/install.sh
COPY --from=builder /build/migrations /app/migrations

RUN chmod +x /app/aegis-backend /app/public/install.sh

ENV PORT=80

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:80/health || exit 1

ENTRYPOINT ["/app/aegis-backend"]
