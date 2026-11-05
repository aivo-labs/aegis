# =============================================================================
# AEGIS TELEMETRY AGENT — SONDE ÉNERGÉTIQUE SOUVERAINE EN RUST (< 15 MB RAM)
# =============================================================================

FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static

WORKDIR /app
COPY Cargo.toml ./
# Cache des dépendances
RUN mkdir src && echo "pub fn dummy() {}" > src/lib.rs && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Compilation du code source
COPY src/ ./src/
RUN touch src/main.rs src/lib.rs && cargo build --release

# -----------------------------------------------------------------------------
# Étape finale d'exécution (Alpine minimale)
# -----------------------------------------------------------------------------
FROM alpine:latest AS runner

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/target/release/aegis-telemetry-agent /usr/local/bin/aegis-telemetry-agent

CMD ["aegis-telemetry-agent"]
