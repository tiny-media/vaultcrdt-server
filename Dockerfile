# ── Stage 1: base with Rust + cargo-chef ────────────────────────────────────
FROM rust:1.95.0-alpine3.23 AS chef
RUN apk add --no-cache musl-dev && cargo install cargo-chef --locked
WORKDIR /app

# ── Stage 2: compute dependency recipe ──────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: build dependencies (cached unless Cargo.toml/Cargo.lock change) ─
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# ── Stage 4: build binary (only reruns when src/ changes) ───────────────────
COPY . .
RUN cargo build --release --locked -p vaultcrdt-server

# ── Stage 5: minimal runtime image ──────────────────────────────────────────
FROM alpine:3.23.4
RUN apk add --no-cache ca-certificates sqlite wget
COPY --from=builder /app/target/release/vaultcrdt-server /usr/local/bin/vaultcrdt-server
RUN adduser -D -H -s /sbin/nologin vaultcrdt \
    && mkdir -p /var/lib/vaultcrdt \
    && chown vaultcrdt:vaultcrdt /var/lib/vaultcrdt
USER vaultcrdt
VOLUME ["/var/lib/vaultcrdt"]
EXPOSE 8080
ENV VAULTCRDT_DB_PATH=/var/lib/vaultcrdt/data.db
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1
CMD ["vaultcrdt-server"]
