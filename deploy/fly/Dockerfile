# syntax=docker/dockerfile:1.7
#
# Multi-stage production build for `aex-control-plane`.
#
# Two stages:
#   1. `builder` — full Rust toolchain + cargo-chef for dependency
#      caching. Produces a musl-statically-linked binary so the
#      runtime image can stay minimal.
#   2. `runtime` — distroless/static:nonroot. Ships only the binary,
#      the SSL roots, and the migration SQL files. No shell, no
#      package manager, no network tools.
#
# Image size target: < 25 MB. That's practical for Fly.io's machine
# pull cadence and keeps the supply-chain attack surface small.
#
# Build locally:
#   docker build -f deploy/fly/Dockerfile -t aex-control-plane:dev .
#
# Run locally against the dev Postgres (from deploy/docker-compose.dev.yml):
#   docker run --rm -p 8080:8080 --network host \
#     -e DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex \
#     -e AEX_ADMIN_TOKEN=$(openssl rand -hex 16) \
#     aex-control-plane:dev

# ---------- builder ----------
FROM rust:1.83-alpine AS builder

# Alpine's musl target is already the default when the toolchain is
# rust:*-alpine. We still add it explicitly so an accidental bump to
# a glibc-based base image doesn't silently switch link flavour.
RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static

WORKDIR /src

# Copy manifests FIRST so `cargo fetch` is a single layer that can be
# cached across source edits. Copying src/ and migrations/ afterwards
# invalidates only the later build layers.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY packages/ packages/

# Build in release mode. The --locked flag forces cargo to honour
# Cargo.lock exactly — a drift here would make reproducible builds
# impossible.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build \
        --release \
        --locked \
        --bin aex-control-plane \
        --package aex-control-plane && \
    cp /src/target/release/aex-control-plane /usr/local/bin/aex-control-plane && \
    strip /usr/local/bin/aex-control-plane

# ---------- runtime ----------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

WORKDIR /app

# Migrations travel with the binary so `sqlx::migrate!("./migrations")`
# keeps resolving at startup. The macro embeds the SQL into the
# binary at compile time too, but the runtime copy keeps `sqlx
# migrate` CLI ergonomics available if we ever run one-off manual
# migrations against a prod DB.
COPY --from=builder /src/crates/aex-control-plane/migrations /app/migrations
COPY --from=builder /usr/local/bin/aex-control-plane /app/aex-control-plane

# Persistent state: audit log, blob store, signing key. Fly.io
# mounts a volume at /app/data (see fly.toml). Distroless runs as
# `nonroot` (uid 65532) — the volume's perms must match.
ENV AUDIT_LOG_PATH=/app/data/audit.jsonl \
    BLOB_DIR=/app/data/blobs \
    SIGNING_KEY_PATH=/app/data/signing-key.bin \
    BIND_ADDR=0.0.0.0:8080 \
    LOG_FORMAT=json

EXPOSE 8080

# `nonroot` is uid 65532 in distroless. Explicit so a future image
# change that drops the default doesn't elevate us back to root.
USER nonroot

ENTRYPOINT ["/app/aex-control-plane"]
