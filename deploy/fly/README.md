# Fly.io deploy — `aex-control-plane`

One-shot guide to get `api.spize.io` serving production traffic.
Follow in order; steps 1-4 are one-time setup, step 5 is the first
deploy, step 6 is the DNS cutover, step 7 is the smoke test.

## Prerequisites

- A Fly.io account. Free tier is enough for the initial deploy.
- `flyctl` installed: `brew install flyctl` (Mac) or
  `curl -L https://fly.io/install.sh | sh` (Linux).
- Local `docker` or `podman` is optional but useful for smoke-testing
  the built image before pushing.

## 1. Log in to Fly

```bash
fly auth signup    # if this is your first Fly account
fly auth login     # if you already have one
```

## 2. Launch the app (no-deploy)

From the repo root:

```bash
fly launch \
    --config deploy/fly/fly.toml \
    --copy-config \
    --no-deploy \
    --name aex-control-plane \
    --region ams
```

If the name `aex-control-plane` is already taken, flyctl will prompt
for an alternative — pick something like `aex-cp-spize`. Update
`fly.toml` accordingly.

## 3. Provision Postgres

The control plane needs Postgres 14+ with `pgcrypto` for UUIDs.
Two options:

### 3a. Fly's managed Postgres (simplest)

```bash
fly postgres create \
    --name aex-postgres \
    --region ams \
    --initial-cluster-size 1 \
    --vm-size shared-cpu-1x \
    --volume-size 10

fly postgres attach aex-postgres --app aex-control-plane
```

The attach step writes `DATABASE_URL` into the app's secrets
automatically.

### 3b. External Postgres (Neon, Supabase, self-hosted)

Set `DATABASE_URL` by hand:

```bash
fly secrets set \
    --app aex-control-plane \
    DATABASE_URL='postgres://user:pass@host:5432/aex?sslmode=require'
```

## 4. Set all required secrets

```bash
# Admin API token — needed once PR #36 (admin bearer-token gate) is
# merged. Generate fresh; this is the operator-facing master key
# for /v1/admin/* endpoints.
fly secrets set \
    --app aex-control-plane \
    AEX_ADMIN_TOKEN="$(openssl rand -hex 16)"

# CORS allowlist: lock to spize.io (plus api.spize.io for
# browser-side self-calls). Leave unset for same-origin only.
fly secrets set \
    --app aex-control-plane \
    CORS_ALLOWED_ORIGINS='https://spize.io,https://api.spize.io'

# Optional: verbose logging for the first deploy so you see any
# startup warnings clearly.
fly secrets set \
    --app aex-control-plane \
    RUST_LOG='info,aex_control_plane=debug,sqlx=warn'
```

## 5. Provision the persistent volume

Audit log + blob store + signing key all persist under `/app/data`.
Mount a single volume:

```bash
fly volumes create aex_data \
    --app aex-control-plane \
    --region ams \
    --size 10    # GB; bump later, can't shrink
```

## 6. First deploy

```bash
fly deploy --config deploy/fly/fly.toml
```

Watch the logs during startup:

```bash
fly logs --app aex-control-plane
```

You should see:

```text
INFO aex_control_plane: aex-control-plane starting bind=0.0.0.0:8080
INFO aex_control_plane: database migrations applied
INFO aex_control_plane: audit log opened path=/app/data/audit.jsonl
INFO aex_control_plane: blob store ready dir=/app/data/blobs
INFO aex_control_plane: control-plane signing key ready pub_key=<hex>
INFO aex_control_plane: admin endpoints enabled; presenting Bearer abcdef... opens /v1/admin/*
INFO aex_control_plane::health_monitor: health monitor started
INFO aex_control_plane: listening addr=0.0.0.0:8080
```

Smoke-test it from your laptop:

```bash
# Public URL Fly assigned during `fly launch`:
FLY_URL=$(fly info --app aex-control-plane --json | jq -r '.Hostname')

curl -sS "https://$FLY_URL/healthz" | jq .
# {"status":"ok","service":"aex-control-plane","version":"1.3.0-beta.1"}

curl -sS "https://$FLY_URL/v1/public-key" | jq .
# {"algorithm":"ed25519","public_key_hex":"..."}
```

## 7. Wire GitHub Actions auto-deploy

```bash
# Create a deploy-scoped token (NOT your personal login token)
fly tokens create deploy --app aex-control-plane
# Copy the output. It starts with "FlyV1 fm2_...".

# Store it as a GitHub Actions secret:
gh secret set FLY_API_TOKEN \
    --app actions \
    --repo icaroholding/aex \
    --body '<paste-the-token>'
```

From now on, every push to `master` that touches control-plane code
or `deploy/fly/**` triggers `.github/workflows/fly-deploy.yml` and
auto-deploys.

## 8. DNS: point `api.spize.io` at Fly

```bash
# Tell Fly to issue a TLS cert for your hostname:
fly certs add api.spize.io --app aex-control-plane

# Fly prints the DNS records you need. Typical output:
#
#   Type    Hostname         Value
#   -----   ---------------  --------
#   A       api.spize.io     66.241.124.x
#   AAAA    api.spize.io     2a09:8280:1::x
#
# Add these in your DNS provider (Cloudflare, Porkbun, wherever
# spize.io lives). Propagation is usually <5 min.
```

Verify with `dig +short api.spize.io` — once the A record resolves,
Fly's ACME dance auto-issues the TLS cert and `curl
https://api.spize.io/healthz` starts working.

## Rollback

```bash
# Show recent releases:
fly releases --app aex-control-plane

# Roll back to the previous one:
fly releases rollback --app aex-control-plane <version-number>
```

Migrations run on every boot via `sqlx::migrate!`. Rolling back to a
release that predates a schema change is SAFE — the old binary
simply won't see the new tables. Going forward again reapplies the
migration. Be careful about data-destructive migrations (we don't
have any today but document this when one lands).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `fly deploy` fails during build | Cargo cache corrupted | `fly deploy --no-cache` |
| Deploy succeeds but `/healthz` 503s | DB unreachable / wrong DATABASE_URL | `fly logs` and check for "could not connect to database" |
| `/v1/admin/*` returns 503 `admin_disabled` | AEX_ADMIN_TOKEN not set | `fly secrets set AEX_ADMIN_TOKEN=...` |
| CORS errors from spize.io | origin not in allowlist | `fly secrets set CORS_ALLOWED_ORIGINS='https://spize.io,...'` |
| `cannot create signing key` on boot | volume perms wrong | `fly ssh console -C 'ls -la /app/data'` — uid should be 65532 (nonroot) |
| Admin token leaked accidentally | — | `fly secrets set AEX_ADMIN_TOKEN=$(openssl rand -hex 16)` → triggers redeploy with new value |

## What's NOT covered here

- **OpenTelemetry tracing** — Sprint 3 plan task 5, deferred pending
  an OTLP collector choice.
- **DERP + TURNS co-location** — Sprint 3 plan task 2; lives in
  sibling Fly apps `aex-derp` and `aex-turns` eventually.
- **Stripe webhook** — Sprint 4 Stripe skeleton PR will add the
  public webhook URL (`https://api.spize.io/webhooks/stripe`) to
  this checklist.
