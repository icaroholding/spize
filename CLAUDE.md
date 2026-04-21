# AEX — repo guidance

Public reference implementation of AEX (Agent Exchange Protocol).

## Build whole workspace
```
cargo check --workspace
```

## Integration tests (requires Postgres)
```
docker compose -f deploy/docker-compose.dev.yml up -d
DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex cargo test --workspace
```

## Crates
- `aex-core` — shared types, traits, wire formats, errors
- `aex-identity` — SpizeNativeProvider (Ed25519), EtereCitizen provider
- `aex-control-plane` — registry + ticket issuer + audit anchor (BSL-1.1)
- `aex-audit` — Merkle-chained local audit log + Rekor trait
- `aex-scanner` — size / MIME / YARA / regex pipeline
- `aex-policy` — pre-send + post-scan trait + tier default
- `aex-tunnel` — Cloudflare tunnel orchestration
- `aex-billing` — billing provider trait (skeleton; real Stripe in spize-enterprise)

## Packages
- `packages/sdk-python` — PyPI `aex-sdk`, imported as `aex_sdk`
- `packages/sdk-typescript` — npm `@aexproto/sdk`
- `packages/mcp-server` — npm `@aexproto/mcp-server`

## Related
- Spize Desktop (private): https://github.com/icaroholding/aex-desktop
- Spize Enterprise (private): https://github.com/icaroholding/aex-enterprise
- EtereCitizen (public): https://github.com/icaroholding/EtereCitizen

## Identity format

Wire format keeps `spize:org/name:fingerprint` as the identity namespace. The protocol rename to AEX is a package-level branding change — the identity prefix, tool names, and canonical message prefixes are held stable for compatibility.
