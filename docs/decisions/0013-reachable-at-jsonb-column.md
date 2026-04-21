# ADR-0013: `reachable_at[]` stored as a JSONB column, not a normalized table

## Status

Accepted 2026-04-21.

## Context

With multiple endpoints per transfer (ADR-0001), the database model has
two choices: normalize into `transfer_endpoints (transfer_id, position, kind,
url, …)` or denormalize into a `jsonb` column on `transfers`. Endpoints are
never queried independently — we always load them alongside the transfer —
and the cardinality is low (typically 1–6). Normalization buys nothing and
costs one JOIN on every transfer lookup.

## Decision

`transfers.reachable_at` is a `jsonb` column holding a JSON array of
endpoint objects. Reads and writes go through the `Transfer` row as a unit.

## Consequences

- Migration from `tunnel_url TEXT` to `reachable_at JSONB` is a single
  column add + backfill + drop in the `v1.3.0-beta.1` release.
- Indexing an individual endpoint (e.g. "all transfers using Iroh") is
  possible via `jsonb_path_ops` GIN index if it ever matters; no such
  query is planned.
- Validation is at the application layer: Rust serializes typed
  `Endpoint` structs, Postgres just stores and returns JSON.
- A later move to normalization is a local refactor if workload changes.
