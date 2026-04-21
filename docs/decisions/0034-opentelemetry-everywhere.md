# ADR-0034: OpenTelemetry everywhere, Grafana Cloud free tier

## Status

Accepted 2026-04-21.

## Context

Observability debt compounds. We either instrument up front with a
portable standard or we pay tenfold later by retrofitting it under
incident pressure. OpenTelemetry is the de-facto portable choice.
Grafana Cloud's free tier accepts OTLP export and is sufficient for
Y1 scale; a self-hosted backend is always an escape hatch.

## Decision

Every AEX service (control plane, data plane, DERP, TURNS) emits
OpenTelemetry traces + metrics via `tracing-opentelemetry` (Rust) and
the OTLP HTTP exporter. Default destination is Grafana Cloud's free
tier, configurable via env. SDKs do not export OpenTelemetry — zero
client-side telemetry (ADR-0008).

## Consequences

- Traces cover request-to-request flow across control-plane ↔ peer
  interactions.
- Moving off Grafana Cloud to self-hosted (or a paid competitor) is a
  config change.
- The free tier has cardinality limits; we attribute by `component` +
  `endpoint`, never by agent ID or transfer ID.
- On-call (Phase 3+) has a pre-built tracing surface to reason about.
