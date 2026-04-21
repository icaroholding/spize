# ADR-0016: Single-region DERP (AMS), metric-gated expansion

## Status

Accepted 2026-04-21.

## Context

Iroh's relay story works best when there's a DERP server topologically
close to both peers; premature multi-region deploy adds ops work without
a measured benefit. The founder is EU-based, early adopters are likely EU
and US. Amsterdam (AMS) is a reasonable compromise — good EU latency,
acceptable transatlantic.

## Decision

Phase 1 ships DERP in Fly.io region `ams` only. We do not deploy a second
region until we observe one of: (a) median DERP-mediated transfer latency
above 800 ms, (b) >10 % of DERP-mediated transfers failing, (c) a paying
customer with a documented latency complaint traceable to DERP.

## Consequences

- One region to provision, one set of TLS certs, one network ACL to keep
  correct.
- US east-coast users pay ~100 ms extra; acceptable for file transfer
  where latency matters less than throughput.
- Concrete expansion trigger means "add more regions" doesn't drift into
  vibe-based decision-making.
- Monitoring must surface the three signals above (ADR-0034, ADR-0035)
  so the trigger fires quickly when it should.
