# ADR-0020: `POST /admin/blob/:id` is first-write-wins; second write returns 409

## Status

Accepted 2026-04-21.

## Context

The data-plane admin endpoint accepts orchestrator uploads for
pre-declared transfer IDs. Retries and races could produce a duplicate
upload for the same `transfer_id` — in-flight retry, redeploy during a
long upload, or (benignly) a demo runner that re-invokes after a
timeout. Accepting later writes silently is wrong: the blob has already
been associated with a content hash that the recipient will verify.

## Decision

`POST /admin/blob/:transfer_id` is first-write-wins. A subsequent POST
for the same `transfer_id` returns HTTP **409 Conflict** with a body
naming the existing blob's size + SHA-256. The existing blob is not
replaced.

## Consequences

- Orchestrators can safely retry uploads — the second attempt's 409 is
  self-describing and they can verify against it.
- There is no admin path for *replacing* a blob; once uploaded, it's
  the content of that transfer. If replacement is ever needed, it's a
  new `transfer_id`.
- Memory for a failed-and-retried upload is not leaked — the first write
  succeeded; the retries fail fast.
- The audit log records each 409 attempt at debug level for incident
  triage.
