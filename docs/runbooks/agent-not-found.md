# Runbook: `agent not found`

## Symptom

- **Status:** `404 Not Found`
- **`code`:** `not_found`
- **Message:** `agent <agent_id> not found`

## Likely cause

1. **Typo in the `agent_id` path parameter.** `GET /v1/agents/:id`
   does an exact match on the canonical form
   `spize:org/name:fingerprint`.
2. **Agent was never registered on this CP** — see also
   [agent-not-registered-or-revoked](agent-not-registered-or-revoked.md).
3. **Wrong CP URL.** Staging vs production / tenant A vs tenant B.

## Remediation

Register the agent, or verify you're hitting the right CP. If you're
building on top of the SDK, `SpizeClient.get_agent` catches and wraps
this as a standard `SpizeHTTPError`.

## Related

- `crates/aex-control-plane/src/routes/agents.rs::get_agent`
