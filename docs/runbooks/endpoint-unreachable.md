# Runbook: `all reachable_at endpoints failed validation`

## Symptom

- **Status:** `400 Bad Request`
- **`code`:** `bad_request`
- **Message:** `all reachable_at endpoints failed validation (N
  entries). First error: <cause>` or `tunnel_url <...> did not respond
  200 on /healthz after N attempts`

## Likely cause

1. **Sender's data plane hasn't finished coming up.** The SDK called
   `POST /v1/transfers` before the sender's `aex-data-plane` binary
   emitted `AEX_READY=1`. On cloudflared the DNS propagation window
   is 5-30 s; the admission-time probe has a 15 s budget per ADR-0014
   so this race is narrow but real.
2. **Sender's tunnel died between admission and retry.** A recipient
   SDK retrying `POST /v1/transfers` after a transient error may now
   find all endpoints dead where one was healthy minutes ago.
3. **Cloudflare edge blocked.** The control plane host cannot reach
   the quick-tunnel hostname — corporate firewall rules, DNS
   blackhole, or a CF incident.
4. **Wrong `reachable_at` schema.** The `url` value was malformed
   (e.g. HTTP instead of HTTPS). The validator returns "unknown
   endpoint kind" for non-HTTP transports it can't probe on its side.

## Remediation

1. Confirm the sender's data plane printed `AEX_READY=1` BEFORE the
   SDK sent the transfer. Orchestrators MUST gate on that line.
2. From the CP host, curl the first endpoint:
   ```bash
   curl -v https://<your-tunnel>.trycloudflare.com/healthz
   ```
   If this fails, the CP-to-tunnel path is broken — check DNS
   (`dig +short <hostname>`) and egress firewall.
3. Verify `reachable_at` entries parse as valid `Endpoint`:
   ```json
   { "kind": "cloudflare_quick", "url": "https://...", "priority": 0 }
   ```
   `kind` must be one of `cloudflare_quick` / `cloudflare_named` /
   `iroh` / `tailscale_funnel` / `frp` — anything else is treated
   as unhealthy.

The background health monitor will re-probe admitted transfers every
30 s (ADR-0021); transient flaps heal within ~1 min on their own.

## Related

- [ADR-0014 — transport validation budget](../decisions/0014-transport-validation-budget.md)
- [ADR-0021 — endpoint health asymmetric debouncing](../decisions/0021-endpoint-health-asymmetric-debouncing.md)
- `crates/aex-control-plane/src/endpoint_validator.rs`
