# AEX Protocol v1

The protocol specification is under active maintenance. Until this
document is fully written, the authoritative references are:

- **Wire format byte-exact reference** — `crates/aex-core/src/wire.rs`:
  `registration_challenge_bytes`, `transfer_intent_bytes`,
  `transfer_receipt_bytes`, `data_ticket_bytes`.
- **State machine + architectural reasoning** —
  [docs/architecture.md](./architecture.md).
- **Reference identities format** — see the `AgentId::new()` validator
  in `crates/aex-core/src/types.rs`.

A full spec that allows re-implementation without reading the Rust
code is tracked as a v1.3.0-beta deliverable.

---

## §5. Normative network behaviour

The rules in this section are **normative**. Every conforming AEX
implementation (SDK, runtime, or tool) MUST behave identically for the
scenarios they cover. The reference implementation lives in `crates/aex-net/`;
Python and TypeScript conforming reimplementations live in
`packages/sdk-python/src/aex_sdk/` and `packages/sdk-typescript/src/`.

Conformance is asserted by a shared test suite: each language carries a
test that pins its own values to the numbers below, so a change to §5
fails the test in all three stacks simultaneously.

### §5.1 Retry policy

Any AEX network operation that can fail transiently — data-plane blob
fetch, control-plane healthcheck, DoH resolution, captive-portal probe —
MUST retry using the algorithm in this section.

**Parameters (normative):**

| Parameter     | Value       | Purpose |
|---------------|-------------|---------|
| max_attempts  | `3`         | Total attempts including the first. |
| base_delay    | `1000 ms`   | Base for the first retry. |
| multiplier    | `2.0`       | Applied between successive retries. |
| jitter        | `±100 ms`   | Uniformly sampled, clamped to non-negative total delay. |

**Sleep computation (normative):**

For attempt number `n` (1-indexed, `n=1` is the initial attempt):

```
sleep(n) = 0                                              if n == 1
sleep(n) = base_delay × multiplier^(n-2) + U(-jitter, +jitter)   if n >= 2
sleep(n) = max(0, sleep(n))                               (always clamped)
```

The jitter distribution is uniform over `[-jitter, +jitter]` inclusive.
The sample is drawn independently for every retry — **do not reuse** a
sample across retries within the same operation.

**Retriable vs permanent failures:**

Whether a particular error is retriable is **not** part of this spec.
The decision is the caller's and depends on the error class. By
convention, transport-level failures (connection refused, timeout, TLS
handshake failure, DNS failure, 5xx responses, 429) are retriable;
authentication failures (401, 403) and protocol errors (4xx other than
429) are not.

**Conformance:**

| Implementation                       | Module                                      | Constructor            |
|--------------------------------------|---------------------------------------------|------------------------|
| Rust `aex-net`                       | `aex_net::retry`                            | `RetryPolicy::normative()` |
| Python `aex_sdk`                     | `aex_sdk.retry`                             | `RetryPolicy.normative()` |
| TypeScript `@aexproto/sdk`           | `@aexproto/sdk` (exports from `retry.ts`)   | `RetryPolicy.normative()` |

Each implementation ships a conformance test pinning the four parameters
above. The Rust conformance test is at
`crates/aex-net/tests/conformance/retry.rs` and runs as part of
`cargo test -p aex-net`.

### §5.2 Reserved

Reserved for a future normative section on AEX HTTPS client
configuration (TLS version floor, cipher suite policy, DNS resolver
requirement). This section is intentionally left vacant in v1.x to
allow adjacent bumps without renumbering downstream references.

### §5.3 Captive-portal and degraded-network detection

Any AEX implementation that emits a network-state observation (e.g. the
`AEX_NETWORK_STATE=<value>` stdout flag on the data-plane binary) MUST
classify via the consensus algorithm defined below.

**Probe endpoints (normative):**

Three unauthenticated HTTP endpoints are probed in parallel. These
exact URLs are mandatory — they match the behaviour Apple, Google, and
Microsoft platforms use natively, so a network that is hostile to them
is hostile to real users regardless of AEX. Implementations MUST NOT
silently substitute alternatives.

| # | URL                                                  | Expected (clean network)          |
|---|------------------------------------------------------|-----------------------------------|
| 1 | `http://captive.apple.com/hotspot-detect.html`       | 200 OK + body contains `Success`  |
| 2 | `http://www.google.com/generate_204`                 | 204 No Content                    |
| 3 | `http://www.msftncsi.com/ncsi.txt`                   | 200 OK + body equals `Microsoft NCSI` (after trim) |

Probes MUST run in parallel. The per-probe timeout is implementation-
defined but SHOULD be no more than 5 seconds; exceeding the timeout
classifies that probe as `failed`.

**Per-probe verdict (normative):**

Each probe produces one of four verdicts:

- `ok` — the probe completed and matched the expected response.
- `captive` — the probe saw an HTTP 3xx redirect, OR a successful
  status code but an unexpected body (the hallmark of a captive-portal
  login page served at an arbitrary URL).
- `unexpected` — the probe completed but returned a status code that
  doesn't match the expected class (e.g. 500 on Apple, 200 instead of
  204 on Google).
- `failed` — the probe did not complete (timeout, TLS error, connection
  refused, DNS failure).

**Consensus (normative, first match wins):**

| Rule                                        | Resulting state  |
|---------------------------------------------|------------------|
| Any probe verdict is `captive`              | `captive_portal` |
| All three probe verdicts are `ok`           | `direct`         |
| All three probe verdicts are `failed`       | `unknown`        |
| Any other combination                       | `limited`        |

**State strings (normative):**

Implementations that serialise the state (stdout flag, JSON log line,
diagnostic payload) MUST use the tokens below — exact casing, exact
spelling. Any mismatch is a conformance failure.

| State             | String           |
|-------------------|------------------|
| Direct            | `direct`         |
| Captive portal    | `captive_portal` |
| Limited           | `limited`        |
| Unknown           | `unknown`        |

**The `AEX_NETWORK_STATE` stdout flag:**

AEX binaries that emit network-state on stdout MUST use the exact line
format:

```
AEX_NETWORK_STATE=<state>\n
```

with `<state>` drawn from the table above. The flag is advisory:
orchestrators may surface it to users but MUST NOT refuse to run based
on it. Binaries SHOULD emit the flag once at startup after the first
consensus computation; they MAY re-emit on network change.

**Conformance:**

| Implementation                       | Module                       | Entry point             |
|--------------------------------------|------------------------------|-------------------------|
| Rust `aex-net`                       | `aex_net::captive`           | `detect_network_state`  |
| Python `aex_sdk`                     | `aex_sdk.captive`            | `detect_network_state`  |
| TypeScript `@aexproto/sdk`           | `@aexproto/sdk`              | `detectNetworkState`    |
