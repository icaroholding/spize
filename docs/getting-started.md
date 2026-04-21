# Getting started with AEX

Two walkthroughs: a simple **M1** demo (blob flows through control plane)
and the production-style **M2** demo (bytes flow peer-to-peer over a
Cloudflare tunnel, control plane never sees payload).

## Prerequisites

- Docker Desktop running
- Rust toolchain (stable)
- Python 3.10+
- For the M2 demo: `cloudflared` on PATH
  (`brew install cloudflare/cloudflare/cloudflared` on macOS)

## M1 demo — control-plane-mediated transfer

```bash
# 1. Start Postgres + control plane
docker compose -f deploy/docker-compose.dev.yml up -d
DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex \
  cargo run -p aex-control-plane

# 2. In a second terminal, install the Python SDK + run the demo
cd packages/sdk-python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python examples/demo_two_agents.py
```

What happens:

1. Two Ed25519 identities (Alice, Bob) register with the control plane
   via signed proof-of-possession.
2. Alice signs a transfer intent, the control plane stores and scans
   the blob, Bob downloads and acks it. The audit chain records it.
3. Alice tries again with the EICAR test malware — the scanner blocks
   delivery, no bytes ever reach Bob.

## M2 demo — peer-to-peer over a real Cloudflare tunnel

```bash
# 1. Keep the control plane from the M1 demo running.
# 2. In a third terminal (venv already active):
python examples/demo_two_agents_cloudflare.py
```

The demo script orchestrates the full flow in ~30 seconds:

1. Fetches the control plane's signing public key via `/v1/public-key`.
2. Spawns `cargo run -p aex-data-plane` with a Cloudflare quick-tunnel
   and an admin endpoint protected by a random token; captures the
   `AEX_DATA_PLANE_URL=https://*.trycloudflare.com` it prints.
3. Registers Alice and Bob.
4. Alice calls `send_via_tunnel` — the control plane records the
   tunnel URL against a new `transfer_id` without ever seeing bytes.
5. Alice uploads the blob to the data plane's admin endpoint.
6. Bob calls `request_ticket` — the control plane signs a short-lived
   ticket bound to the tunnel URL.
7. Bob calls `fetch_from_tunnel` — bytes flow directly from Alice's
   data plane to Bob. Verifies a byte-for-byte match.
8. Bob acks; the audit chain head is printed.

If step 2 times out, it's usually either a missing `cloudflared`
binary or no outbound HTTPS — everything else should just work.

## Self-hosting the control plane in production

Coming soon: `docs/self-host.md` with Fly.io / Render recipes.
