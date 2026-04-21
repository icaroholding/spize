# Getting started with AEX

Three-minute walkthrough: two Python agents exchange a file locally.

## Prerequisites

- Docker Desktop running
- Rust toolchain (stable)
- Python 3.10+

## Steps

```bash
# 1. Start the control plane
docker compose -f deploy/docker-compose.dev.yml up -d
DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex \
  cargo run -p aex-control-plane

# 2. In a second terminal, install the Python SDK + run the demo
cd packages/sdk-python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python examples/demo_two_agents.py
```

What the demo does:

1. Generates two Ed25519 identities (Alice, Bob) and registers them
   with the control plane via signed proof-of-possession.
2. Alice signs a transfer intent over a small file (M1 path), the
   scanner clears it, Bob downloads and acks it. The audit chain
   records the event.
3. Alice tries again with the EICAR test malware — the scanner blocks
   delivery, no bytes ever reach Bob.

The M2 variant (`examples/demo_two_agents_m2.py`) exercises the new
peer-to-peer flow where bytes never touch the control plane. It
currently needs a running `cloudflared tunnel` to complete end-to-end;
without it, the demo stops at ticket issuance (which is already a
useful sanity check of the control-plane side).

## Self-hosting the control plane in production

Coming soon: `docs/self-host.md` with Fly.io / Render recipes.
