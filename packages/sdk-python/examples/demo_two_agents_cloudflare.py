"""End-to-end M2 demo: two agents exchange a file over a real Cloudflare
quick tunnel, control plane never sees the payload.

Preconditions
-------------
1. Postgres + control plane running::

       docker compose -f deploy/docker-compose.dev.yml up -d
       DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex \\
           cargo run -p aex-control-plane

2. `cloudflared` on PATH (brew install cloudflare/cloudflare/cloudflared)

What this demo does
-------------------
1. Fetches the control-plane signing public key via /v1/public-key.
2. Spawns `cargo run -p aex-data-plane` with an admin endpoint enabled,
   orchestrating a Cloudflare quick tunnel and printing
   ``AEX_DATA_PLANE_URL=https://<random>.trycloudflare.com`` on stdout.
3. Registers Alice and Bob identities.
4. Alice calls ``send_via_tunnel`` — the control plane stores the
   transfer with the tunnel URL and issues a transfer_id. No blob upload.
5. Alice uploads the blob to the data plane via its admin endpoint
   (loopback but protected by a random token since the tunnel exposes it).
6. Bob calls ``request_ticket`` — control plane returns a ticket signed
   with its Ed25519 key, bound to Alice's tunnel URL.
7. Bob calls ``fetch_from_tunnel`` — bytes flow from Alice → Bob via
   the tunnel, never through the control plane.
8. Bob verifies the received bytes and acks.

Run with::

    python packages/sdk-python/examples/demo_two_agents_cloudflare.py
"""

from __future__ import annotations

import atexit
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

from aex_sdk import Identity, SpizeClient

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTROL_PLANE = os.environ.get("AEX_CONTROL_PLANE_URL", "http://127.0.0.1:8080")
PAYLOAD = b"Hello from Alice via a real Cloudflare tunnel!\n"


def main() -> int:
    print(f"[0/8] control plane: {CONTROL_PLANE}")
    cp_pubkey = fetch_control_plane_pubkey()
    print(f"[0/8] control plane signing key: {cp_pubkey[:16]}…")

    admin_token = secrets.token_urlsafe(32)
    data_plane, data_plane_url = start_data_plane(cp_pubkey, admin_token)
    print(f"[1/8] data plane subprocess up, URL = {data_plane_url}")
    wait_for_reachable(data_plane_url, timeout=30.0)
    print(f"[1/8] tunnel DNS resolved, data plane reachable over the internet")

    alice_id = Identity.generate(org="demo", name=f"alice{int(time.time())}")
    bob_id = Identity.generate(org="demo", name=f"bob{int(time.time())}")

    with SpizeClient(base_url=CONTROL_PLANE, identity=alice_id) as alice:
        alice.register()
    with SpizeClient(base_url=CONTROL_PLANE, identity=bob_id) as bob:
        bob.register()
    print(f"[2/8] Alice: {alice_id.agent_id}")
    print(f"[2/8] Bob:   {bob_id.agent_id}")

    with SpizeClient(base_url=CONTROL_PLANE, identity=alice_id) as alice:
        tx = alice.send_via_tunnel(
            recipient=bob_id.agent_id,
            declared_size=len(PAYLOAD),
            declared_mime="text/plain",
            filename="hello.txt",
            tunnel_url=data_plane_url,
        )
    print(f"[3/8] transfer created: {tx.transfer_id} (state={tx.state})")

    upload_to_data_plane(
        data_plane_url=data_plane_url,
        transfer_id=tx.transfer_id,
        token=admin_token,
        payload=PAYLOAD,
        mime="text/plain",
        filename="hello.txt",
    )
    print(f"[4/8] Alice uploaded {len(PAYLOAD)} bytes to the data plane")

    with SpizeClient(base_url=CONTROL_PLANE, identity=bob_id) as bob:
        ticket = bob.request_ticket(tx.transfer_id)
        print(
            f"[5/8] Bob got ticket — expires in "
            f"{ticket.expires - int(time.time())}s"
        )

        bytes_ = bob.fetch_from_tunnel(ticket)
        print(f"[6/8] Bob fetched {len(bytes_)} bytes from the tunnel")

        if bytes_ != PAYLOAD:
            print(
                f"[FAIL] payload mismatch: expected {len(PAYLOAD)} bytes, "
                f"got {len(bytes_)}",
                file=sys.stderr,
            )
            return 1
        print("[7/8] payload matches — peer-to-peer round-trip verified")

        ack = bob.ack(tx.transfer_id)
    print(f"[8/8] Bob acknowledged; audit chain head: {ack['audit_chain_head'][:16]}…")

    print("\n✅ demo complete")
    return 0


def fetch_control_plane_pubkey() -> str:
    try:
        r = httpx.get(f"{CONTROL_PLANE}/v1/public-key", timeout=5.0)
        r.raise_for_status()
    except Exception as e:
        print(
            f"Cannot reach control plane at {CONTROL_PLANE}/v1/public-key: {e}\n"
            "Start the control plane first:\n"
            "  docker compose -f deploy/docker-compose.dev.yml up -d\n"
            "  DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex \\\n"
            "    cargo run -p aex-control-plane",
            file=sys.stderr,
        )
        sys.exit(2)
    return r.json()["public_key_hex"]


def start_data_plane(cp_pubkey: str, admin_token: str) -> tuple[subprocess.Popen, str]:
    env = os.environ.copy()
    env.update(
        AEX_CONTROL_PLANE_PUBLIC_KEY_HEX=cp_pubkey,
        AEX_TUNNEL_PROVIDER="cloudflare",
        AEX_ADMIN_TOKEN=admin_token,
        AEX_BIND_ADDR="127.0.0.1:0",
        RUST_LOG="info,aex_data_plane=info,aex_tunnel=info",
    )

    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "-p", "aex-data-plane"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    def cleanup() -> None:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass

    atexit.register(cleanup)

    # Read stdout until we see AEX_DATA_PLANE_URL=… (or the process dies).
    deadline = time.time() + 120.0  # cargo first-build can take a while
    url: str | None = None
    assert proc.stdout is not None
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                stderr_tail = (proc.stderr.read() if proc.stderr else "") or ""
                raise RuntimeError(
                    f"aex-data-plane exited (code {proc.returncode}) before "
                    f"emitting its URL.\n---- stderr ----\n{stderr_tail[-2000:]}"
                )
            time.sleep(0.1)
            continue
        if line.startswith("AEX_DATA_PLANE_URL="):
            url = line.strip().split("=", 1)[1]
            break

    if not url:
        cleanup()
        raise RuntimeError("data plane did not report its URL within 120s")

    return proc, url


def wait_for_reachable(url: str, timeout: float) -> None:
    """Poll GET {url}/healthz until it returns 200 or we give up.

    Cloudflare quick tunnels emit the public URL as soon as the edge
    connection is established, but the DNS record for
    *.trycloudflare.com typically needs another 5-10 seconds to
    propagate. Without this wait, the first httpx.post against the URL
    fails with "nodename nor servname provided, or not known".
    """
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"{url}/healthz", timeout=3.0)
            if r.status_code == 200:
                return
        except Exception as e:
            last_err = e
        time.sleep(1.0)
    raise RuntimeError(
        f"data plane at {url} not reachable within {timeout}s; "
        f"last error: {last_err!r}"
    )


def upload_to_data_plane(
    *,
    data_plane_url: str,
    transfer_id: str,
    token: str,
    payload: bytes,
    mime: str,
    filename: str,
) -> None:
    r = httpx.post(
        f"{data_plane_url}/admin/blob/{transfer_id}",
        params={"mime": mime, "filename": filename},
        headers={"x-aex-admin-token": token, "content-type": "application/octet-stream"},
        content=payload,
        timeout=30.0,
    )
    if r.status_code != 201:
        raise RuntimeError(f"admin upload failed: {r.status_code} {r.text}")


if __name__ == "__main__":
    sys.exit(main())
