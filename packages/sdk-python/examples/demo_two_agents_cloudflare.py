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
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

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
    wait_for_reachable(data_plane_url, dns_timeout=120.0, http_timeout=30.0)
    print(f"[1/8] tunnel fully reachable from the public internet")

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


def wait_for_reachable(
    url: str,
    dns_timeout: float = 120.0,
    http_timeout: float = 30.0,
) -> None:
    """Wait for a Cloudflare quick tunnel to be reachable end-to-end.

    Done in two phases so failures point at the right cause:
    1. DNS phase — `socket.getaddrinfo` for the hostname until it
       resolves. `*.trycloudflare.com` records typically appear in
       public DNS 5-30 seconds AFTER cloudflared emits the URL on
       stderr, and macOS caches negative lookups (NXDOMAIN) for
       several seconds, so we poll the raw resolver rather than relying
       on httpx's connection pool which may cache its own failures.
    2. HTTP phase — once DNS answers, poll `GET /healthz` with a fresh
       httpx client each attempt. A healthy response means the tunnel,
       the Cloudflare edge, and our axum server are all up.
    """
    hostname = urlparse(url).hostname
    if hostname is None:
        raise RuntimeError(f"cannot parse hostname from {url!r}")

    dns_deadline = time.time() + dns_timeout
    last_dns_err: Exception | None = None
    while time.time() < dns_deadline:
        try:
            socket.getaddrinfo(hostname, 443)
            break
        except socket.gaierror as e:
            last_dns_err = e
            time.sleep(2.0)
    else:
        raise RuntimeError(
            f"DNS never resolved {hostname} within {dns_timeout}s "
            f"(last error: {last_dns_err!r}). "
            "cloudflared may have emitted a URL that never reached "
            "Cloudflare's authoritative DNS."
        )

    http_deadline = time.time() + http_timeout
    last_http_err: Exception | None = None
    while time.time() < http_deadline:
        try:
            with httpx.Client(timeout=5.0) as c:
                r = c.get(f"{url}/healthz")
                if r.status_code == 200:
                    return
                last_http_err = RuntimeError(
                    f"/healthz returned {r.status_code}: {r.text[:200]!r}"
                )
        except Exception as e:
            last_http_err = e
        time.sleep(1.0)
    raise RuntimeError(
        f"DNS resolved but {url}/healthz not 200 within {http_timeout}s "
        f"(last error: {last_http_err!r})"
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
