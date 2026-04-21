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
    # `start_data_plane` only returns after the binary emits AEX_READY=1,
    # which is itself gated on a successful self-roundtrip through the
    # tunnel. No client-side reachability check is needed.
    print(f"[1/8] data plane ready at {data_plane_url}")

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

        # Fetch via curl for the same DNS-robustness reason as the
        # upload step. See upload_to_data_plane() docstring.
        bytes_ = fetch_from_tunnel_via_curl(ticket)
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

    # Read stdout until we see BOTH `AEX_DATA_PLANE_URL=...` and
    # `AEX_READY=1`. The binary prints them in that order, and only
    # emits the second one after verifying a full round-trip through
    # the tunnel. Waiting for both is the readiness contract the
    # binary guarantees.
    # 240s total: 120s for cargo first-build, up to 120s for DNS
    # propagation + self-roundtrip inside the binary.
    deadline = time.time() + 240.0
    url: str | None = None
    ready = False
    assert proc.stdout is not None
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                stderr_tail = (proc.stderr.read() if proc.stderr else "") or ""
                raise RuntimeError(
                    f"aex-data-plane exited (code {proc.returncode}) before "
                    f"it became ready.\n---- stderr ----\n{stderr_tail[-3000:]}"
                )
            time.sleep(0.1)
            continue
        if line.startswith("AEX_DATA_PLANE_URL="):
            url = line.strip().split("=", 1)[1]
        elif line.strip() == "AEX_READY=1":
            ready = True
            break

    if not (url and ready):
        cleanup()
        raise RuntimeError(
            f"data plane never reached AEX_READY=1 within 240s "
            f"(url_seen={url is not None}, ready={ready})"
        )

    return proc, url


def _hostname_of(url: str) -> str:
    from urllib.parse import urlparse

    host = urlparse(url).hostname
    if not host:
        raise RuntimeError(f"cannot parse hostname from {url!r}")
    return host


def resolve_via_cloudflare(hostname: str, timeout: float = 30.0) -> str:
    """Resolve `hostname` to an IPv4 by talking to Cloudflare's DNS
    over HTTPS (https://1.1.1.1/dns-query).

    Why DoH and not `dig @1.1.1.1`: plain DNS over UDP/53 is frequently
    blocked or transparently rewritten on corporate / captive / consumer
    wifi (seen live on this laptop — dig returned an empty body with
    no stderr, i.e. the resolver was intercepting). DoH runs on TCP/443
    and is indistinguishable from regular HTTPS, so it rides through.

    We curl to 1.1.1.1 directly with `--resolve` so there's zero DNS
    dependency in the resolution of the resolver itself. Retries for
    up to `timeout`s because a fresh *.trycloudflare.com record can
    take a second or two to land in Cloudflare's own public DNS.
    """
    import json
    import shutil

    if shutil.which("curl") is None:
        raise RuntimeError("curl not found on PATH")

    deadline = time.time() + timeout
    last_err = "no attempts"
    while time.time() < deadline:
        proc = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                # Talk to 1.1.1.1 directly by IP, no DNS needed for the
                # resolver endpoint itself.
                "--resolve",
                "cloudflare-dns.com:443:1.1.1.1",
                "-H",
                "accept: application/dns-json",
                f"https://cloudflare-dns.com/dns-query?name={hostname}&type=A",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                for ans in data.get("Answer", []):
                    # RR type 1 == A.
                    if ans.get("type") == 1 and isinstance(ans.get("data"), str):
                        return ans["data"]
                last_err = f"DoH answered but no A record: {data}"
            except json.JSONDecodeError as e:
                last_err = f"DoH response not JSON: {e}; body={proc.stdout[:200]!r}"
        else:
            last_err = (
                f"DoH curl failed exit={proc.returncode} "
                f"stdout={proc.stdout[:200]!r} stderr={proc.stderr[:200]!r}"
            )
        time.sleep(2.0)
    raise RuntimeError(
        f"could not resolve {hostname} via DoH @ 1.1.1.1 within {timeout}s "
        f"(last: {last_err})"
    )


def _curl_with_resolve(hostname: str, ip: str, args: list[str]) -> subprocess.CompletedProcess:
    """Run curl with --resolve so DNS is bypassed entirely and curl
    talks directly to `ip` while keeping TLS SNI + HTTP Host set to
    `hostname`.
    """
    import shutil

    if shutil.which("curl") is None:
        raise RuntimeError("curl not found on PATH")
    return subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--resolve",
            f"{hostname}:443:{ip}",
            "--max-time",
            "30",
        ]
        + args,
        capture_output=True,
        timeout=45,
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
    """POST the blob to the data plane's admin endpoint.

    DNS resolution is done out-of-band via `dig @1.1.1.1` and then fed
    to curl through `--resolve hostname:443:ip`. This means the HTTP
    call is completely independent of whichever DNS resolver Python or
    the OS would pick — which matters on macOS + wifi networks that
    ship a search-domain suffix, and during the first ~minute of a
    fresh Cloudflare quick-tunnel before it has fully propagated into
    ISP resolvers.
    """
    import tempfile
    import urllib.parse

    hostname = _hostname_of(data_plane_url)
    ip = resolve_via_cloudflare(hostname)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".blob") as f:
        f.write(payload)
        blob_path = f.name

    qs = urllib.parse.urlencode({"mime": mime, "filename": filename})
    url = f"{data_plane_url}/admin/blob/{transfer_id}?{qs}"

    try:
        proc = _curl_with_resolve(
            hostname,
            ip,
            [
                "-X",
                "POST",
                url,
                "-H",
                f"x-aex-admin-token: {token}",
                "-H",
                "content-type: application/octet-stream",
                "--data-binary",
                f"@{blob_path}",
                "-o",
                "/dev/null",
                "-w",
                "HTTP_CODE=%{http_code}",
            ],
        )
    finally:
        try:
            os.unlink(blob_path)
        except OSError:
            pass

    stdout_text = proc.stdout.decode("utf-8", errors="replace") if isinstance(proc.stdout, bytes) else proc.stdout
    stderr_text = proc.stderr.decode("utf-8", errors="replace") if isinstance(proc.stderr, bytes) else proc.stderr
    if proc.returncode != 0 or "HTTP_CODE=201" not in stdout_text:
        raise RuntimeError(
            f"admin upload failed (exit={proc.returncode}): "
            f"stdout={stdout_text[-500:]!r} stderr={stderr_text[-500:]!r}"
        )


def fetch_from_tunnel_via_curl(ticket) -> bytes:
    """Same DNS-bypass trick as upload_to_data_plane."""
    hostname = _hostname_of(ticket.data_plane_url)
    ip = resolve_via_cloudflare(hostname)

    url = f"{ticket.data_plane_url}/blob/{ticket.transfer_id}"
    proc = _curl_with_resolve(
        hostname,
        ip,
        [
            "-X",
            "GET",
            url,
            "-H",
            f"x-aex-ticket: {ticket.as_header()}",
            "-o",
            "-",
        ],
    )
    if proc.returncode != 0:
        stderr_text = (
            proc.stderr.decode("utf-8", errors="replace")
            if isinstance(proc.stderr, bytes)
            else proc.stderr
        )
        raise RuntimeError(
            f"tunnel fetch failed (exit={proc.returncode}): {stderr_text[-500:]!r}"
        )
    return proc.stdout if isinstance(proc.stdout, bytes) else proc.stdout.encode()


if __name__ == "__main__":
    sys.exit(main())
