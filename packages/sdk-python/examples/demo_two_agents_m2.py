"""M2 demo — peer-to-peer bytes, control plane only signs tickets.

Preconditions (alpha.2 scaffold — full orchestration in a later release):
- control plane running with signer: set AEX_CONTROL_PLANE_URL.
- a running `aex-data-plane` on the sender machine exposed at
  AEX_DATA_PLANE_URL (https://, typically via `cloudflared tunnel`).

This script exercises the control-plane side of the M2 flow:
1. Two agents register.
2. Alice creates a transfer WITH tunnel_url (no blob upload).
3. Bob requests a ticket; control plane signs + returns.
4. Bob fetches bytes from the tunnel URL presenting the ticket.

Until cloudflared is wired up end-to-end, step 4 fails at DNS — that is
expected and marked as TODO(alpha.3).
"""

import os
import time

from aex_sdk import SpizeClient, Identity


def main() -> None:
    base = os.environ.get("AEX_CONTROL_PLANE_URL", "http://127.0.0.1:8080")
    tunnel = os.environ.get("AEX_DATA_PLANE_URL", "https://alice.tunnel.example")

    alice_id = Identity.generate(org="demo", name=f"alice{int(time.time())}")
    bob_id = Identity.generate(org="demo", name=f"bob{int(time.time())}")

    with SpizeClient(base_url=base, identity=alice_id) as alice:
        alice.register()
    with SpizeClient(base_url=base, identity=bob_id) as bob:
        bob.register()

    print(f"Alice: {alice_id.agent_id}")
    print(f"Bob:   {bob_id.agent_id}")

    # Alice announces a transfer via M2 (no blob upload).
    with SpizeClient(base_url=base, identity=alice_id) as alice:
        tx = alice.send_via_tunnel(
            recipient=bob_id.agent_id,
            declared_size=42,
            declared_mime="text/plain",
            filename="hello.txt",
            tunnel_url=tunnel,
        )
        print(f"\n[1] Transfer created on M2 path:\n    {tx.transfer_id}")
        print(f"    state: {tx.state}")

    # Bob requests a ticket.
    with SpizeClient(base_url=base, identity=bob_id) as bob:
        ticket = bob.request_ticket(tx.transfer_id)
        print(f"\n[2] Ticket issued:")
        print(f"    data_plane_url: {ticket.data_plane_url}")
        print(f"    expires:        {ticket.expires} ({ticket.expires - int(time.time())}s from now)")
        print(f"    nonce:          {ticket.nonce[:12]}…")

        # TODO(alpha.3): Actually fetch when cloudflared is orchestrated.
        # bytes_ = bob.fetch_from_tunnel(ticket)
        # print(f"\n[3] Fetched {len(bytes_)} bytes from tunnel")


if __name__ == "__main__":
    main()
