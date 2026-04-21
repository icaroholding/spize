# spize (Python SDK)

Python client for the [Agent Exchange Protocol (AEX)](https://github.com/icaroholding/aex).

## Install

```sh
pip install spize
```

## Quick start

```python
from spize import Identity, SpizeClient

# One-time: create + register an identity.
identity = Identity.generate(org="acme", name="alice")
identity.save("alice.key")

client = SpizeClient(base_url="http://localhost:8080", identity=identity)
client.register()

# Send.
transfer = client.send(
    recipient="spize:acme/bob:aabbcc",
    file="invoice.pdf",
    declared_mime="application/pdf",
)
print(transfer.state)  # 'ready_for_pickup' or 'rejected'

# Receive (as Bob).
bob = Identity.load("bob.key")
bob_client = SpizeClient(base_url="http://localhost:8080", identity=bob)
bytes_in = bob_client.download(transfer.transfer_id)
bob_client.ack(transfer.transfer_id)
```

## Components

- `Identity` — Ed25519 keypair + canonical agent_id derivation. Save/load to disk.
- `SpizeClient` — thin HTTP wrapper over the control plane. Handles signing + replay nonces.
- `wire` — canonical byte functions that mirror `spize_core::wire` exactly; change only in lockstep.
