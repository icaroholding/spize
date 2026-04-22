"""Unit tests for ``SpizeClient.rotate_key`` and the canonical
``rotate_key_challenge_bytes`` helper.

Uses httpx's ``MockTransport`` so we don't need a live control plane —
the server half is replaced with an assertion over the signed payload.
"""

from __future__ import annotations

import time

import httpx
import pytest

from aex_sdk import Identity, RotateKeyResponse, SpizeClient, SpizeError
from aex_sdk.identity import verify_signature
from aex_sdk.wire import rotate_key_challenge_bytes


def _make_client(identity: Identity, handler) -> SpizeClient:
    """Build a client whose outgoing requests go to ``handler`` instead
    of a real server. The handler sees each ``httpx.Request`` and
    returns an ``httpx.Response``."""
    transport = httpx.MockTransport(handler)
    client = SpizeClient("http://test", identity)
    client._http.close()
    client._http = httpx.Client(base_url="http://test", transport=transport)
    return client


def test_rotate_key_posts_signed_challenge() -> None:
    alice_old = Identity.generate(org="acme", name="alice")
    alice_new = Identity.from_secret(
        org="acme",
        name="alice",
        private_key_bytes=bytes(range(32)),
    )

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/agents/rotate-key"
        import json

        body = json.loads(request.content.decode("utf-8"))
        captured.update(body)

        # Re-derive canonical bytes and verify the signature that the
        # client included was made with the OLD key over exactly those
        # bytes. This is the same validation the real control plane
        # would do.
        canonical = rotate_key_challenge_bytes(
            agent_id=body["agent_id"],
            old_public_key_hex=alice_old.public_key_hex,
            new_public_key_hex=body["new_public_key_hex"],
            nonce=body["nonce"],
            issued_at_unix=body["issued_at"],
        )
        sig = bytes.fromhex(body["signature_hex"])
        assert verify_signature(alice_old.public_key_bytes, canonical, sig)

        now = int(time.time())
        return httpx.Response(
            200,
            json={
                "agent_id": body["agent_id"],
                "new_public_key_hex": body["new_public_key_hex"],
                "valid_from": now,
                "previous_key_valid_until": now + 24 * 60 * 60,
            },
        )

    client = _make_client(alice_old, handler)
    try:
        resp = client.rotate_key(alice_new)
    finally:
        client.close()

    assert isinstance(resp, RotateKeyResponse)
    assert resp.new_public_key_hex == alice_new.public_key_hex
    assert resp.previous_key_valid_until - resp.valid_from == 24 * 60 * 60
    assert captured["agent_id"] == alice_old.agent_id
    assert captured["new_public_key_hex"] == alice_new.public_key_hex


def test_rotate_key_refuses_cross_agent_rotation() -> None:
    alice = Identity.generate(org="acme", name="alice")
    not_alice = Identity.generate(org="acme", name="mallory")

    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("client must refuse before reaching the network")

    client = _make_client(alice, handler)
    try:
        with pytest.raises(SpizeError):
            client.rotate_key(not_alice)
    finally:
        client.close()


def test_rotate_key_refuses_identical_new_key() -> None:
    alice = Identity.generate(org="acme", name="alice")

    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("client must refuse before reaching the network")

    client = _make_client(alice, handler)
    try:
        with pytest.raises(SpizeError):
            client.rotate_key(alice)
    finally:
        client.close()
