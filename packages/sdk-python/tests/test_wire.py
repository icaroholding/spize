"""Canonical wire bytes must be byte-identical to the Rust side.

The expected byte strings here are the same golden vectors used in
`crates/spize-core/src/wire.rs` tests. If you modify either side, update
both in the same commit.
"""

from __future__ import annotations

import pytest

from aex_sdk import wire


def test_registration_challenge_stable_bytes() -> None:
    bytes_ = wire.registration_challenge_bytes(
        public_key_hex="aabbcc",
        org="acme",
        name="alice",
        nonce="0123456789abcdef0123456789abcdef",
        issued_at_unix=1_700_000_000,
    )
    expected = (
        b"spize-register:v1\n"
        b"pub=aabbcc\n"
        b"org=acme\n"
        b"name=alice\n"
        b"nonce=0123456789abcdef0123456789abcdef\n"
        b"ts=1700000000"
    )
    assert bytes_ == expected


def test_transfer_intent_stable_bytes() -> None:
    bytes_ = wire.transfer_intent_bytes(
        sender_agent_id="spize:acme/alice:aabbcc",
        recipient="spize:acme/bob:ddeeff",
        size_bytes=12345,
        declared_mime="application/pdf",
        filename="invoice.pdf",
        nonce="0123456789abcdef0123456789abcdef",
        issued_at_unix=1_700_000_000,
    )
    expected = (
        b"spize-transfer-intent:v1\n"
        b"sender=spize:acme/alice:aabbcc\n"
        b"recipient=spize:acme/bob:ddeeff\n"
        b"size=12345\n"
        b"mime=application/pdf\n"
        b"filename=invoice.pdf\n"
        b"nonce=0123456789abcdef0123456789abcdef\n"
        b"ts=1700000000"
    )
    assert bytes_ == expected


def test_transfer_intent_empty_optionals() -> None:
    bytes_ = wire.transfer_intent_bytes(
        sender_agent_id="spize:acme/alice:aabbcc",
        recipient="bob@example.com",
        size_bytes=100,
        declared_mime="",
        filename="",
        nonce="0123456789abcdef0123456789abcdef",
        issued_at_unix=1_700_000_000,
    )
    s = bytes_.decode()
    assert "mime=\n" in s
    assert "filename=\n" in s


def test_transfer_receipt_stable_bytes() -> None:
    bytes_ = wire.transfer_receipt_bytes(
        recipient_agent_id="spize:acme/bob:ddeeff",
        transfer_id="tx_abc123",
        action="ack",
        nonce="0123456789abcdef0123456789abcdef",
        issued_at_unix=1_700_000_000,
    )
    expected = (
        b"spize-transfer-receipt:v1\n"
        b"recipient=spize:acme/bob:ddeeff\n"
        b"transfer=tx_abc123\n"
        b"action=ack\n"
        b"nonce=0123456789abcdef0123456789abcdef\n"
        b"ts=1700000000"
    )
    assert bytes_ == expected


def test_invalid_action_rejected() -> None:
    with pytest.raises(ValueError):
        wire.transfer_receipt_bytes(
            "spize:acme/bob:ddeeff", "tx_abc", "overwrite",
            "0123456789abcdef0123456789abcdef", 1,
        )


def test_rotate_key_stable_bytes() -> None:
    bytes_ = wire.rotate_key_challenge_bytes(
        agent_id="spize:acme/alice:aabbcc",
        old_public_key_hex="1111111111111111111111111111111111111111111111111111111111111111",
        new_public_key_hex="2222222222222222222222222222222222222222222222222222222222222222",
        nonce="0123456789abcdef0123456789abcdef",
        issued_at_unix=1_700_000_000,
    )
    expected = (
        b"spize-rotate-key:v1\n"
        b"agent=spize:acme/alice:aabbcc\n"
        b"old_pub=1111111111111111111111111111111111111111111111111111111111111111\n"
        b"new_pub=2222222222222222222222222222222222222222222222222222222222222222\n"
        b"nonce=0123456789abcdef0123456789abcdef\n"
        b"ts=1700000000"
    )
    assert bytes_ == expected


def test_rotate_key_same_old_and_new_rejected() -> None:
    with pytest.raises(ValueError):
        wire.rotate_key_challenge_bytes(
            agent_id="spize:acme/alice:aabbcc",
            old_public_key_hex="1111111111111111111111111111111111111111111111111111111111111111",
            new_public_key_hex="1111111111111111111111111111111111111111111111111111111111111111",
            nonce="0123456789abcdef0123456789abcdef",
            issued_at_unix=1_700_000_000,
        )


def test_short_nonce_rejected() -> None:
    with pytest.raises(ValueError):
        wire.registration_challenge_bytes(
            "aa", "acme", "alice", "deadbeef", 100,
        )


def test_newline_in_field_rejected() -> None:
    with pytest.raises(ValueError):
        wire.registration_challenge_bytes(
            "aa", "ac\nme", "alice",
            "0123456789abcdef0123456789abcdef", 100,
        )
