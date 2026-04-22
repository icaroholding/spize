"""Canonical wire-format functions.

These MUST produce byte-for-byte identical output to the corresponding
Rust functions in ``aex_core::wire``. The test suite in
``tests/test_wire.py`` checks this against the golden vectors exported
from the Rust tests — DO NOT modify without updating both sides
together.
"""

from __future__ import annotations

PROTOCOL_VERSION = "v1"
MAX_CLOCK_SKEW_SECS = 300
MIN_NONCE_LEN = 32
MAX_NONCE_LEN = 128


def _validate_ascii_line(s: str, field: str, *, allow_empty: bool = False) -> None:
    if not s:
        if allow_empty:
            return
        raise ValueError(f"{field} is empty")
    for i, c in enumerate(s):
        if ord(c) > 127 or c in ("\n", "\r", "\0"):
            raise ValueError(f"{field} has invalid char at {i}: {c!r}")


def _validate_nonce(nonce: str) -> None:
    if not (MIN_NONCE_LEN <= len(nonce) <= MAX_NONCE_LEN):
        raise ValueError(
            f"nonce length {len(nonce)} outside [{MIN_NONCE_LEN}, {MAX_NONCE_LEN}]"
        )
    if not all(c in "0123456789abcdefABCDEF" for c in nonce):
        raise ValueError("nonce must be hex")


def registration_challenge_bytes(
    public_key_hex: str,
    org: str,
    name: str,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    _validate_ascii_line(public_key_hex, "public_key_hex")
    _validate_ascii_line(org, "org")
    _validate_ascii_line(name, "name")
    _validate_nonce(nonce)
    return (
        f"spize-register:{PROTOCOL_VERSION}\n"
        f"pub={public_key_hex}\n"
        f"org={org}\n"
        f"name={name}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")


def transfer_intent_bytes(
    sender_agent_id: str,
    recipient: str,
    size_bytes: int,
    declared_mime: str,
    filename: str,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    _validate_ascii_line(sender_agent_id, "sender_agent_id")
    _validate_ascii_line(recipient, "recipient")
    _validate_ascii_line(declared_mime, "declared_mime", allow_empty=True)
    _validate_ascii_line(filename, "filename", allow_empty=True)
    _validate_nonce(nonce)
    return (
        f"spize-transfer-intent:{PROTOCOL_VERSION}\n"
        f"sender={sender_agent_id}\n"
        f"recipient={recipient}\n"
        f"size={size_bytes}\n"
        f"mime={declared_mime}\n"
        f"filename={filename}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")


def rotate_key_challenge_bytes(
    agent_id: str,
    old_public_key_hex: str,
    new_public_key_hex: str,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    """Canonical bytes signed by the OUTGOING key when rotating.

    Mirrors ``aex_core::wire::rotate_key_challenge_bytes``. See
    ADR-0024 for the rotation protocol.
    """
    _validate_ascii_line(agent_id, "agent_id")
    _validate_ascii_line(old_public_key_hex, "old_public_key_hex")
    _validate_ascii_line(new_public_key_hex, "new_public_key_hex")
    _validate_nonce(nonce)
    if old_public_key_hex == new_public_key_hex:
        raise ValueError("old_public_key_hex and new_public_key_hex must differ")
    return (
        f"spize-rotate-key:{PROTOCOL_VERSION}\n"
        f"agent={agent_id}\n"
        f"old_pub={old_public_key_hex}\n"
        f"new_pub={new_public_key_hex}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")


def transfer_receipt_bytes(
    recipient_agent_id: str,
    transfer_id: str,
    action: str,
    nonce: str,
    issued_at_unix: int,
) -> bytes:
    _validate_ascii_line(recipient_agent_id, "recipient_agent_id")
    _validate_ascii_line(transfer_id, "transfer_id")
    _validate_ascii_line(action, "action")
    _validate_nonce(nonce)
    if action not in ("download", "ack", "inbox", "request_ticket"):
        raise ValueError(
            f"action must be 'download', 'ack', 'inbox' or 'request_ticket', got {action}"
        )
    return (
        f"spize-transfer-receipt:{PROTOCOL_VERSION}\n"
        f"recipient={recipient_agent_id}\n"
        f"transfer={transfer_id}\n"
        f"action={action}\n"
        f"nonce={nonce}\n"
        f"ts={issued_at_unix}"
    ).encode("ascii")
