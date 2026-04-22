"""Spize-native Ed25519 identity."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from mnemonic import Mnemonic

from aex_sdk.errors import IdentityError

_LABEL_ALPHABET = set(string.ascii_letters + string.digits + "-_")
_LABEL_MAX = 64


def _validate_label(s: str, field: str) -> None:
    if not s:
        raise IdentityError(f"{field} is empty")
    if len(s) > _LABEL_MAX:
        raise IdentityError(f"{field} exceeds {_LABEL_MAX} chars")
    for c in s:
        if c not in _LABEL_ALPHABET:
            raise IdentityError(
                f"{field} must match [a-zA-Z0-9_-]+, got {c!r}"
            )


def _compute_fingerprint(public_key_bytes: bytes) -> str:
    """First 3 bytes of SHA-256 over the public key, hex-encoded."""
    return hashlib.sha256(public_key_bytes).digest()[:3].hex()


@dataclass(frozen=True)
class Identity:
    """Ed25519 keypair + canonical Spize agent_id."""

    org: str
    name: str
    private_key_bytes: bytes  # 32 bytes
    public_key_bytes: bytes  # 32 bytes

    @classmethod
    def generate(cls, org: str, name: str) -> "Identity":
        _validate_label(org, "org")
        _validate_label(name, "name")
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(org=org, name=name, private_key_bytes=private_bytes, public_key_bytes=public_bytes)

    @classmethod
    def from_secret(cls, org: str, name: str, private_key_bytes: bytes) -> "Identity":
        _validate_label(org, "org")
        _validate_label(name, "name")
        if len(private_key_bytes) != 32:
            raise IdentityError(f"Ed25519 secret must be 32 bytes, got {len(private_key_bytes)}")
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(org=org, name=name, private_key_bytes=private_key_bytes, public_key_bytes=public_bytes)

    @classmethod
    def generate_with_mnemonic(cls, org: str, name: str) -> "tuple[Identity, str]":
        """Generate a fresh identity along with a 12-word BIP-39
        recovery phrase (Sprint 4 Delight).

        The caller is responsible for persisting the phrase somewhere
        the user can recover it — typically they write it down on
        paper the first time the Spize Desktop app starts. Losing
        both the identity file AND the phrase means losing the
        ``spize:org/name:fingerprint`` permanently; there is no
        server-side backup.

        Derivation path:

        - Pick 128 bits of CSPRNG entropy.
        - Encode as a 12-word BIP-39 phrase over the 2048-word
          English word list.
        - Derive a 64-byte seed via PBKDF2-HMAC-SHA512 (2048 rounds,
          empty passphrase) per BIP-39 §2.
        - Take the first 32 bytes as the Ed25519 secret.

        Returns a ``(Identity, phrase)`` tuple.
        """
        _validate_label(org, "org")
        _validate_label(name, "name")
        mnemo = Mnemonic("english")
        phrase = mnemo.generate(strength=128)
        seed = mnemo.to_seed(phrase, passphrase="")
        identity = cls.from_secret(org, name, seed[:32])
        return identity, phrase

    @classmethod
    def from_mnemonic(cls, org: str, name: str, phrase: str) -> "Identity":
        """Reconstruct an identity from the 12-word BIP-39 recovery
        phrase emitted by :meth:`generate_with_mnemonic`.

        The phrase is validated (word count, checksum) before any
        key material is derived. Any failure raises :class:`
        IdentityError` — never a silent fallback. If a user typos
        one word, the checksum catches it; if the whole phrase is
        garbage, the validator catches it.
        """
        _validate_label(org, "org")
        _validate_label(name, "name")
        mnemo = Mnemonic("english")
        normalised = " ".join(phrase.lower().split())
        if not mnemo.check(normalised):
            raise IdentityError(
                "invalid BIP-39 recovery phrase — check word list, spacing, "
                "and that every word is in the English BIP-39 dictionary"
            )
        seed = mnemo.to_seed(normalised, passphrase="")
        return cls.from_secret(org, name, seed[:32])

    # ---------- derived properties ----------

    @property
    def fingerprint(self) -> str:
        return _compute_fingerprint(self.public_key_bytes)

    @property
    def agent_id(self) -> str:
        return f"spize:{self.org}/{self.name}:{self.fingerprint}"

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    # ---------- signing ----------

    def sign(self, message: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(self.private_key_bytes).sign(message)

    # ---------- persistence ----------

    def save(self, path: str | os.PathLike, *, overwrite: bool = False) -> None:
        """Persist the identity to a JSON file with 0600 perms.

        Write pattern: write to a sibling tmp file → fsync → rename. This
        guarantees the final path either contains the full, valid JSON or
        nothing at all — a crash during save cannot leave a truncated key
        file that re-opens as corrupt.
        """
        p = Path(path)
        if p.exists() and not overwrite:
            raise IdentityError(f"{p} already exists; pass overwrite=True to replace")
        payload = {
            "version": 1,
            "org": self.org,
            "name": self.name,
            "private_key_hex": self.private_key_bytes.hex(),
            "public_key_hex": self.public_key_bytes.hex(),
            "agent_id": self.agent_id,
        }
        data = json.dumps(payload, indent=2).encode("utf-8")

        tmp = p.with_name(p.name + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
        except Exception:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path: str | os.PathLike) -> "Identity":
        p = Path(path)
        with open(p, "rb") as f:
            payload = json.loads(f.read().decode("utf-8"))
        if payload.get("version") != 1:
            raise IdentityError(f"unsupported identity file version: {payload.get('version')}")
        try:
            org = payload["org"]
            name = payload["name"]
            private_key_hex = payload["private_key_hex"]
        except KeyError as e:
            raise IdentityError(f"missing field in identity file: {e.args[0]}") from e

        identity = cls.from_secret(org, name, bytes.fromhex(private_key_hex))
        # Sanity: stored public/agent_id should match derived values.
        if "public_key_hex" in payload and payload["public_key_hex"] != identity.public_key_hex:
            raise IdentityError("stored public_key_hex does not match derived public key")
        if "agent_id" in payload and payload["agent_id"] != identity.agent_id:
            raise IdentityError("stored agent_id does not match derived agent_id")
        return identity


def random_nonce(byte_length: int = 16) -> str:
    """Hex nonce with `byte_length` bytes of entropy."""
    return secrets.token_hex(byte_length)


def verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature; returns True/False without raising."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
        return True
    except Exception:
        return False
