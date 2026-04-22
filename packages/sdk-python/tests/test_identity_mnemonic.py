"""BIP-39 mnemonic recovery for Identity (Sprint 4 PR 3).

Generate → persist phrase → lose identity file → reconstruct from
phrase → assert same public key. Also cover the invalid-phrase
failure modes so a typo'd or outright wrong phrase doesn't silently
produce a different identity.
"""

from __future__ import annotations

import pytest

from aex_sdk import Identity
from aex_sdk.errors import IdentityError


def test_generate_with_mnemonic_produces_12_word_phrase() -> None:
    identity, phrase = Identity.generate_with_mnemonic(org="acme", name="alice")
    words = phrase.split()
    assert len(words) == 12, f"expected 12 words, got {len(words)}: {phrase}"
    # Every word is lowercase ASCII — the BIP-39 English wordlist is
    # all-lowercase, and our generator doesn't post-process case.
    for w in words:
        assert w.islower(), f"word {w!r} is not lowercase"
        assert w.isascii(), f"word {w!r} is non-ASCII"

    # Identity is well-formed.
    assert identity.org == "acme"
    assert identity.name == "alice"
    assert len(identity.private_key_bytes) == 32
    assert len(identity.public_key_bytes) == 32
    assert identity.agent_id.startswith("spize:acme/alice:")


def test_mnemonic_roundtrip_recovers_same_identity() -> None:
    identity_a, phrase = Identity.generate_with_mnemonic(org="acme", name="alice")
    identity_b = Identity.from_mnemonic(org="acme", name="alice", phrase=phrase)

    # Most important: same public key → same agent_id. The 3-byte
    # fingerprint is derived from the public key, so equality on
    # public_key_bytes cascades.
    assert identity_a.public_key_bytes == identity_b.public_key_bytes
    assert identity_a.private_key_bytes == identity_b.private_key_bytes
    assert identity_a.agent_id == identity_b.agent_id


def test_mnemonic_tolerates_whitespace_and_case() -> None:
    identity, phrase = Identity.generate_with_mnemonic(org="acme", name="alice")
    # Upper-case + double spaces + leading/trailing whitespace — the
    # recovery method normalises before hashing.
    messy = "   " + phrase.upper().replace(" ", "   ") + "   "
    recovered = Identity.from_mnemonic(org="acme", name="alice", phrase=messy)
    assert recovered.public_key_bytes == identity.public_key_bytes


def test_mnemonic_rejects_wrong_word_count() -> None:
    # 11 words — below the 12-word floor for 128-bit entropy.
    bad = "abandon " * 11
    with pytest.raises(IdentityError, match="invalid BIP-39"):
        Identity.from_mnemonic(org="acme", name="alice", phrase=bad.strip())


def test_mnemonic_rejects_bad_checksum() -> None:
    # 12 identical words fail the BIP-39 checksum byte.
    bad = "abandon " * 12
    with pytest.raises(IdentityError, match="invalid BIP-39"):
        Identity.from_mnemonic(org="acme", name="alice", phrase=bad.strip())


def test_mnemonic_rejects_non_dictionary_word() -> None:
    identity, phrase = Identity.generate_with_mnemonic(org="acme", name="alice")
    words = phrase.split()
    # Swap one word for a non-dictionary string. The validator
    # catches it on the word-list lookup, before even hitting the
    # checksum.
    words[0] = "notabip39word"
    bad = " ".join(words)
    with pytest.raises(IdentityError, match="invalid BIP-39"):
        Identity.from_mnemonic(org="acme", name="alice", phrase=bad)


def test_two_different_generations_produce_different_identities() -> None:
    a, _ = Identity.generate_with_mnemonic(org="acme", name="alice")
    b, _ = Identity.generate_with_mnemonic(org="acme", name="alice")
    # Astronomically unlikely to collide, but the test locks in the
    # invariant that the generator DOES use fresh entropy each call.
    assert a.public_key_bytes != b.public_key_bytes


def test_known_vector_reproduces() -> None:
    # BIP-39 test vector from the spec (see
    # https://github.com/trezor/python-mnemonic/blob/master/vectors.json).
    # Proves our PBKDF2 iteration count + salt match the standard.
    phrase = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    identity = Identity.from_mnemonic(org="acme", name="alice", phrase=phrase)
    # We only derive the first 32 bytes of the 64-byte BIP-39 seed.
    # The canonical test-vector seed for "abandon … about" with
    # empty passphrase is (from the spec):
    #   5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1
    #   9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
    # First 32 bytes: 5eb00bbd...ccb85e70811aaed6f6da5fc1
    expected_prefix = bytes.fromhex(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    )
    assert identity.private_key_bytes == expected_prefix
