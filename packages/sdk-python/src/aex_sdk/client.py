"""Synchronous HTTP client for the Spize control plane."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import json
import httpx

from aex_sdk.endpoint import Endpoint
from aex_sdk.errors import SpizeError, SpizeHTTPError
from aex_sdk.identity import Identity, random_nonce
from aex_sdk.resolver import CloudflareDoHResolver, build_http_client
from aex_sdk.wire import (
    registration_challenge_bytes,
    rotate_key_challenge_bytes,
    transfer_intent_bytes,
    transfer_receipt_bytes,
)


@dataclass
class TransferResponse:
    transfer_id: str
    state: str
    sender_agent_id: str
    recipient: str
    size_bytes: int
    declared_mime: Optional[str]
    filename: Optional[str]
    scanner_verdict: Optional[dict[str, Any]]
    policy_decision: Optional[dict[str, Any]]
    rejection_code: Optional[str]
    rejection_reason: Optional[str]

    @classmethod
    def from_json(cls, body: dict[str, Any]) -> "TransferResponse":
        return cls(
            transfer_id=body["transfer_id"],
            state=body["state"],
            sender_agent_id=body["sender_agent_id"],
            recipient=body["recipient"],
            size_bytes=int(body["size_bytes"]),
            declared_mime=body.get("declared_mime"),
            filename=body.get("filename"),
            scanner_verdict=body.get("scanner_verdict"),
            policy_decision=body.get("policy_decision"),
            rejection_code=body.get("rejection_code"),
            rejection_reason=body.get("rejection_reason"),
        )

    @property
    def was_delivered(self) -> bool:
        return self.state == "delivered"

    @property
    def was_rejected(self) -> bool:
        return self.state == "rejected"


class SpizeClient:
    """Thin wrapper over the control-plane REST API.

    The client is stateless beyond `base_url` + `identity`; each call
    builds a fresh nonce and signs the canonical payload. Reuses an
    httpx.Client for connection pooling.
    """

    def __init__(
        self,
        base_url: str,
        identity: Identity,
        *,
        timeout: float = 30.0,
        resolver: Optional[CloudflareDoHResolver] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.identity = identity
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout)
        # The control-plane client (self._http) talks to base_url which in
        # practice is localhost or a well-known api.spize.io host — DoH is
        # overkill there. The resolver is kept around so operations that
        # reach out to a third-party data-plane tunnel (fetch_from_tunnel,
        # upload_blob_admin) can route through DoH and bypass any local
        # search-domain or NXDOMAIN cache nonsense.
        self._resolver = resolver or CloudflareDoHResolver()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "SpizeClient":
        return self

    def __exit__(self, *exc) -> None:  # noqa: D401 - context manager boilerplate
        self.close()

    # ------------------------------ health ------------------------------

    def health(self) -> dict[str, Any]:
        r = self._http.get("/healthz")
        self._raise_for_status(r)
        return r.json()

    # ---------------------------- registration ---------------------------

    def register(self) -> dict[str, Any]:
        """Register this identity with the control plane (idempotent-safe:
        re-registering the same public key returns 409 Conflict — callers
        can treat that as 'already registered')."""
        issued_at = int(time.time())
        nonce = random_nonce()
        challenge = registration_challenge_bytes(
            self.identity.public_key_hex,
            self.identity.org,
            self.identity.name,
            nonce,
            issued_at,
        )
        signature = self.identity.sign(challenge)
        payload = {
            "public_key_hex": self.identity.public_key_hex,
            "org": self.identity.org,
            "name": self.identity.name,
            "nonce": nonce,
            "issued_at": issued_at,
            "signature_hex": signature.hex(),
        }
        r = self._http.post("/v1/agents/register", json=payload)
        self._raise_for_status(r)
        return r.json()

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        r = self._http.get(f"/v1/agents/{agent_id}")
        self._raise_for_status(r)
        return r.json()

    def rotate_key(self, new_identity: Identity) -> "RotateKeyResponse":
        """Rotate to ``new_identity``, authorised by this client's
        current identity (ADR-0024).

        The caller holds two Identity objects across the rotation
        window: the outgoing one (``self.identity``) that authorises
        the rotation, and the incoming one (``new_identity``) that
        continues to verify for signatures issued after the grace
        period. Both identities MUST share the same ``org`` / ``name``
        — you cannot rename an agent by rotating.
        """
        if new_identity.org != self.identity.org or new_identity.name != self.identity.name:
            raise SpizeError(
                "rotate_key: new identity must share org/name with current identity"
            )
        if new_identity.public_key_hex == self.identity.public_key_hex:
            raise SpizeError("rotate_key: new key is identical to current key")
        issued_at = int(time.time())
        nonce = random_nonce()
        challenge = rotate_key_challenge_bytes(
            self.identity.agent_id,
            self.identity.public_key_hex,
            new_identity.public_key_hex,
            nonce,
            issued_at,
        )
        signature = self.identity.sign(challenge)
        payload = {
            "agent_id": self.identity.agent_id,
            "new_public_key_hex": new_identity.public_key_hex,
            "nonce": nonce,
            "issued_at": issued_at,
            "signature_hex": signature.hex(),
        }
        r = self._http.post("/v1/agents/rotate-key", json=payload)
        self._raise_for_status(r)
        body = r.json()
        return RotateKeyResponse(
            agent_id=body["agent_id"],
            new_public_key_hex=body["new_public_key_hex"],
            valid_from=int(body["valid_from"]),
            previous_key_valid_until=int(body["previous_key_valid_until"]),
        )

    # ------------------------------- send -------------------------------

    def send(
        self,
        recipient: str,
        *,
        data: Optional[bytes] = None,
        file: Optional[str | Path] = None,
        declared_mime: str = "",
        filename: str = "",
    ) -> TransferResponse:
        """Initiate a transfer. Provide exactly one of `data` or `file`."""
        if (data is None) == (file is None):
            raise SpizeError("pass exactly one of data= or file=")
        if file is not None:
            p = Path(file)
            data = p.read_bytes()
            if not filename:
                filename = p.name
        assert data is not None

        issued_at = int(time.time())
        nonce = random_nonce()
        canonical = transfer_intent_bytes(
            self.identity.agent_id,
            recipient,
            len(data),
            declared_mime,
            filename,
            nonce,
            issued_at,
        )
        signature = self.identity.sign(canonical)
        payload = {
            "sender_agent_id": self.identity.agent_id,
            "recipient": recipient,
            "declared_mime": declared_mime,
            "filename": filename,
            "nonce": nonce,
            "issued_at": issued_at,
            "intent_signature_hex": signature.hex(),
            "blob_hex": data.hex(),
        }
        r = self._http.post("/v1/transfers", json=payload)
        self._raise_for_status(r)
        return TransferResponse.from_json(r.json())

    # ----------------------------- receive ------------------------------

    def send_via_tunnel(
        self,
        *,
        recipient: str,
        declared_size: int,
        declared_mime: str,
        filename: str,
        tunnel_url: str,
    ) -> TransferResponse:
        """M2: announce a transfer without uploading bytes. The sender
        must serve the blob via `tunnel_url` (a data-plane URL)."""
        if not self.identity:
            raise ValueError("client has no identity")
        nonce = random_nonce()
        issued_at = int(time.time())
        intent = transfer_intent_bytes(
            sender_agent_id=self.identity.agent_id,
            recipient=recipient,
            size_bytes=declared_size,
            declared_mime=declared_mime,
            filename=filename,
            nonce=nonce,
            issued_at_unix=issued_at,
        )
        sig = self.identity.sign(intent)
        payload = {
            "sender_agent_id": self.identity.agent_id,
            "recipient": recipient,
            "declared_mime": declared_mime,
            "filename": filename,
            "nonce": nonce,
            "issued_at": issued_at,
            "intent_signature_hex": sig.hex(),
            "blob_hex": "",
            "tunnel_url": tunnel_url,
            "declared_size": declared_size,
        }
        r = self._http.post("/v1/transfers", json=payload)
        self._raise_for_status(r)
        return TransferResponse.from_json(r.json())

    def send_via_transports(
        self,
        *,
        recipient: str,
        declared_size: int,
        declared_mime: str,
        filename: str,
        endpoints: list[Endpoint],
    ) -> TransferResponse:
        """Sprint 2 (wire v1.3.0-beta.1): announce a transfer with a
        sender-ranked list of transport endpoints (`reachable_at[]`).

        The control plane probes every endpoint in parallel under a
        50-permit semaphore + 15s budget and requires at-least-1
        healthy. Unhealthy endpoints are dropped from the stored list
        so the recipient never sees a known-dead address.

        This is the forward path; :meth:`send_via_tunnel` is kept for
        single-URL senders during the dual-wire grace period.
        """
        if not self.identity:
            raise ValueError("client has no identity")
        if not endpoints:
            raise SpizeError("endpoints[] must not be empty")
        nonce = random_nonce()
        issued_at = int(time.time())
        intent = transfer_intent_bytes(
            sender_agent_id=self.identity.agent_id,
            recipient=recipient,
            size_bytes=declared_size,
            declared_mime=declared_mime,
            filename=filename,
            nonce=nonce,
            issued_at_unix=issued_at,
        )
        sig = self.identity.sign(intent)
        payload = {
            "sender_agent_id": self.identity.agent_id,
            "recipient": recipient,
            "declared_mime": declared_mime,
            "filename": filename,
            "nonce": nonce,
            "issued_at": issued_at,
            "intent_signature_hex": sig.hex(),
            "blob_hex": "",
            "reachable_at": [e.to_json() for e in endpoints],
            "declared_size": declared_size,
        }
        r = self._http.post("/v1/transfers", json=payload)
        self._raise_for_status(r)
        return TransferResponse.from_json(r.json())

    def get_transfer(self, transfer_id: str) -> TransferResponse:
        r = self._http.get(f"/v1/transfers/{transfer_id}")
        self._raise_for_status(r)
        return TransferResponse.from_json(r.json())

    def download(self, transfer_id: str) -> bytes:
        """Download the blob bytes. Must be called by the declared
        recipient (signature bound to the recipient's identity)."""
        body = self._build_receipt(transfer_id, "download")
        r = self._http.post(f"/v1/transfers/{transfer_id}/download", json=body)
        self._raise_for_status(r)
        return bytes.fromhex(r.json()["blob_hex"])

    def ack(self, transfer_id: str) -> dict[str, Any]:
        """Acknowledge delivery. The returned `audit_chain_head` is proof
        the delivery was logged at this chain position."""
        body = self._build_receipt(transfer_id, "ack")
        r = self._http.post(f"/v1/transfers/{transfer_id}/ack", json=body)
        self._raise_for_status(r)
        return r.json()

    def request_ticket(self, transfer_id: str) -> "DataPlaneTicket":
        """M2: request a signed data-plane ticket to fetch the blob directly
        from the sender's tunnel, bypassing the control plane for payload.
        Requires the transfer to be in ``ready_for_pickup`` with a tunnel_url.
        """
        receipt = self._build_receipt(transfer_id, "request_ticket")
        r = self._http.post(
            f"/v1/transfers/{transfer_id}/ticket",
            json=receipt,
        )
        self._raise_for_status(r)
        body = r.json()
        return DataPlaneTicket(
            transfer_id=body["transfer_id"],
            recipient=body["recipient"],
            data_plane_url=body["data_plane_url"],
            expires=int(body["expires"]),
            nonce=body["nonce"],
            signature=body["signature"],
        )

    def fetch_from_tunnel(self, ticket: "DataPlaneTicket") -> bytes:
        """M2: fetch blob bytes from the sender's data plane using a ticket.

        Routes DNS through Cloudflare DoH so a freshly-created
        ``*.trycloudflare.com`` hostname resolves correctly even on a wifi
        network with a search-domain suffix (the exact failure mode Sprint 1
        hit repeatedly).
        """
        with build_http_client(resolver=self._resolver, timeout=30.0) as client:
            r = client.get(
                f"{ticket.data_plane_url}/blob/{ticket.transfer_id}",
                headers={"X-AEX-Ticket": ticket.as_header()},
            )
            self._raise_for_status(r)
            return r.content

    def upload_blob_admin(
        self,
        *,
        data_plane_url: str,
        transfer_id: str,
        admin_token: str,
        payload: bytes,
        mime: str = "application/octet-stream",
        filename: str = "blob",
    ) -> None:
        """Upload ``payload`` to a data plane's admin endpoint.

        This wraps the ``POST /admin/blob/:transfer_id`` route that
        ``aex-data-plane`` exposes when an admin token is set. Used by
        orchestrated M2 scenarios (the canonical demo, the desktop app)
        where the sender's data plane is launched with an ephemeral token
        and accepts blobs for pre-declared transfer IDs.

        Routes DNS through the DoH resolver for the same reason as
        :meth:`fetch_from_tunnel`.
        """
        url = f"{data_plane_url.rstrip('/')}/admin/blob/{transfer_id}"
        with build_http_client(resolver=self._resolver, timeout=60.0) as client:
            r = client.post(
                url,
                content=payload,
                params={"mime": mime, "filename": filename},
                headers={
                    "x-aex-admin-token": admin_token,
                    "content-type": "application/octet-stream",
                },
            )
            if r.status_code != 201:
                raise SpizeError(
                    f"admin upload rejected: status={r.status_code} body={r.text[:300]!r}"
                )

    def inbox(self) -> dict[str, Any]:
        """List transfers waiting for this identity (state:
        `ready_for_pickup` or `accepted`). Capped at 100 most recent rows."""
        body = self._build_receipt("inbox", "inbox")
        r = self._http.post("/v1/inbox", json=body)
        self._raise_for_status(r)
        return r.json()

    def _build_receipt(self, transfer_id: str, action: str) -> dict[str, Any]:
        issued_at = int(time.time())
        nonce = random_nonce()
        canonical = transfer_receipt_bytes(
            self.identity.agent_id, transfer_id, action, nonce, issued_at
        )
        signature = self.identity.sign(canonical)
        return {
            "recipient_agent_id": self.identity.agent_id,
            "nonce": nonce,
            "issued_at": issued_at,
            "signature_hex": signature.hex(),
        }

    # ------------------------------ helpers ------------------------------

    @staticmethod
    def _raise_for_status(r: httpx.Response) -> None:
        if r.is_success:
            return
        try:
            body = r.json()
        except Exception:
            body = {}
        raise SpizeHTTPError(
            status_code=r.status_code,
            code=body.get("code"),
            message=body.get("message") or r.text or "unknown error",
            runbook_url=body.get("runbook_url"),
        )


# ---------- M2 additions ----------

@dataclass(frozen=True)
class RotateKeyResponse:
    """Response body returned by ``POST /v1/agents/rotate-key``."""

    agent_id: str
    new_public_key_hex: str
    valid_from: int
    previous_key_valid_until: int


@dataclass(frozen=True)
class DataPlaneTicket:
    transfer_id: str
    recipient: str
    data_plane_url: str
    expires: int
    nonce: str
    signature: str

    def as_header(self) -> str:
        """JSON-encoded ticket for the `X-AEX-Ticket` header."""
        return json.dumps(
            {
                "transfer_id": self.transfer_id,
                "recipient": self.recipient,
                "data_plane_url": self.data_plane_url,
                "expires": self.expires,
                "nonce": self.nonce,
                "signature": self.signature,
            },
            separators=(",", ":"),
        )
