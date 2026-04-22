"""Agent Exchange Protocol (AEX) — Python SDK."""

from aex_sdk.captive import NetworkState, detect_network_state
from aex_sdk.client import (
    DataPlaneTicket,
    RotateKeyResponse,
    SpizeClient,
    TransferResponse,
)
from aex_sdk.endpoint import (
    HTTP_KINDS,
    KIND_CLOUDFLARE_NAMED,
    KIND_CLOUDFLARE_QUICK,
    KIND_FRP,
    KIND_IROH,
    KIND_TAILSCALE_FUNNEL,
    KNOWN_KINDS,
    Endpoint,
    FallbackAttempt,
    FallbackResult,
    sort_by_priority,
    try_endpoints,
)
from aex_sdk.errors import SpizeError, SpizeHTTPError
from aex_sdk.identity import Identity
from aex_sdk.resolver import CloudflareDoHResolver, DoHTransport, build_http_client
from aex_sdk.retry import RetryPolicy, retry_with_backoff

__all__ = [
    "CloudflareDoHResolver",
    "DataPlaneTicket",
    "DoHTransport",
    "Endpoint",
    "FallbackAttempt",
    "FallbackResult",
    "HTTP_KINDS",
    "Identity",
    "KIND_CLOUDFLARE_NAMED",
    "KIND_CLOUDFLARE_QUICK",
    "KIND_FRP",
    "KIND_IROH",
    "KIND_TAILSCALE_FUNNEL",
    "KNOWN_KINDS",
    "NetworkState",
    "RetryPolicy",
    "RotateKeyResponse",
    "SpizeClient",
    "SpizeError",
    "SpizeHTTPError",
    "TransferResponse",
    "build_http_client",
    "detect_network_state",
    "retry_with_backoff",
    "sort_by_priority",
    "try_endpoints",
]

__version__ = "1.2.0a3"
