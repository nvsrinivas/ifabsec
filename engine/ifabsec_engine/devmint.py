"""Development-only token minting, for tests and pod checks.

Production tokens come from the Go gateway (gateway/cmd/ifabsec-mint).
Keep the seed out of git: it is the gateway's signing key.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .token import segment_digest


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def public_key(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def mint(seed: bytes, claims: dict) -> str:
    signed = "ifab1." + _b64(json.dumps(claims, separators=(",", ":")).encode())
    return signed + "." + _b64(Ed25519PrivateKey.from_private_bytes(seed).sign(signed.encode()))


def chat_token(
    seed: bytes,
    *,
    kid: str,
    aud: str,
    user: str,
    org: str,
    shared_messages: Sequence[dict],
    now: Optional[int] = None,
) -> str:
    """Token for the common shape: the first len(shared_messages) messages are
    the org's approved prompt, everything after belongs to the user."""
    now = int(time.time()) if now is None else now
    segments = [{"scope": f"user:{user}"}]
    if shared_messages:
        segments.insert(0, {
            "until_message": len(shared_messages),
            "scope": f"org:{org}",
            "content_sha256": segment_digest(shared_messages),
        })
    return mint(seed, {
        "v": 1, "iss": "dev", "kid": kid, "sub": f"user:{user}", "aud": aud,
        "iat": now, "exp": now + 60, "jti": _b64(os.urandom(16)),
        "read": [f"org:{org}", f"user:{user}"], "segments": segments,
    })
