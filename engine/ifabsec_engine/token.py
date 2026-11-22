"""Engine-side verification of ifab1 label tokens.

Mirrors gateway/token/token.go. The engine holds only gateway public keys.
See docs/label-token.md for the format and the verification checklist.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import heapq
import threading
import time
from dataclasses import dataclass
from typing import Optional, Callable, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .scope import Scope, ScopeError, narrow, parse_scope

PREFIX = "ifab1"
MAX_LIFETIME = 300
CLOCK_SKEW = 30
MIN_JTI_BYTES = 16


class TokenError(Exception):
    """Base class; the chat endpoint rejects the request (HTTP 400) and logs the reason."""


class FormatError(TokenError):
    pass


class SignatureError(TokenError):
    pass


class ExpiredError(TokenError):
    pass


class AudienceError(TokenError):
    pass


class ReplayError(TokenError):
    pass


class ContentMismatch(TokenError):
    pass


class KeyScopeError(TokenError):
    """The signing key is not allowed to mint scopes for this org."""


def _b64decode(s: str) -> bytes:
    if not isinstance(s, str) or "=" in s:
        raise FormatError("bad base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise FormatError("bad base64url") from e


def segment_digest(messages: Iterable[Mapping[str, str]]) -> str:
    """content_sha256 for a run of chat messages: role 0x00 content 0x00 each."""
    h = hashlib.sha256()
    for m in messages:
        h.update(m["role"].encode())
        h.update(b"\0")
        h.update(m["content"].encode())
        h.update(b"\0")
    return h.hexdigest()


def _is_sha256_hex(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(ch in "0123456789abcdef" for ch in s)


def tools_digest(tools: Iterable[Mapping]) -> str:
    """tools_sha256 for a request's tools list.

    Canonical JSON (sorted keys, no spaces, UTF-8) of each tool reduced to what
    chat templates render: type, and the function's name, description and
    parameters (absent or null fields dropped). The gateway hashes the tools the
    client sent; the engine hashes the tools SGLang parsed. Both must normalize
    the same way.
    """
    norm = []
    for t in tools:
        f = t.get("function") or {}
        norm.append({
            "type": t.get("type") or "function",
            "function": {k: f[k] for k in ("name", "description", "parameters") if f.get(k) is not None},
        })
    blob = json.dumps(norm, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass(frozen=True)
class Segment:
    until_message: int | None
    scope: Scope
    content_sha256: str | None


@dataclass(frozen=True)
class VerifiedToken:
    claims: dict
    segments: tuple[Segment, ...]
    effective: tuple[Scope, ...]  # effective scope of each segment after narrowing

    def message_ranges(self, n_messages: int) -> list[tuple[int, int]]:
        """[start, end) message indices covered by each segment."""
        out, start = [], 0
        for seg in self.segments:
            end = n_messages if seg.until_message is None else seg.until_message
            out.append((start, end))
            start = end
        return out


def _check_claims(c: dict) -> tuple[tuple[Segment, ...], tuple[Scope, ...]]:
    if c.get("v") != 1:
        raise FormatError("version must be 1")
    for f in ("iss", "kid", "sub", "aud"):
        if not isinstance(c.get(f), str) or not c[f]:
            raise FormatError(f"missing {f}")
    iat, exp = c.get("iat"), c.get("exp")
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (iat, exp)):
        raise FormatError("iat and exp must be integers")
    if exp <= iat or exp - iat > MAX_LIFETIME:
        raise FormatError(f"lifetime must be 1..{MAX_LIFETIME} s")
    if len(_b64decode(c.get("jti", ""))) < MIN_JTI_BYTES:
        raise FormatError(f"jti must be >= {MIN_JTI_BYTES} bytes")
    if "tools_sha256" in c and not _is_sha256_hex(c["tools_sha256"]):
        raise FormatError("tools_sha256 must be 64 lowercase hex characters")
    read_raw = c.get("read")
    if not isinstance(read_raw, list):
        raise FormatError("read must be a list")
    try:
        for r in read_raw:
            parse_scope(r)
    except (ScopeError, AttributeError) as e:
        raise FormatError(f"read: {e}") from e
    read = set(read_raw)

    raw_segs = c.get("segments")
    if not isinstance(raw_segs, list) or not raw_segs:
        raise FormatError("no segments")
    segs, eff, last = [], [], 0
    for i, s in enumerate(raw_segs):
        is_last = i == len(raw_segs) - 1
        until = s.get("until_message")
        if is_last and until is not None:
            raise FormatError("last segment must not set until_message")
        if not is_last:
            if not isinstance(until, int) or isinstance(until, bool) or until <= last:
                raise FormatError("until_message must strictly increase from 1")
            last = until
        try:
            scope = parse_scope(s.get("scope"))
        except (ScopeError, AttributeError, TypeError) as e:
            raise FormatError(f"segment {i}: {e}") from e
        if s["scope"] not in read:
            raise FormatError(f"segment {i} scope {scope} not in read set")
        digest = s.get("content_sha256")
        if scope.shared:
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or digest != digest.lower()
                or any(ch not in "0123456789abcdef" for ch in digest)
            ):
                raise FormatError(f"shared segment {i} needs lowercase hex content_sha256")
        try:
            eff.append(scope if i == 0 else narrow(eff[-1], scope))
        except ScopeError as e:
            raise FormatError(f"segment {i}: {e}") from e
        segs.append(Segment(until, scope, digest))
    return tuple(segs), tuple(eff)


class Verifier:
    """Checks tokens for one audience. Thread-safe."""

    def __init__(
        self,
        audience: str,
        keys: Mapping[str, bytes],
        now: Callable[[], float] = time.time,
        key_orgs: Optional[Mapping[str, frozenset]] = None,
    ):
        """key_orgs maps a kid to the orgs it may mint scopes for. A kid absent
        from key_orgs is unrestricted (one gateway serving every org)."""
        self.audience = audience
        self._keys = {kid: Ed25519PublicKey.from_public_bytes(k) for kid, k in keys.items()}
        self._key_orgs = dict(key_orgs or {})
        self._now = now
        self._seen: dict[str, int] = {}
        self._expiry: list[tuple[int, str]] = []  # min-heap of (until, jti)
        self._lock = threading.Lock()

    def verify(self, token: str) -> VerifiedToken:
        """Checks 1-8 of docs/label-token.md."""
        parts = token.split(".") if isinstance(token, str) else []
        if len(parts) != 3 or parts[0] != PREFIX:
            raise FormatError("malformed token")
        payload, sig = _b64decode(parts[1]), _b64decode(parts[2])
        try:
            claims = json.loads(payload)
        except ValueError as e:
            raise FormatError("payload is not JSON") from e
        if not isinstance(claims, dict):
            raise FormatError("payload is not an object")
        key = self._keys.get(claims.get("kid"))
        if key is None:
            raise SignatureError("unknown kid")
        try:
            key.verify(sig, f"{parts[0]}.{parts[1]}".encode())
        except InvalidSignature as e:
            raise SignatureError("bad signature") from e
        if claims.get("aud") != self.audience:
            raise AudienceError("wrong audience")
        segs, eff = _check_claims(claims)
        allowed = self._key_orgs.get(claims["kid"])
        if allowed is not None:
            for r in claims["read"]:
                org = parse_scope(r).org
                if org and org not in allowed:
                    raise KeyScopeError(f"key {claims['kid']} may not mint scopes for org {org}")
        t = int(self._now())
        if claims["iat"] > t + CLOCK_SKEW or t >= claims["exp"] + CLOCK_SKEW:
            raise ExpiredError("token expired or not yet valid")
        self._mark_seen(claims["jti"], claims["exp"] + CLOCK_SKEW, t)
        return VerifiedToken(claims, segs, eff)

    def _mark_seen(self, jti: str, until: int, now: int) -> None:
        with self._lock:
            while self._expiry and self._expiry[0][0] <= now:
                _, old = heapq.heappop(self._expiry)
                if self._seen.get(old, until + 1) <= now:
                    del self._seen[old]
            if jti in self._seen:
                raise ReplayError("token replayed")
            self._seen[jti] = until
            heapq.heappush(self._expiry, (until, jti))


def check_tools(tok: VerifiedToken, tools: Optional[Sequence[Mapping]]) -> bool:
    """Check 11: tools approved by the token. Returns True when the request's
    tools match tools_sha256, so they may be rendered into the shared prefix.
    Returns False when the token approves no tools or the request renders none
    (the tools then fall in the user's scope, or the request is isolated)."""
    want = tok.claims.get("tools_sha256")
    if want is None or not tools:
        return False
    if not hmac.compare_digest(tools_digest(tools), want):
        raise ContentMismatch("tools do not match the token")
    return True


def check_messages(tok: VerifiedToken, messages: Sequence[Mapping[str, str]]) -> None:
    """Check 9: shared-scope segments must contain exactly the approved content."""
    ranges = tok.message_ranges(len(messages))
    if ranges and ranges[-1][0] > len(messages):
        raise ContentMismatch("segments reference messages the request does not have")
    for seg, (start, end) in zip(tok.segments, ranges):
        if seg.scope.shared:
            got = segment_digest(messages[start:end])
            if not hmac.compare_digest(got, seg.content_sha256 or ""):
                raise ContentMismatch(f"segment {seg.scope} content does not match the token")
