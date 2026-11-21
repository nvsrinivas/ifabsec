"""Glue between ifabsec and SGLang. Kept free of SGLang and torch imports so it
can be tested without a GPU; the SGLang patch calls into it through a small
hook module.

Two sides, which run in different SGLang processes:

* **Ingress** (HTTP/tokenizer process): verify the label token, check approved
  content, find where each segment's tokens end, and encode the result as a
  MAC'd internal cache salt that travels with the request.
* **Keys** (scheduler process): turn a request's token ids into cache-key ids
  that carry their scope, so the radix tree matches on (scope, token).

Packing: key id = (scope_id << 20) | token_id. Token ids must be < 2**20
(about 1M; current vocabularies are about 256K). scope_id is 43 bits of
SHA-256 of the scope string, so every SGLang process derives the same id
without coordination. A collision between two different scopes is detected
and the request falls back to full isolation.

Every failure path fails closed: the request is isolated (no sharing), never
widened.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import threading
from array import array
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence

from .scope import ScopeError, parse_scope
from .token import ContentMismatch, TokenError, Verifier, check_messages

log = logging.getLogger("ifabsec")

SALT_PREFIX = "ifab1:"
LABELED_NAMESPACE = "ifab1"  # RadixKey.cache_salt for every labeled request
ISOLATE_PREFIX = "ifab-iso:"  # per-request namespace when we fail closed
TOKEN_BITS = 20
SCOPE_BITS = 43
_MAC_CONTEXT = b"ifab-salt-v1\0"


# ---------------------------------------------------------------- config


@dataclass(frozen=True)
class Config:
    enforce: bool
    audience: str = ""
    gateway_keys: Mapping[str, bytes] = None  # kid -> Ed25519 public key
    internal_key: bytes = b""  # shared by ingress and scheduler processes

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Config":
        mode = env.get("IFAB_MODE", "off")
        if mode == "off":
            return cls(enforce=False)
        if mode != "enforce":
            raise ValueError(f"IFAB_MODE must be 'off' or 'enforce', got {mode!r}")
        keys = {}
        for item in filter(None, env.get("IFAB_GATEWAY_KEYS", "").split(",")):
            kid, _, hexkey = item.partition(":")
            keys[kid.strip()] = bytes.fromhex(hexkey.strip())
        internal = bytes.fromhex(env.get("IFAB_INTERNAL_KEY", ""))
        audience = env.get("IFAB_AUDIENCE", "")
        if not keys or not audience or len(internal) < 32:
            raise ValueError(
                "IFAB_MODE=enforce needs IFAB_AUDIENCE, IFAB_GATEWAY_KEYS (kid:hex,...) "
                "and IFAB_INTERNAL_KEY (>= 32 bytes hex)"
            )
        return cls(True, audience, keys, internal)


_config: Optional[Config] = None
_verifier: Optional[Verifier] = None
_lock = threading.Lock()


def config() -> Config:
    global _config
    if _config is None:
        with _lock:
            if _config is None:
                _config = Config.from_env()
    return _config


def verifier() -> Verifier:
    global _verifier
    if _verifier is None:
        cfg = config()
        with _lock:
            if _verifier is None:
                _verifier = Verifier(cfg.audience, cfg.gateway_keys)
    return _verifier


def _reset_for_tests(cfg: Optional[Config] = None, ver: Optional[Verifier] = None) -> None:
    global _config, _verifier
    _config, _verifier = cfg, ver
    _runs_memo.clear()
    _scope_ids.clear()


# ---------------------------------------------------------------- ingress


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _ids_digest(ids: Sequence[int]) -> bytes:
    return hashlib.sha256(array("q", ids).tobytes()).digest()


def _mac(key: bytes, payload: bytes, ids: Sequence[int]) -> bytes:
    return hmac.new(key, _MAC_CONTEXT + payload + b"\0" + _ids_digest(ids), hashlib.sha256).digest()


def encode_salt(internal_key: bytes, runs: list, input_ids: Sequence[int]) -> str:
    """runs: [[end_token_or_None, scope_str], ...], ends strictly increasing, last None."""
    payload = json.dumps(runs, separators=(",", ":")).encode()
    return SALT_PREFIX + _b64(payload) + "." + _b64(_mac(internal_key, payload, input_ids))


def digest_messages(raw_messages: Sequence[Any]) -> list[dict]:
    """Normalize chat messages for check_messages. Non-text content becomes None,
    which fails the digest check if it falls inside a shared segment."""
    out = []
    for m in raw_messages:
        role = m.get("role") if isinstance(m, Mapping) else getattr(m, "role", None)
        content = m.get("content") if isinstance(m, Mapping) else getattr(m, "content", None)
        out.append({"role": role if isinstance(role, str) else "", "content": content})
    return out


def _check_text_messages(tok, msgs: list[dict]) -> None:
    for seg, (start, end) in zip(tok.segments, tok.message_ranges(len(msgs))):
        if seg.scope.shared and any(not isinstance(m["content"], str) for m in msgs[start:end]):
            raise ContentMismatch("shared segments must be plain text")
    check_messages(tok, [{"role": m["role"], "content": m["content"] if isinstance(m["content"], str) else ""}
                         for m in msgs])


def label_request(
    cfg: Config,
    ver: Verifier,
    token_header: Optional[str],
    raw_messages: Sequence[Any],
    input_ids: Sequence[int],
    render_prefix: Callable[[int], str],
    tokenize: Callable[[str], list[int]],
) -> str:
    """Ingress. Returns the internal cache salt, or raises TokenError.

    render_prefix(k) renders messages[:k] with the chat template (no generation
    prompt). A segment boundary is trusted only if tokenizing that render
    gives exactly the first tokens of input_ids; otherwise the whole request
    falls back to its most private scope.
    """
    if not token_header:
        raise TokenError("missing X-Ifab-Token")
    tok = ver.verify(token_header)
    msgs = digest_messages(raw_messages)
    _check_text_messages(tok, msgs)

    most_private = str(tok.effective[-1])
    runs: list = []
    ranges = tok.message_ranges(len(msgs))
    for i, ((start, end), eff) in enumerate(zip(ranges, tok.effective)):
        if i == len(ranges) - 1:
            runs.append([None, str(eff)])
            break
        try:
            prefix_ids = list(tokenize(render_prefix(end)))
        except Exception as e:  # templates may refuse partial conversations
            log.warning("ifabsec: prefix render failed (%s); isolating request", e)
            runs = [[None, most_private]]
            break
        n = len(prefix_ids)
        prev_end = runs[-1][0] if runs else 0
        if n == 0 or n <= prev_end or n > len(input_ids) or list(input_ids[:n]) != prefix_ids:
            log.warning("ifabsec: segment boundary not token-stable; isolating request")
            runs = [[None, most_private]]
            break
        runs.append([n, str(eff)])
    return encode_salt(cfg.internal_key, runs, input_ids)


# ---------------------------------------------------------------- keys

_runs_memo: "OrderedDict[str, tuple]" = OrderedDict()
_MEMO_MAX = 65536
_scope_ids: dict[int, str] = {}
_ids_lock = threading.Lock()


def scope_id(scope: str) -> Optional[int]:
    """43-bit id for a scope string; None on a (detected) collision."""
    sid = int.from_bytes(hashlib.sha256(b"ifab-scope\0" + scope.encode()).digest()[:8], "big") >> (64 - SCOPE_BITS)
    with _ids_lock:
        prev = _scope_ids.setdefault(sid, scope)
    if prev != scope:
        log.error("ifabsec: scope id collision between %r and %r; isolating", prev, scope)
        return None
    return sid


def decode_salt(internal_key: bytes, salt: Any, input_ids: Sequence[int]) -> Optional[list[tuple[Optional[int], int]]]:
    """Verify an internal salt against the request's input ids. Returns
    [(end, scope_id), ...] or None if anything is off."""
    if not isinstance(salt, str) or not salt.startswith(SALT_PREFIX):
        return None
    try:
        body, mac = salt[len(SALT_PREFIX):].split(".")
        payload = _unb64(body)
        if not hmac.compare_digest(_unb64(mac), _mac(internal_key, payload, input_ids)):
            return None
        runs = json.loads(payload)
        out, prev = [], 0
        for i, (end, scope) in enumerate(runs):
            is_last = i == len(runs) - 1
            if is_last != (end is None):
                return None
            if not is_last and (not isinstance(end, int) or end <= prev):
                return None
            parse_scope(scope)
            sid = scope_id(scope)
            if sid is None:
                return None
            out.append((end, sid))
            prev = end if end is not None else prev
        return out or None
    except (ValueError, TypeError, ScopeError):
        return None


def _runs_for(cfg: Config, rid: str, salt: Any, origin_ids: Sequence[int]):
    key = f"{rid}\0{salt}\0{len(origin_ids)}"
    hit = _runs_memo.get(key)
    if hit is not None:
        _runs_memo.move_to_end(key)
        return hit[0]
    runs = decode_salt(cfg.internal_key, salt, origin_ids)
    _runs_memo[key] = (runs,)
    if len(_runs_memo) > _MEMO_MAX:
        _runs_memo.popitem(last=False)
    return runs


def pack(token_ids: Sequence[int], runs: Sequence[tuple[Optional[int], int]]) -> Optional[array]:
    """(scope_id << 20) | token for each position; None if a token is out of range."""
    import numpy as np

    ids = np.asarray(token_ids, dtype=np.int64)
    if ids.size and (ids.min() < 0 or ids.max() >= (1 << TOKEN_BITS)):
        return None
    ends = np.asarray([e for e, _ in runs[:-1]], dtype=np.int64)
    sids = np.asarray([s for _, s in runs], dtype=np.int64)
    run_idx = np.searchsorted(ends, np.arange(ids.size, dtype=np.int64), side="right")
    packed = (sids[run_idx] << TOKEN_BITS) | ids
    out = array("q")
    out.frombytes(packed.astype(np.int64).tobytes())
    return out


def scoped_key(req: Any, token_ids: Sequence[int]):
    """Scheduler side. Returns (key_token_ids, key_cache_salt) for RadixKey.

    With IFAB_MODE=off this is the identity. With enforce on, a labeled
    request gets packed ids in the shared labeled namespace; anything else
    (no salt, forged or stale salt, out-of-range tokens, multimodal requests
    whose salt SGLang replaced) gets a namespace of its own: no sharing.
    """
    cfg = config()
    salt = getattr(req, "cache_salt", None)
    if not cfg.enforce:
        return token_ids, salt
    rid = str(getattr(req, "rid", ""))
    runs = _runs_for(cfg, rid, salt, getattr(req, "origin_input_ids", ()))
    if runs is not None:
        packed = pack(token_ids, runs)
        if packed is not None:
            return packed, LABELED_NAMESPACE
    return token_ids, ISOLATE_PREFIX + rid
