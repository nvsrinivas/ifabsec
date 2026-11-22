"""Glue between ifabsec and vLLM (v1 engine). Kept free of vLLM and torch
imports so it can be tested without a GPU; the vLLM patch calls into it through
a small hook module.

Ingress is shared with SGLang (``sglang_glue.label_request``): verify the label
token, check approved content, find where each segment's tokens end, and seal
the result into a MAC'd internal salt. On vLLM the salt rides in the request's
``cache_salt`` field from the API server to the EngineCore process.

Keys differ. vLLM hashes the prefix cache in fixed-size blocks (16 tokens by
default), each hash chained to its parent's, and lets extra keys join a block's
hash. Stock vLLM adds ``cache_salt`` to the first block only, which can isolate
a whole request but never share part of one. ifabsec adds the block's scope to
every block hash instead:

* A block's scope is the scope of its last token. Scopes only narrow along a
  prompt (the narrowing rule), so that is the narrowest scope of any token in
  the block. A block that straddles a segment boundary is cached as the
  narrower scope: up to one block of an approved shared segment per request
  is not shared.
* The parent chain carries the rest: once a block is private, every later
  block's hash depends on it.
* Generated tokens past the prompt take the last (most private) scope.

Every failure path fails closed: a request without a valid internal salt
(other endpoints, a client-chosen or forged salt, embeddings input) gets a key
of its own on every block and shares nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from typing import Any, Optional, Sequence

from .sglang_glue import (  # engine-neutral ingress and salt handling
    ISOLATE_PREFIX,
    TokenError,
    _timed,
    config,
    is_ifab_salt,
    isolation_id,
    label_request,
    render_messages,
    request_runs,
    verifier,
)

__all__ = ["block_keys", "label_request", "render_messages", "config", "verifier", "TokenError",
           "LABELED_KEY", "ISOLATE_KEY", "ignore_frontend_hashes"]

LABELED_KEY = "ifab1"  # extra-key tag for a labeled block: ("ifab1", keyed scope id)
ISOLATE_KEY = ISOLATE_PREFIX.rstrip(":")  # ("ifab-iso", random per-request id): shares nothing

_keyed: dict[int, str] = {}
_keyed_lock = threading.Lock()


def _runs(cfg, request: Any) -> Optional[list[tuple[Optional[int], int]]]:
    """Verified [(end, scope_id), ...] for a request, or None to isolate.
    Decoded once per request and kept on the Request object."""
    prompt = getattr(request, "prompt_token_ids", None)
    if prompt is None:  # embeddings input: no token ids to bind a salt to
        return None
    with _timed("sched.unseal"):
        return request_runs(cfg, request, str(getattr(request, "request_id", "")),
                            getattr(request, "cache_salt", None), prompt)


def _keyed_scope(cfg, sid: int) -> str:
    """The scope id as it appears in block hashes and KV events: keyed with
    the internal key, so event consumers can't map it back to a scope name
    by hashing guesses like 'user:acme/alice'."""
    k = _keyed.get(sid)
    if k is None:
        k = hmac.new(cfg.internal_key, b"ifab-block-scope\0" + sid.to_bytes(8, "big"), hashlib.sha256).hexdigest()[:24]
        with _keyed_lock:
            if len(_keyed) > (1 << 16):
                _keyed.clear()
            _keyed[sid] = k
    return k


def _scope_at(runs: Sequence[tuple[Optional[int], int]], pos: int) -> int:
    for end, sid in runs:
        if end is None or pos < end:
            return sid
    return runs[-1][1]


def block_keys(request: Any, start_token_idx: int, end_token_idx: int) -> Optional[list[tuple]]:
    """Extra hash keys for the block [start, end) of ``request``, used in place
    of vLLM's first-block cache_salt key. None means "hash exactly like stock
    vLLM" (ifabsec off, or observe mode on a request ifabsec didn't label)."""
    cfg = config()
    if not cfg.enforce:
        return None
    salt = getattr(request, "cache_salt", None)
    if cfg.observe:
        if not is_ifab_salt(salt):
            return None  # an operator's own salt keeps working in observe mode
        with _timed("sched"):
            _runs(cfg, request)  # measured, not applied
        return []  # stock keys with no salt: our salt is unique per request
    with _timed("sched"):
        runs = _runs(cfg, request)
        if runs is None:
            return [(ISOLATE_KEY, isolation_id(request))]
        return [(LABELED_KEY, _keyed_scope(cfg, _scope_at(runs, end_token_idx - 1)))]


def ignore_frontend_hashes() -> bool:
    """Block hashes a frontend computed itself never carry scopes: with
    ifabsec on, the engine always hashes prompts itself."""
    return config().enforce


def _reset_for_tests() -> None:
    with _keyed_lock:
        _keyed.clear()
