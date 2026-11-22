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

import threading
from collections import OrderedDict
from typing import Any, Optional, Sequence

from .sglang_glue import (  # engine-neutral ingress and salt handling
    ISOLATE_PREFIX,
    TokenError,
    _dbg,
    _decode_salt,
    _timed,
    config,
    label_request,
    verifier,
)

__all__ = ["block_keys", "label_request", "config", "verifier", "TokenError", "LABELED_KEY", "ISOLATE_KEY"]

LABELED_KEY = "ifab1"  # extra-key tag for a labeled block: ("ifab1", scope_id)
ISOLATE_KEY = ISOLATE_PREFIX.rstrip(":")  # ("ifab-iso", request_id): shares nothing

_runs_memo: "OrderedDict[tuple, tuple]" = OrderedDict()
_MEMO_MAX = 65536
_memo_lock = threading.Lock()


def _runs(cfg, request: Any) -> Optional[list[tuple[Optional[int], int]]]:
    """Verified [(end, scope_id), ...] for a request, or None to isolate.
    The block hasher calls this once per block, so results are memoized."""
    prompt = getattr(request, "prompt_token_ids", None)
    if prompt is None:  # embeddings input: no token ids to bind a salt to
        return None
    salt = getattr(request, "cache_salt", None)
    rid = str(getattr(request, "request_id", ""))
    key = (rid, salt, len(prompt))
    with _memo_lock:
        hit = _runs_memo.get(key)
        if hit is not None:
            _runs_memo.move_to_end(key)
            return hit[0]
    with _timed("sched.unseal"):
        runs, reason = _decode_salt(cfg.internal_key, salt, prompt)
    _dbg("engine", f"rid={rid}", f"n={len(prompt)}", f"salt={str(salt)[:20]}", f"-> {reason}")
    with _memo_lock:
        _runs_memo[key] = (runs,)
        if len(_runs_memo) > _MEMO_MAX:
            _runs_memo.popitem(last=False)
    return runs


def _scope_at(runs: Sequence[tuple[Optional[int], int]], pos: int) -> int:
    for end, sid in runs:
        if end is None or pos < end:
            return sid
    return runs[-1][1]


def block_keys(request: Any, start_token_idx: int, end_token_idx: int) -> Optional[list[tuple]]:
    """Extra hash keys for the block [start, end) of ``request``, used in place
    of vLLM's first-block cache_salt key. None means "ifabsec is off or only
    observing: hash like stock"."""
    cfg = config()
    if not cfg.enforce:
        return None
    with _timed("sched"):
        runs = _runs(cfg, request)
        if cfg.observe:
            return None  # measurement only: stock keys, no isolation
        if runs is None:
            return [(ISOLATE_KEY, str(getattr(request, "request_id", "")))]
        return [(LABELED_KEY, _scope_at(runs, end_token_idx - 1))]


def _reset_for_tests() -> None:
    with _memo_lock:
        _runs_memo.clear()
