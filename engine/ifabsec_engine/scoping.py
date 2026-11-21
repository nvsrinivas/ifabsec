"""Turn a verified token into per-token cache scopes and scoped cache keys.

The engine applies the chat template, tokenizes, and records where each
message's tokens end (including that message's role header and delimiters).
From that, every prompt token gets a scope. Scopes only narrow along the
prompt, because a token's KV depends on everything before it.
"""

from __future__ import annotations

from typing import Sequence

from .scope import Scope
from .token import VerifiedToken

ScopedKey = tuple[str, int]  # (scope string, token id)


def token_scopes(tok: VerifiedToken, message_ends: Sequence[int], n_tokens: int) -> list[Scope]:
    """Scope of every prompt token.

    message_ends[i] is the exclusive token index where message i ends. Tokens
    after the last message (for example the generation prompt the template
    appends) get the last segment's effective scope.
    """
    if any(b < a for a, b in zip(message_ends, message_ends[1:])) or (
        message_ends and (message_ends[0] < 0 or message_ends[-1] > n_tokens)
    ):
        raise ValueError("message_ends must be non-decreasing and within the prompt")
    ranges = tok.message_ranges(len(message_ends))
    out: list[Scope] = []
    start = 0
    for (m_start, m_end), eff in zip(ranges, tok.effective):
        end = message_ends[m_end - 1] if m_end > m_start else start
        if end > start:
            out.extend([eff] * (end - start))
            start = end
    out.extend([tok.effective[-1]] * (n_tokens - start))
    return out


def page_align(scopes: Sequence[Scope], page_size: int) -> list[Scope]:
    """With paged KV, a page that straddles a scope boundary takes the more
    private scope. Scopes are monotone along the prompt, so that is the scope
    of the page's last token."""
    if page_size < 1:
        raise ValueError("page_size must be >= 1")
    n = len(scopes)
    return [scopes[min((i // page_size + 1) * page_size, n) - 1] for i in range(n)]


def scoped_keys(tokens: Sequence[int], scopes: Sequence[Scope]) -> list[ScopedKey]:
    """Cache keys: (scope, token). Identical text under different scopes never matches."""
    if len(tokens) != len(scopes):
        raise ValueError("one scope per token")
    return [(str(s), t) for s, t in zip(scopes, tokens)]
