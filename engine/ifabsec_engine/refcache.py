"""A reference prefix cache keyed by (scope, token).

This is not SGLang. It is the smallest cache with the same matching semantics
as a radix prefix cache, used to test the isolation claim without a GPU and to
serve as the oracle the SGLang patch must agree with.
"""

from __future__ import annotations

from typing import Hashable, Sequence


class _Node:
    __slots__ = ("children",)

    def __init__(self) -> None:
        self.children: dict[Hashable, _Node] = {}


class PrefixCache:
    """Trie over arbitrary hashable keys. Pass plain token ids for the
    unprotected baseline, or (scope, token) pairs for the labeled cache."""

    def __init__(self) -> None:
        self._root = _Node()

    def match_prefix(self, keys: Sequence[Hashable]) -> int:
        """Number of leading keys already cached (what a server reports as cached tokens)."""
        node, n = self._root, 0
        for k in keys:
            node = node.children.get(k)
            if node is None:
                break
            n += 1
        return n

    def insert(self, keys: Sequence[Hashable]) -> None:
        node = self._root
        for k in keys:
            node = node.children.setdefault(k, _Node())
