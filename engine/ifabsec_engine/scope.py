"""Cache-sharing scopes. Mirrors gateway/token/scope.go; see docs/label-token.md."""

from __future__ import annotations

import re
from dataclasses import dataclass

PUBLIC, ORG, TEAM, USER = range(4)

_IDENT = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class Scope:
    kind: int
    org: str = ""
    team: str = ""
    user: str = ""

    @property
    def shared(self) -> bool:
        """Entries in this scope can be hit by more than one principal."""
        return self.kind != USER

    def is_ancestor_of(self, other: "Scope") -> bool:
        """Everyone in other's audience is in self's audience (equal counts).

        User membership in orgs and teams is asserted by the gateway, so org and
        team scopes are ancestors of every user scope.
        """
        if self == other or self.kind == PUBLIC:
            return True
        if self.kind == ORG:
            return (other.kind == TEAM and other.org == self.org) or other.kind == USER
        if self.kind == TEAM:
            return other.kind == USER
        return False

    def __str__(self) -> str:
        if self.kind == PUBLIC:
            return "public"
        if self.kind == ORG:
            return f"org:{self.org}"
        if self.kind == TEAM:
            return f"team:{self.org}/{self.team}"
        return f"user:{self.user}"


def _ident(s: str, what: str, full: str) -> str:
    if not _IDENT.fullmatch(s):
        raise ScopeError(f"scope {full!r}: bad {what} id")
    return s


def parse_scope(s: str) -> Scope:
    if s == "public":
        return Scope(PUBLIC)
    kind, sep, rest = s.partition(":")
    if not sep:
        raise ScopeError(f"scope {s!r}: missing kind")
    if kind == "org":
        return Scope(ORG, org=_ident(rest, "org", s))
    if kind == "team":
        org, sep, team = rest.partition("/")
        if not sep:
            raise ScopeError(f"scope {s!r}: want team:<org>/<team>")
        return Scope(TEAM, org=_ident(org, "org", s), team=_ident(team, "team", s))
    if kind == "user":
        return Scope(USER, user=_ident(rest, "user", s))
    raise ScopeError(f"scope {s!r}: unknown kind {kind!r}")


def narrow(a: Scope, b: Scope) -> Scope:
    """The more private of two comparable scopes."""
    if a.is_ancestor_of(b):
        return b
    if b.is_ancestor_of(a):
        return a
    raise ScopeError(f"scopes {a} and {b} are not comparable")
