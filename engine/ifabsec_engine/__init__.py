"""Engine-side enforcement for ifabsec: verify label tokens and derive scoped cache keys."""

from .scope import Scope, ScopeError, narrow, parse_scope
from .scoping import page_align, scoped_keys, token_scopes
from .token import (
    AudienceError,
    ContentMismatch,
    ExpiredError,
    FormatError,
    ReplayError,
    SignatureError,
    TokenError,
    Verifier,
    VerifiedToken,
    check_messages,
    segment_digest,
)

__all__ = [
    "AudienceError",
    "ContentMismatch",
    "ExpiredError",
    "FormatError",
    "ReplayError",
    "Scope",
    "ScopeError",
    "SignatureError",
    "TokenError",
    "Verifier",
    "VerifiedToken",
    "check_messages",
    "narrow",
    "page_align",
    "parse_scope",
    "scoped_keys",
    "segment_digest",
    "token_scopes",
]
