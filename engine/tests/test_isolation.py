"""The core claim, tested without a GPU: with (scope, token) keys, what one
principal can observe through the prefix cache does not depend on another
principal's private requests, while approved org content is still shared."""

import random

import pytest

from conftest import T0, VECTOR, b64, mint
from ifabsec_engine import Verifier, check_messages, page_align, scoped_keys, segment_digest, token_scopes
from ifabsec_engine.refcache import PrefixCache

SYSTEM = {"role": "system", "content": "You are Acme's internal assistant."}
OTHER_SYSTEM = {"role": "system", "content": "You are Beta's assistant."}


def make_verifier():
    return Verifier("cluster-1", {"gw-key-1": bytes.fromhex(VECTOR["public_key_hex"])}, now=lambda: T0 + 10)


class Tenant:
    """A principal plus the fake tokenizer/template the engine would use."""

    _n = 0

    def __init__(self, user: str, org: str, system: dict):
        self.user, self.org, self.system = user, org, system

    def request(self, verifier, user_text: str):
        msgs = [self.system, {"role": "user", "content": user_text}]
        Tenant._n += 1
        tok = verifier.verify(mint({
            "v": 1, "iss": "gw-1", "kid": "gw-key-1", "sub": f"user:{self.user}", "aud": "cluster-1",
            "iat": T0, "exp": T0 + 60, "jti": b64(Tenant._n.to_bytes(16, "big")),
            "read": [f"org:{self.org}", f"user:{self.user}"],
            "segments": [
                {"until_message": 1, "scope": f"org:{self.org}", "content_sha256": segment_digest(msgs[:1])},
                {"scope": f"user:{self.user}"},
            ],
        }))
        check_messages(tok, msgs)
        tokens, ends = tokenize(msgs)
        return tokens, token_scopes(tok, ends, len(tokens))


def tokenize(msgs):
    """Stand-in for chat template + tokenizer: one id per character, plus role headers."""
    tokens, ends = [], []
    for m in msgs:
        tokens.append({"system": 1001, "user": 1002}[m["role"]])  # role header
        tokens.extend(ord(c) for c in m["content"])
        ends.append(len(tokens))
    tokens.append(999)  # generation prompt
    return tokens, ends


ALICE = Tenant("alice", "acme", SYSTEM)
BOB = Tenant("bob", "acme", SYSTEM)
EVE = Tenant("eve", "beta", OTHER_SYSTEM)


def test_unprotected_cache_leaks():
    """Baseline: plain token keys let Bob see that Alice sent this exact text."""
    v, cache = make_verifier(), PrefixCache()
    secret = "account 4417 is overdrawn"
    a_tokens, _ = ALICE.request(v, secret)
    cache.insert(a_tokens)
    b_tokens, _ = BOB.request(v, secret)
    assert cache.match_prefix(b_tokens) == len(b_tokens)  # full hit: Alice's text is revealed


def test_labeled_cache_isolates_user_text_but_shares_org_prompt():
    v, cache = make_verifier(), PrefixCache()
    secret = "account 4417 is overdrawn"
    a_tokens, a_scopes = ALICE.request(v, secret)
    cache.insert(scoped_keys(a_tokens, a_scopes))

    b_tokens, b_scopes = BOB.request(v, secret)  # identical text, different user
    org_len = sum(1 for s in b_scopes if str(s) == "org:acme")
    assert org_len > 0
    assert cache.match_prefix(scoped_keys(b_tokens, b_scopes)) == org_len  # org prompt hits, secret misses

    a2_tokens, a2_scopes = ALICE.request(v, secret)  # Alice herself still gets the full hit
    assert cache.match_prefix(scoped_keys(a2_tokens, a2_scopes)) == len(a2_tokens)


def test_page_alignment_never_widens():
    v = make_verifier()
    tokens, scopes = ALICE.request(v, "hello")
    for page in (1, 4, 16, 64):
        aligned = page_align(scopes, page)
        for orig, al in zip(scopes, aligned):
            assert al == orig or orig.is_ancestor_of(al)  # same or more private
        # whole pages inside the org prompt stay shared
        org_len = sum(1 for s in scopes if str(s) == "org:acme")
        assert sum(1 for s in aligned if str(s) == "org:acme") == (org_len // page) * page


@pytest.mark.parametrize("seed", range(20))
def test_noninterference(seed):
    """Bob's cache observations are identical whether or not Alice (same org)
    and Eve (other org) sent private text. Only approved org content is shared."""
    rng = random.Random(seed)
    words = ["balance", "4417", "overdrawn", "refund", "ssn", "diagnosis", "hello", "loan", "the", "is"]

    def text():
        return " ".join(rng.choice(words) for _ in range(rng.randint(1, 6)))

    schedule = [(rng.choice([ALICE, EVE, BOB]), text()) for _ in range(60)]

    def bob_view(include_others: bool) -> list[int]:
        v, cache, seen = make_verifier(), PrefixCache(), []
        for tenant, t in schedule:
            if tenant is not BOB and not include_others:
                continue
            tokens, scopes = tenant.request(v, t)
            keys = scoped_keys(tokens, page_align(scopes, 4))
            if tenant is BOB:
                seen.append(cache.match_prefix(keys))
            cache.insert(keys)
        return seen

    with_others, without = bob_view(True), bob_view(False)
    # The only thing others can change for Bob is whether the approved org
    # prompt is already warm, and only before Bob's own first request warms it.
    org_len = sum(1 for s in page_align(BOB.request(make_verifier(), "x")[1], 4) if str(s) == "org:acme")
    for i, (a, b) in enumerate(zip(with_others, without)):
        if i == 0:
            assert a in (b, org_len)
        else:
            assert a == b
