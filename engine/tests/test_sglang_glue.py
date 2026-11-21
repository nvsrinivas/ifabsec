"""Tests for the SGLang glue, with a fake chat template and tokenizer.

These check the logic the SGLang patch relies on. They do not run SGLang;
that needs a GPU pod (see engine/sglang/README.md).
"""

import types

import pytest

from conftest import T0, VECTOR, b64, mint
from ifabsec_engine import ContentMismatch, TokenError, Verifier, segment_digest
from ifabsec_engine import sglang_glue as g
from ifabsec_engine.refcache import PrefixCache

INTERNAL = bytes(range(32))
PUB = bytes.fromhex(VECTOR["public_key_hex"])
SYSTEM = {"role": "system", "content": "You are Acme's internal assistant."}


def render(msgs, gen=False):
    s = "".join(f"<|{m['role']}|>{m['content']}<|end|>" for m in msgs)
    return s + ("<|assistant|>" if gen else "")


def tokenize(text):
    return [ord(c) for c in text]


@pytest.fixture
def cfg():
    c = g.Config(True, "cluster-1", {"gw-key-1": PUB}, INTERNAL)
    g._reset_for_tests(c, Verifier("cluster-1", {"gw-key-1": PUB}, now=lambda: T0 + 10))
    yield c
    g._reset_for_tests()


_n = [1000]


def token_for(user, org, msgs, system_ok=True):
    _n[0] += 1
    return mint({
        "v": 1, "iss": "gw-1", "kid": "gw-key-1", "sub": f"user:{user}", "aud": "cluster-1",
        "iat": T0, "exp": T0 + 60, "jti": b64(_n[0].to_bytes(16, "big")),
        "read": [f"org:{org}", f"user:{user}"],
        "segments": [
            {"until_message": 1, "scope": f"org:{org}",
             "content_sha256": segment_digest(msgs[:1] if system_ok else [{"role": "system", "content": "x"}])},
            {"scope": f"user:{user}"},
        ],
    })


def ingress(cfg, user, org, text, header=None, renderer=None):
    msgs = [SYSTEM, {"role": "user", "content": text}]
    ids = tokenize(render(msgs, gen=True))
    salt = g.label_request(
        cfg, g.verifier(), header if header is not None else token_for(user, org, msgs),
        msgs, ids, renderer or (lambda k: render(msgs[:k])), tokenize,
    )
    return types.SimpleNamespace(rid=f"{user}-{_n[0]}", cache_salt=salt, origin_input_ids=ids), msgs


def test_config_from_env():
    assert not g.Config.from_env({}).enforce
    with pytest.raises(ValueError):
        g.Config.from_env({"IFAB_MODE": "enforce"})
    with pytest.raises(ValueError):
        g.Config.from_env({"IFAB_MODE": "on"})
    c = g.Config.from_env({
        "IFAB_MODE": "enforce", "IFAB_AUDIENCE": "c1",
        "IFAB_GATEWAY_KEYS": f"k1:{PUB.hex()}", "IFAB_INTERNAL_KEY": INTERNAL.hex(),
    })
    assert c.enforce and c.gateway_keys == {"k1": PUB}


def test_salt_marks_system_prompt_as_org(cfg):
    req, msgs = ingress(cfg, "alice", "acme", "my balance?")
    runs = g.decode_salt(INTERNAL, req.cache_salt, req.origin_input_ids)
    assert runs[0][0] == len(render(msgs[:1]))  # boundary right after the system message
    assert runs[0][1] == g.scope_id("org:acme") and runs[1] == (None, g.scope_id("user:alice"))


def test_unstable_boundary_isolates(cfg):
    req, _ = ingress(cfg, "alice", "acme", "hi", renderer=lambda k: "<|system|>something else")
    runs = g.decode_salt(INTERNAL, req.cache_salt, req.origin_input_ids)
    assert runs == [(None, g.scope_id("user:alice"))]


def test_render_failure_isolates(cfg):
    def boom(k):
        raise RuntimeError("template needs a user turn")
    req, _ = ingress(cfg, "alice", "acme", "hi", renderer=boom)
    assert g.decode_salt(INTERNAL, req.cache_salt, req.origin_input_ids) == [(None, g.scope_id("user:alice"))]


def test_ingress_rejections(cfg):
    with pytest.raises(TokenError):
        ingress(cfg, "alice", "acme", "hi", header="")
    with pytest.raises(ContentMismatch):  # system prompt not the approved one
        msgs = [SYSTEM, {"role": "user", "content": "hi"}]
        ingress(cfg, "alice", "acme", "hi", header=token_for("alice", "acme", msgs, system_ok=False))
    with pytest.raises(ContentMismatch):  # non-text content in a shared segment
        msgs = [{"role": "system", "content": [{"type": "image_url"}]}, {"role": "user", "content": "hi"}]
        g.label_request(cfg, g.verifier(), token_for("alice", "acme", [SYSTEM]), msgs, [1, 2], lambda k: "", tokenize)


def test_salt_is_bound_to_key_and_prompt(cfg):
    req, _ = ingress(cfg, "alice", "acme", "hi")
    assert g.decode_salt(INTERNAL, req.cache_salt, req.origin_input_ids)
    assert g.decode_salt(bytes(32), req.cache_salt, req.origin_input_ids) is None  # other key
    assert g.decode_salt(INTERNAL, req.cache_salt, req.origin_input_ids + [65]) is None  # other prompt
    body, mac = req.cache_salt[len(g.SALT_PREFIX):].split(".")
    forged = g.SALT_PREFIX + b64(b'[[null,"org:acme"]]') + "." + mac
    assert g.decode_salt(INTERNAL, forged, req.origin_input_ids) is None
    assert g.decode_salt(INTERNAL, "user-chosen-salt", req.origin_input_ids) is None


def test_pack():
    sa, sb = g.scope_id("org:acme"), g.scope_id("user:alice")
    out = g.pack([5, 6, 7, 8], [(2, sa), (None, sb)])
    assert list(out) == [(sa << 20) | 5, (sa << 20) | 6, (sb << 20) | 7, (sb << 20) | 8]
    assert g.pack([1 << 20], [(None, sa)]) is None
    assert g.pack([-1], [(None, sa)]) is None
    assert list(g.pack([], [(None, sa)])) == []


def test_scoped_key_modes(cfg):
    req, _ = ingress(cfg, "alice", "acme", "hi")
    ids, salt = g.scoped_key(req, req.origin_input_ids)
    assert salt == g.LABELED_NAMESPACE and len(ids) == len(req.origin_input_ids)

    unlabeled = types.SimpleNamespace(rid="r9", cache_salt=None, origin_input_ids=[1, 2, 3])
    assert g.scoped_key(unlabeled, [1, 2, 3]) == ([1, 2, 3], g.ISOLATE_PREFIX + "r9")

    forged = types.SimpleNamespace(rid="r10", cache_salt=req.cache_salt, origin_input_ids=[9, 9])
    assert g.scoped_key(forged, [9, 9])[1] == g.ISOLATE_PREFIX + "r10"

    g._reset_for_tests(g.Config(False))
    assert g.scoped_key(unlabeled, [1, 2, 3]) == ([1, 2, 3], None)


def test_scope_id_collision_isolates(cfg):
    sid = g.scope_id("org:acme")
    g._scope_ids[sid] = "org:impostor"  # simulate a 43-bit collision
    req, _ = ingress(cfg, "alice", "acme", "hi")
    assert g.scoped_key(req, req.origin_input_ids)[1].startswith(g.ISOLATE_PREFIX)


def radix_keys(req):
    """What SGLang's RadixKey.child_key sees with a salt: ((extra_key, salt), id)."""
    ids, salt = g.scoped_key(req, req.origin_input_ids)
    return [((None, salt), t) for t in ids]


def test_end_to_end_isolation_and_sharing(cfg):
    cache = PrefixCache()
    secret = "account 4417 is overdrawn"
    alice, msgs = ingress(cfg, "alice", "acme", secret)
    cache.insert(radix_keys(alice))
    org_len = len(render(msgs[:1]))

    bob, _ = ingress(cfg, "bob", "acme", secret)  # same org, identical text
    assert cache.match_prefix(radix_keys(bob)) == org_len  # org prompt shared, secret not

    eve, _ = ingress(cfg, "eve", "beta", secret)  # other org
    assert cache.match_prefix(radix_keys(eve)) == 0

    alice2, _ = ingress(cfg, "alice", "acme", secret)  # Alice herself: full hit
    assert cache.match_prefix(radix_keys(alice2)) == len(alice2.origin_input_ids)

    raw = types.SimpleNamespace(rid="raw-1", cache_salt=None, origin_input_ids=alice.origin_input_ids)
    assert cache.match_prefix(radix_keys(raw)) == 0  # /generate without a token: isolated


def test_prefix_boundary_cache_still_checks_the_prompt(cfg):
    calls = []

    def counting_render(msgs):
        def render_prefix(k):
            calls.append(k)
            return render(msgs[:k])
        return render_prefix

    for user in ("alice", "bob"):
        msgs = [SYSTEM, {"role": "user", "content": f"hi from {user}"}]
        ids = tokenize(render(msgs, gen=True))
        salt = g.label_request(cfg, g.verifier(), token_for(user, "acme", msgs), msgs, ids,
                               counting_render(msgs), tokenize)
        assert g.decode_salt(INTERNAL, salt, ids)[0][1] == g.scope_id("org:acme")
    assert calls == [1]  # the org prompt was rendered once, then cached

    # A prompt whose tokens don't start with the cached render still falls back to isolation.
    msgs = [SYSTEM, {"role": "user", "content": "hi"}]
    ids = tokenize("<|system|>tampered" + render(msgs, gen=True))
    salt = g.label_request(cfg, g.verifier(), token_for("carol", "acme", msgs), msgs, ids,
                           counting_render(msgs), tokenize)
    assert g.decode_salt(INTERNAL, salt, ids) == [(None, g.scope_id("user:carol"))]


def test_template_that_closes_partial_chats_still_shares(cfg):
    """Phi-style templates append an end-of-text token when no generation prompt
    is requested. The shared boundary stops before it instead of isolating."""
    msgs = [SYSTEM, {"role": "user", "content": "hi"}]
    full = tokenize(render(msgs, gen=True))
    phi_render = lambda k: render(msgs[:k]) + "\u00a7"  # one end-of-text token in this char tokenizer
    salt = g.label_request(cfg, g.verifier(), token_for("alice", "acme", msgs), msgs, full, phi_render, tokenize)
    runs = g.decode_salt(INTERNAL, salt, full)
    assert runs[0] == (len(render(msgs[:1])), g.scope_id("org:acme"))  # boundary at the system prompt's end


def test_boundary_never_extends_past_the_approved_render(cfg):
    """Even if the user's text starts exactly like the render's trailing tokens,
    the shared span is capped at the render's own length."""
    msgs = [SYSTEM, {"role": "user", "content": "hi"}]
    full = tokenize(render(msgs, gen=True))
    short_render = lambda k: render(msgs[:k])[:-5]  # a render shorter than the real boundary
    salt = g.label_request(cfg, g.verifier(), token_for("alice", "acme", msgs), msgs, full, short_render, tokenize)
    assert g.decode_salt(INTERNAL, salt, full)[0][0] == len(render(msgs[:1])) - 5


def test_observe_mode_runs_checks_but_keys_like_stock(cfg):
    req, _ = ingress(cfg, "alice", "acme", "hi")
    g._reset_for_tests(g.Config(True, "cluster-1", {"gw-key-1": PUB}, INTERNAL, observe=True),
                       Verifier("cluster-1", {"gw-key-1": PUB}, now=lambda: T0 + 10))
    assert g.scoped_key(req, req.origin_input_ids) == (req.origin_input_ids, None)
    assert g.Config.from_env({"IFAB_MODE": "observe", "IFAB_AUDIENCE": "c1",
                              "IFAB_GATEWAY_KEYS": f"k1:{PUB.hex()}", "IFAB_INTERNAL_KEY": INTERNAL.hex()}).observe
