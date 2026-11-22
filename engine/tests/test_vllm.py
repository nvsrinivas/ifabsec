"""Tests for the vLLM glue and hook module, with a fake chat template, tokenizer
and a model of vLLM's chained block hashing.

They check the logic the vLLM patch relies on. They do not run vLLM; that
needs a GPU pod (see engine/vllm/README.md).
"""

import hashlib
import importlib.util
import pickle
import types
from pathlib import Path

import pytest

import test_sglang_glue as t
from conftest import T0
from ifabsec_engine import Verifier
from ifabsec_engine import sglang_glue as g
from ifabsec_engine import vllm_glue as v
from test_sglang_hooks import added_file

VLLM_DIR = Path(__file__).parents[1] / "vllm"
B = 16  # vLLM's default block size


@pytest.fixture
def cfg():
    c = g.Config(True, "cluster-1", {"gw-key-1": t.PUB}, t.INTERNAL)
    g._reset_for_tests(c, Verifier("cluster-1", {"gw-key-1": t.PUB}, now=lambda: T0 + 10))
    v._reset_for_tests()
    yield c
    g._reset_for_tests()
    v._reset_for_tests()


def request(user, org, text, header=None):
    msgs = [t.SYSTEM, {"role": "user", "content": text}]
    ids = t.tokenize(t.render(msgs, gen=True))
    salt = g.label_request(
        g.config(), g.verifier(), header if header is not None else t.token_for(user, org, msgs),
        msgs, ids, lambda k: t.render(msgs[:k]), t.tokenize,
    )
    return types.SimpleNamespace(request_id=f"{user}-{t._n[0]}", cache_salt=salt, prompt_token_ids=ids), msgs


def block_hashes(req, keys=v.block_keys):
    """vLLM v1: hash(parent, block tokens, extra keys) per full block, where the
    extra keys are ifabsec's (or, when that returns None, the first-block salt)."""
    ids, out, parent = req.prompt_token_ids, [], None
    for start in range(0, len(ids) - B + 1, B):
        extra = keys(req, start, start + B)
        if extra is None:
            extra = [("cache_salt", req.cache_salt)] if start == 0 and req.cache_salt else []
        parent = hashlib.sha256(pickle.dumps((parent, tuple(ids[start:start + B]), tuple(extra)))).digest()
        out.append(parent)
    return out


class BlockCache:
    def __init__(self):
        self.blocks = set()

    def insert(self, req):
        self.blocks.update(block_hashes(req))

    def match(self, req) -> int:
        n = 0
        for h in block_hashes(req):
            if h not in self.blocks:
                break
            n += B
        return n


def test_hook_copy_matches_patch():
    patch = (VLLM_DIR / "ifabsec-vllm.patch").read_text()
    assert added_file(patch, "vllm/ifabsec_hooks.py") == (VLLM_DIR / "ifabsec_hooks.py").read_text()


def test_patch_touches_only_the_two_call_sites():
    patch = (VLLM_DIR / "ifabsec-vllm.patch").read_text()
    files = sorted(line.split(" b/")[1] for line in patch.splitlines() if line.startswith("diff --git"))
    assert files == [
        "vllm/entrypoints/openai/chat_completion/serving.py",
        "vllm/ifabsec_hooks.py",
        "vllm/v1/core/kv_cache_utils.py",
    ]


def test_end_to_end_isolation_and_sharing(cfg):
    cache = BlockCache()
    secret = "My account number is 877893. Please check my balance."
    alice, msgs = request("alice", "acme", secret)
    cache.insert(alice)
    org_len = len(t.render(msgs[:1]))
    shared = (org_len // B) * B  # the block straddling the boundary is Alice's

    bob, _ = request("bob", "acme", secret)  # same org, identical text
    assert cache.match(bob) == shared

    eve, _ = request("eve", "beta", secret)  # other org
    assert cache.match(eve) == 0

    alice2, _ = request("alice", "acme", secret)  # Alice herself: every full block
    assert cache.match(alice2) == (len(alice2.prompt_token_ids) // B) * B


def test_probing_reveals_nothing_past_the_org_prompt(cfg):
    cache = BlockCache()
    alice, msgs = request("alice", "acme", "My account number is 877893.")
    cache.insert(alice)
    shared = (len(t.render(msgs[:1])) // B) * B
    counts = set()
    for d in "0123456789":
        probe, _ = request("eve", "acme", "My account number is " + d)
        counts.add(cache.match(probe))
    assert counts == {shared}  # every guess looks the same


def test_requests_without_a_valid_salt_share_nothing(cfg):
    cache = BlockCache()
    alice, _ = request("alice", "acme", "hello there, a long enough message")
    cache.insert(alice)
    ids = alice.prompt_token_ids
    for rid, salt in [("raw-1", None), ("raw-2", "client-chosen"), ("raw-3", alice.cache_salt + "x")]:
        other = types.SimpleNamespace(request_id=rid, cache_salt=salt, prompt_token_ids=ids)
        assert cache.match(other) == 0
        cache.insert(other)
    # Two requests that pick the same client salt still don't share with each other.
    again = types.SimpleNamespace(request_id="raw-4", cache_salt="client-chosen", prompt_token_ids=ids)
    assert cache.match(again) == 0
    # Embeddings input (no token ids) is isolated too.
    embeds = types.SimpleNamespace(request_id="emb-1", cache_salt=alice.cache_salt, prompt_token_ids=None)
    assert v.block_keys(embeds, 0, B)[0][0] == v.ISOLATE_KEY


def test_isolated_requests_with_the_same_client_request_id_never_share(cfg):
    """vLLM request ids can be client-chosen (X-Request-Id without
    randomization); isolation must not depend on them."""
    ids = list(range(40, 40 + 3 * B))
    a = types.SimpleNamespace(request_id="same", cache_salt=None, prompt_token_ids=ids)
    b = types.SimpleNamespace(request_id="same", cache_salt=None, prompt_token_ids=ids)
    cache = BlockCache()
    cache.insert(a)
    assert cache.match(b) == 0
    assert v.block_keys(a, 0, B) == v.block_keys(a, B, 2 * B)  # stable within a request


def test_salt_from_another_prompt_is_rejected(cfg):
    alice, _ = request("alice", "acme", "my own question")
    eve = types.SimpleNamespace(request_id=alice.request_id, cache_salt=alice.cache_salt,
                                prompt_token_ids=alice.prompt_token_ids[:-1] + [0])
    v.block_keys(alice, 0, B)  # Alice's runs are decoded first
    assert v.block_keys(eve, 0, B)[0][0] == v.ISOLATE_KEY


def test_block_keys_do_not_reveal_scope_names(cfg):
    """KV events publish extra keys; a scope id must not be a plain hash of
    a guessable name like 'user:acme/alice'."""
    import hashlib

    alice, _ = request("alice", "acme", "hello there")
    key = v.block_keys(alice, len(alice.prompt_token_ids) - B, len(alice.prompt_token_ids))[0][1]
    sid = g.scope_id("user:acme/alice")
    assert str(sid) not in str(key) and hashlib.sha256(b"user:acme/alice").hexdigest()[:24] != key


def test_frontend_hashes_are_ignored_when_on(cfg):
    assert v.ignore_frontend_hashes()
    g._reset_for_tests(g.Config(False))
    assert not v.ignore_frontend_hashes()


def test_generated_tokens_take_the_most_private_scope(cfg):
    alice, _ = request("alice", "acme", "hi")
    n = len(alice.prompt_token_ids)
    last = v.block_keys(alice, n + B, n + 2 * B)
    first = v.block_keys(alice, 0, B)
    assert last != first and last == v.block_keys(alice, n - B, n)


def test_off_hashes_like_stock(cfg):
    alice, _ = request("alice", "acme", "hi")
    g._reset_for_tests(g.Config(False))
    assert v.block_keys(alice, 0, B) is None


def test_observe_keeps_an_operators_own_salt(cfg):
    g._reset_for_tests(g.Config(True, "cluster-1", {"gw-key-1": t.PUB}, t.INTERNAL, observe=True),
                       Verifier("cluster-1", {"gw-key-1": t.PUB}, now=lambda: T0 + 10))
    mine = types.SimpleNamespace(request_id="r", cache_salt="acme.alice", prompt_token_ids=list(range(3 * B)))
    assert v.block_keys(mine, 0, B) is None  # vLLM's own first-block salt applies


def test_observe_shares_like_stock_without_a_salt(cfg):
    """Observe mode labels requests (so each carries a unique sealed salt) but
    must cache like stock: identical text from anyone shares every block."""
    cache = BlockCache()
    alice, _ = request("alice", "acme", "My account number is 877893.")
    eve, _ = request("eve", "beta", "My account number is 877893.")
    g._reset_for_tests(g.Config(True, "cluster-1", {"gw-key-1": t.PUB}, t.INTERNAL, observe=True),
                       Verifier("cluster-1", {"gw-key-1": t.PUB}, now=lambda: T0 + 10))
    assert v.block_keys(alice, 0, B) == []
    cache.insert(alice)
    assert cache.match(eve) == (len(eve.prompt_token_ids) // B) * B


# ---------------------------------------------------------------- hook module


@pytest.fixture
def hooks(monkeypatch, cfg):
    monkeypatch.setenv("IFAB_MODE", "enforce")
    spec = importlib.util.spec_from_file_location("ifabsec_vllm_hooks", VLLM_DIR / "ifabsec_hooks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def rag_render(messages, documents=None, gen=False):
    """A RAG-style template: documents and a message's name render inside the
    system turn, before anything the gateway approved ends."""
    out = ""
    for i, m in enumerate(messages):
        extra = f"[{m['name']}]" if m.get("name") else ""
        docs = "".join(f"<doc>{d}</doc>" for d in (documents or [])) if i == 0 else ""
        out += f"<|{m['role']}|>{extra}{m['content']}{docs}<|end|>"
    return out + ("<|assistant|>" if gen else "")


class FakeTokenizer:
    def __init__(self):
        self.calls = []

    def apply_chat_template(self, messages, tools=None, tokenize=False, add_generation_prompt=False, **kw):
        assert not tokenize and not kw.get("tools")
        self.calls.append(kw)
        return rag_render(messages, kw.get("documents"), gen=add_generation_prompt)

    def encode(self, text, add_special_tokens=True):
        assert add_special_tokens is False
        return t.tokenize(text)


def fake_serving():
    return types.SimpleNamespace(
        renderer=types.SimpleNamespace(tokenizer=FakeTokenizer()),
        default_chat_template_kwargs={"enable_thinking": False},
        chat_template=None,
        exclude_tools_when_tool_choice_none=False,
    )


def chat(text, header, cache_salt=None, input_type="token", documents=None, system=None):
    msgs = [system or t.SYSTEM, {"role": "user", "content": text}]
    req = types.SimpleNamespace(messages=msgs, tools=None, tool_choice=None, cache_salt=cache_salt,
                                documents=documents, chat_template_kwargs={"documents": documents})
    raw = types.SimpleNamespace(headers={"x-ifab-token": header} if header else {})
    # The prompt as vLLM renders it: with the client's documents and every field.
    inputs = [{"type": input_type, "prompt_token_ids": t.tokenize(rag_render(msgs, documents, gen=True))}]
    return msgs, req, raw, inputs


def shared_end(salt, ids):
    """Tokens in the first (shared) run; 0 when the whole request is private."""
    runs, _ = g._decode_salt(t.INTERNAL, salt, ids)
    return 0 if len(runs) == 1 else runs[0][0]


def test_label_chat_sets_salt_the_engine_accepts(hooks):
    msgs, req, raw, inputs = chat("hello", None)
    raw.headers["x-ifab-token"] = t.token_for("alice", "acme", msgs)
    assert hooks.label_chat(fake_serving(), req, raw, inputs) is None
    salt = inputs[0]["cache_salt"]
    engine_req = types.SimpleNamespace(request_id="r1", cache_salt=salt, prompt_token_ids=inputs[0]["prompt_token_ids"])
    assert hooks.block_salt_keys(engine_req, 0, B)[0][0] == v.LABELED_KEY


def test_client_documents_never_join_the_shared_segment(hooks):
    """Template-rendered client extras inside the approved system turn must
    not be cached at org scope (the boundary moves before them)."""
    secret = "Customer 88214 owes $12,950"
    msgs, req, raw, inputs = chat("summarize", None, documents=[secret])
    raw.headers["x-ifab-token"] = t.token_for("alice", "acme", msgs)
    serving = fake_serving()
    assert hooks.label_chat(serving, req, raw, inputs) is None
    ids = inputs[0]["prompt_token_ids"]
    n = shared_end(inputs[0]["cache_salt"], ids)
    assert secret not in "".join(map(chr, ids[:n]))
    assert all("documents" not in kw for kw in serving.renderer.tokenizer.calls)


def test_extra_message_fields_never_join_the_shared_segment(hooks):
    system = {**t.SYSTEM, "name": "acct-877893"}
    msgs, req, raw, inputs = chat("hello", None, system=system)
    raw.headers["x-ifab-token"] = t.token_for("alice", "acme", msgs)
    assert hooks.label_chat(fake_serving(), req, raw, inputs) is None
    ids = inputs[0]["prompt_token_ids"]
    assert "877893" not in "".join(map(chr, ids[:shared_end(inputs[0]["cache_salt"], ids)]))


def test_one_prompt_per_request(hooks):
    msgs, req, raw, inputs = chat("hello", None)
    raw.headers["x-ifab-token"] = t.token_for("alice", "acme", msgs)
    twice = inputs + [dict(inputs[0])]
    assert hooks.label_chat(fake_serving(), req, raw, twice) is None  # verified once, both labeled
    assert twice[0]["cache_salt"] == twice[1]["cache_salt"]
    msgs, req, raw, inputs = chat("hello", "x")
    other = inputs + [{"type": "token", "prompt_token_ids": inputs[0]["prompt_token_ids"][:-1]}]
    assert "one prompt" in hooks.label_chat(fake_serving(), req, raw, other)


def test_observe_mode_logs_instead_of_rejecting(hooks):
    g._reset_for_tests(g.Config(True, "cluster-1", {"gw-key-1": t.PUB}, t.INTERNAL, observe=True),
                       Verifier("cluster-1", {"gw-key-1": t.PUB}, now=lambda: T0 + 10))
    msgs, req, raw, inputs = chat("hello", None)
    assert hooks.label_chat(fake_serving(), req, raw, inputs) is None and "cache_salt" not in inputs[0]
    msgs, req, raw, inputs = chat("hello", None, cache_salt="acme.alice")
    assert hooks.label_chat(fake_serving(), req, raw, inputs) is None


def test_label_chat_rejections(hooks):
    msgs, req, raw, inputs = chat("hello", None)
    assert "missing X-Ifab-Token" in hooks.label_chat(fake_serving(), req, raw, inputs)

    msgs, req, raw, inputs = chat("hello", "x", cache_salt="mine")
    assert "set by the gateway" in hooks.label_chat(fake_serving(), req, raw, inputs)

    msgs, req, raw, inputs = chat("hello", "x", input_type="embeds")
    assert "text-only" in hooks.label_chat(fake_serving(), req, raw, inputs)

    msgs, req, raw, inputs = chat("hello", "not-a-token")
    assert hooks.label_chat(fake_serving(), req, raw, inputs).startswith("ifabsec:")
    assert "cache_salt" not in inputs[0]


def test_hooks_are_inert_when_off(monkeypatch):
    monkeypatch.setenv("IFAB_MODE", "off")
    spec = importlib.util.spec_from_file_location("ifabsec_vllm_hooks_off", VLLM_DIR / "ifabsec_hooks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.block_salt_keys(object(), 0, B) is None
    assert mod.label_chat(None, None, None, []) is None


def test_engine_token_buffer_is_accepted(cfg):
    """EngineCore holds prompt ids in an int32 array (vllm.v1.token_buffer)."""
    from array import array

    alice, _ = request("alice", "acme", "hello")
    as_buffer = types.SimpleNamespace(request_id=alice.request_id + "-e", cache_salt=alice.cache_salt,
                                      prompt_token_ids=array("i", alice.prompt_token_ids))
    assert v.block_keys(as_buffer, 0, B) == v.block_keys(alice, 0, B)
