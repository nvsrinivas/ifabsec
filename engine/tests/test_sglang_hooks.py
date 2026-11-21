"""Run the SGLang hook module (the file the patch adds) against fake SGLang objects."""

import importlib.util
import types
from pathlib import Path

import pytest

import test_sglang_glue as t
from conftest import T0
from ifabsec_engine import Verifier
from ifabsec_engine import sglang_glue as g

SGLANG_DIR = Path(__file__).parents[1] / "sglang"


def added_file(patch: str, path: str) -> str:
    """Contents of a file the patch creates."""
    lines, inside = [], False
    for line in patch.splitlines():
        if line.startswith("diff --git"):
            inside = line.endswith(f"b/{path}")
        elif inside and line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return "\n".join(lines) + "\n"


def test_hook_copy_matches_patch():
    patch = (SGLANG_DIR / "ifabsec-sglang.patch").read_text()
    assert added_file(patch, "python/sglang/srt/ifabsec_hooks.py") == (SGLANG_DIR / "ifabsec_hooks.py").read_text()


@pytest.fixture
def hooks(monkeypatch):
    monkeypatch.setenv("IFAB_MODE", "enforce")
    spec = importlib.util.spec_from_file_location("ifabsec_hooks", SGLANG_DIR / "ifabsec_hooks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    g._reset_for_tests(g.Config(True, "cluster-1", {"gw-key-1": t.PUB}, t.INTERNAL),
                       Verifier("cluster-1", {"gw-key-1": t.PUB}, now=lambda: T0 + 10))
    yield mod
    g._reset_for_tests()


class FakeTokenizer:
    def encode(self, text, add_special_tokens=False):
        return t.tokenize(text)

    def apply_chat_template(self, msgs, tokenize=False, add_generation_prompt=False):
        return t.render(msgs, add_generation_prompt)


class Msg(dict):
    def model_dump(self, exclude_none=True):
        return dict(self)


def fakes(header, salt=None):
    msgs = [Msg(t.SYSTEM), Msg(role="user", content="hello")]
    serving = types.SimpleNamespace(tokenizer_manager=types.SimpleNamespace(tokenizer=FakeTokenizer()))
    request = types.SimpleNamespace(messages=msgs, cache_salt=salt)
    raw = types.SimpleNamespace(headers={"x-ifab-token": header} if header else {})
    adapted = types.SimpleNamespace(text=t.render(msgs, True), input_ids=None, cache_salt=None,
                                    image_data=None, video_data=None, audio_data=None)
    return serving, request, raw, adapted, msgs


def test_label_chat_converts_to_ids_and_attaches_salt(hooks):
    msgs = [dict(t.SYSTEM), {"role": "user", "content": "hello"}]
    serving, request, raw, adapted, _ = fakes(t.token_for("alice", "acme", msgs))
    out = hooks.label_chat(serving, request, raw, adapted)
    assert out.text is None and out.input_ids == t.tokenize(t.render(msgs, True))
    runs = g.decode_salt(t.INTERNAL, out.cache_salt, out.input_ids)
    assert runs[0][1] == g.scope_id("org:acme")
    key_ids, ns = hooks.scoped_key(types.SimpleNamespace(rid="a", cache_salt=out.cache_salt,
                                                         origin_input_ids=out.input_ids), out.input_ids)
    assert ns == g.LABELED_NAMESPACE and len(key_ids) == len(out.input_ids)


def test_label_chat_rejects(hooks):
    msgs = [dict(t.SYSTEM), {"role": "user", "content": "hello"}]
    with pytest.raises(ValueError, match="cache_salt"):
        hooks.label_chat(*fakes(t.token_for("alice", "acme", msgs), salt="client")[:4])
    with pytest.raises(ValueError, match="missing"):
        hooks.label_chat(*fakes(None)[:4])
    serving, request, raw, adapted, _ = fakes(t.token_for("alice", "acme", msgs))
    adapted.image_data = ["img"]
    with pytest.raises(ValueError, match="text-only"):
        hooks.label_chat(serving, request, raw, adapted)
