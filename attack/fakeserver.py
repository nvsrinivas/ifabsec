"""A stand-in for SGLang that uses the real ifabsec glue and the reference
prefix cache, with a simple latency model. For testing the harness and the
pod scripts without a GPU. Its numbers are illustrative, not measurements.
"""

from __future__ import annotations

import random
import types

from ifabsec_engine import Verifier
from ifabsec_engine import sglang_glue as g
from ifabsec_engine.refcache import PrefixCache


class CharTokenizer:
    """One token per character; role headers like a chat template."""

    def encode(self, text, add_special_tokens=False):
        return [ord(c) for c in text]

    def apply_chat_template(self, msgs, tokenize=False, add_generation_prompt=False):
        s = "".join(f"<|{m['role']}|>{m['content']}<|end|>" for m in msgs)
        return s + ("<|assistant|>" if add_generation_prompt else "")


class FakeServer:
    """enforce=False behaves like stock SGLang; enforce=True like the patch.
    block > 1 reports cached tokens in whole blocks, as vLLM does."""

    def __init__(self, enforce: bool, gateway_keys: dict, internal_key: bytes, audience: str = "pod-1",
                 base_ms: float = 8.0, per_token_ms: float = 0.05, noise_ms: float = 1.0, seed: int = 0,
                 block: int = 1):
        self.enforce, self.block = enforce, block
        cfg = g.Config(True, audience, gateway_keys, internal_key) if enforce else g.Config(False)
        g._reset_for_tests(cfg, Verifier(audience, gateway_keys))
        self.cache, self.tok = PrefixCache(), CharTokenizer()
        self.base, self.per_tok, self.noise = base_ms / 1000, per_token_ms / 1000, noise_ms / 1000
        self.rng, self.n = random.Random(seed), 0

    def flush(self) -> bool:
        self.cache = PrefixCache()
        return True

    def _serve(self, ids, salt):
        self.n += 1
        req = types.SimpleNamespace(rid=f"r{self.n}", cache_salt=salt, origin_input_ids=ids)
        key_ids, key_salt = g.scoped_key(req, ids)
        keys = [((None, key_salt), t) for t in key_ids]
        cached = min(self.cache.match_prefix(keys), max(len(ids) - 1, 0))  # always compute the last token
        cached -= cached % self.block
        out_ids, out_salt = g.scoped_key(req, list(ids) + [0])  # insert prompt + one output token
        self.cache.insert([((None, out_salt), t) for t in out_ids])
        latency = self.base + self.per_tok * (len(ids) - cached) + abs(self.rng.gauss(0, self.noise))
        return cached, latency

    def post(self, path, body, headers=None):
        headers = headers or {}
        if path == "/generate":
            cached, lat = self._serve(self.tok.encode(body["text"]), None)
            return 200, {"meta_info": {"cached_tokens": cached}}, lat
        msgs = body["messages"]
        ids = self.tok.encode(self.tok.apply_chat_template(msgs, add_generation_prompt=True))
        salt = body.get("cache_salt")
        if self.enforce:
            if salt is not None:
                return 400, {"error": "cache_salt is set by the gateway"}, 0.001
            try:
                salt = g.label_request(g.config(), g.verifier(), headers.get("X-Ifab-Token"), msgs, ids,
                                       lambda k: self.tok.apply_chat_template(msgs[:k]), self.tok.encode)
            except g.TokenError as e:
                return 400, {"error": str(e)}, 0.001
        cached, lat = self._serve(ids, salt)
        return 200, {"usage": {"prompt_tokens": len(ids), "prompt_tokens_details": {"cached_tokens": cached}},
                     "prompt_token_ids": ids}, lat
