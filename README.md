# ifabsec: zero trust inside the inference engine

Zero-trust networks verify who you are at the front door. Inside a shared
inference server, that identity is gone: every tenant's requests share one
prefix cache, one batch and one router. The prefix cache alone is enough to
leak: a cached prompt returns its first token faster, and servers often report
how many prompt tokens were cached, so a co-tenant can test whether someone
else just sent a given text.

ifabsec carries verified identity from the zero-trust layer into the engine and
enforces it there:

```
client or agent
  → zero-trust tunnel (WireGuard): verified identity
  → policy gateway (Go): decides scopes, mints a signed label token
  → inference engine (SGLang fork): verifies the token, enforces scopes
  → GPU
```

The gateway decides; the engine enforces. The engine holds only the gateway's
public keys, never trusts labels in a request body, and keys its prefix cache
by `(scope, token)` instead of `token`. Identical text under different scopes
never matches, so the probe can't form the victim's key. Content the gateway
approved for an org, such as its system prompt, is still shared across that
org.

## Why not just isolate every tenant?

Per-tenant isolation is safe, but it throws away the cache hits on prompts
that are legitimately shared: an org's system prompt, tool schemas, shared
documents. SGLang already has a per-request `cache_salt` that isolates a whole
prompt; it is also chosen by the client, so on its own it relies on the client
picking it honestly. ifabsec's claim is **the same
isolation as per-tenant salting, while keeping the hits on approved shared
content**. The v0.1 benchmark exists to measure exactly that.

## What's here

| Path | What it is | Status |
|---|---|---|
| `docs/label-token.md` | The `ifab1` label-token spec and verification checklist | Draft v1 |
| `docs/threat-model.md` | Channels, attacker positions, what is in and out of scope | Draft |
| `gateway/token` | Go: Ed25519 mint and verify, scope rules, replay protection | Tested |
| `gateway/cmd/ifabsec-mint` | Go CLI: generate a gateway key, mint test tokens | Works |
| `engine/ifabsec_engine` | Python: verify tokens, check approved content, per-token scopes, page alignment, scoped cache keys | Tested |
| `engine/ifabsec_engine/refcache.py` | Reference prefix cache used as the test oracle | Tested |
| `engine/ifabsec_engine/sglang_glue.py` | Ingress labeling and scoped radix-key ids for SGLang | Tested (no GPU) |
| `engine/sglang/` | The SGLang patch, pinned commit, run instructions and GPU checklist | Written, not yet run on a GPU |
| `attack/` | Guessing and digit-extraction attacks over timing and cached-token counts, a fake server, and the pod runner | Tested on the fake server |
| `sim/` | Hit-rate simulation: stock vs per-org vs per-user isolation vs labels | Runs in seconds |
| `testdata/token_vector_v1.json` | A Go-minted token both test suites check, so the implementations can't drift | — |

Not here yet: a GPU run of the patch, the attacks and the latency benchmark.
See the roadmap and `engine/sglang/README.md`.

## Run the tests

```sh
(cd gateway && go test ./...)
(cd engine && pip install -e '.[test]' && python -m pytest)
```

No GPU is needed. The engine tests include a randomized noninterference check:
one user's cache hits are identical whether or not other users (in the same org
or another org) sent private text. Removing scopes from the cache keys makes
that test fail, which is the leak.

## Roadmap

| Version | Adds | Shows |
|---|---|---|
| **v0.1** | SGLang radix cache keyed by `(scope, token)`; token check at ingress; filtered cached-token counts; timing attack; baselines: stock and per-request salt | The leak, the fix, and the hits recovered vs salting |
| v0.2 | Per-scope eviction quotas | Eviction-pressure probing is closed |
| v0.3 | Gateway in front of the WireGuard ZTNA layer, end to end | Identity issued at the network edge, enforced in the engine |
| v0.4 | Two nodes behind a cache-aware router with label-aware routing | The routing channel and its fix |
| later | vLLM port; Dynamo/router-level enforcement | Engine-independent enforcement |

## Ground rules

- Attacks run only against our own servers, with synthetic tenants and fake data.
- Findings in third-party systems are reported to their maintainers before
  anything is published.

## License

Apache 2.0, the same as SGLang.
