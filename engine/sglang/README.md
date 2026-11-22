# SGLang patch (v0.1)

`ifabsec-sglang.patch` adds scope enforcement to SGLang at commit
`SGLANG_COMMIT`. It is small on purpose: about 20 changed lines in SGLang plus
one new hook module. The logic lives in `ifabsec_engine/sglang_glue.py`, which
is tested here without a GPU.

**Status: written against the real SGLang source and unit-tested with fake
SGLang objects, but not yet run on a GPU.** The checklist below is what the
first pod session has to confirm.

## How it works

1. **Ingress** (`/v1/chat/completions`): the hook requires a gateway-signed
   `X-Ifab-Token`, checks that shared segments contain exactly the approved
   content, and tokenizes the prompt itself so it labels exactly the ids the
   model will see. It finds each segment boundary by rendering the prefix
   messages with the chat template and checking that their tokens are a prefix
   of the full prompt. If not, the whole request takes its most private scope.
   The result rides along as `cache_salt`, MAC'd with an internal key and bound
   to the request's token ids.
2. **Keys** (scheduler): wherever SGLang builds a `RadixKey` from a request,
   the hook replaces each token id with `(scope_id << 20) | token_id` and uses
   one shared namespace for labeled requests. The radix tree then matches on
   `(scope, token)` with no changes to the tree itself. Matching, insertion,
   page alignment, cached-token counts and in-batch scheduling all follow.
3. **Fail closed**: any request without a valid internal salt (other
   endpoints, a client-supplied salt, multimodal requests, out-of-range token
   ids) gets a namespace of its own and shares nothing.

Patched call sites:

| File | Change |
|---|---|
| `mem_cache/common.py` `_req_radix_key` | Lookup and touch keys are scoped |
| `mem_cache/radix_cache.py` `_insert_cache` | Insert keys, including the prompt split, are scoped |
| `mem_cache/unified_radix_cache.py` | Same for `UnifiedRadixCache`, the default at the pinned commit: checkpoint and unpublished inserts, the prompt split, the linker skip key |
| `managers/schedule_policy.py` `_compute_prefix_matches` | In-batch prefix grouping is scoped, so queue order can't reveal other tenants' prompts |
| `entrypoints/openai/serving_chat.py` | Ingress hook, after header overrides so nothing the client sends can set the salt |
| `ifabsec_hooks.py` (new) | No-op unless `IFAB_MODE=enforce` |

## Apply and run

```sh
git clone https://github.com/sgl-project/sglang && cd sglang
git checkout "$(cat ../ifabsec/engine/sglang/SGLANG_COMMIT)"
git apply ../ifabsec/engine/sglang/ifabsec-sglang.patch
pip install -e "python[all]" && pip install -e ../ifabsec/engine

export IFAB_MODE=enforce
export IFAB_AUDIENCE=cluster-1
export IFAB_GATEWAY_KEYS="gw-key-1:$(ifabsec-mint pubkey -key gw.seed)"  # append :acme|beta to limit the key to those orgs
export IFAB_INTERNAL_KEY="$(openssl rand -hex 32)"
python -m sglang.launch_server --model-path Qwen/Qwen3-8B
```

Leave HiCache, LMCache/FlexKV, external linkers and multimodal off. v0.1
patches `RadixCache` and the default `UnifiedRadixCache` insert and lookup
paths, but not their storage prefetch paths.

## First GPU session checklist

1. **No behavior change when off.** With `IFAB_MODE=off`, run SGLang's radix
   cache and OpenAI-server tests on the patched tree. They should pass
   unchanged.
2. **Same model input.** With enforcement on, the ingress converts text
   prompts to token ids. Confirm the ids match stock SGLang for the same chat
   request (`return_prompt_token_ids`), including BOS handling.
3. **Boundaries hold for the real template.** Send normal requests and check
   the log has no `isolating request` warnings. If it does, the model's chat
   template renders prefixes differently and that model shares nothing until
   fixed.
4. **Cached-token counts.** Alice twice: the second request reports nearly the
   whole prompt cached. Bob with Alice's identical text: only the org system
   prompt (page-aligned) is cached. Eve in another org: nothing.
5. **Unlabeled traffic is isolated.** `/generate` without a token, and chat
   with a client `cache_salt`, never hit labeled entries.
6. **Overhead.** Time the ingress hook and key packing per request against
   stock SGLang.

Then the timing-attack harness and the baselines: stock SGLang and SGLang's own
per-request `cache_salt`.

## Known limits

- `RadixCache` and `UnifiedRadixCache` only, without HiCache storage
  prefetch. Other cache backends (LMCache, FlexKV, external linkers) build
  keys elsewhere and are not patched. With enforcement on they never widen
  sharing, since the raw internal salt keeps each prompt in its own
  namespace, but they lose sharing. The first GPU run hit exactly this with
  the unified cache: every labeled request fell back to isolation.
- Tool definitions or chat-template options that change how the system prompt
  renders make boundaries unstable, so those requests fall back to user scope.
- Token ids must be below 2^20; larger ids isolate the request.
- Scope ids are 43-bit hashes. A collision is detected per process and
  isolates the request; it never merges two scopes.
