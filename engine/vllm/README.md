# vLLM patch (v0.1)

`ifabsec-vllm.patch` adds scope enforcement to vLLM at the release in
`VLLM_VERSION` (v0.34.0). It changes about 20 lines in two vLLM files and adds
one hook module. The logic lives in `ifabsec_engine/vllm_glue.py`, which reuses
the engine-neutral ingress code the SGLang patch uses and is tested here
without a GPU (`engine/tests/test_vllm.py`).

**Status: run on an A100** ([results](../../docs/results/2026-11-22-a100-vllm.md)).
The checklist below is what `scripts/pod/check.py` confirms on a pod after
`scripts/pod/setup-vllm.sh`.

## How it works

1. **Ingress** (`/v1/chat/completions`, API server process): after vLLM renders
   and tokenizes the chat, the hook requires a gateway-signed `X-Ifab-Token`,
   checks that shared segments contain exactly the approved content, and finds
   each segment boundary by rendering the prefix messages (role and text only)
   with the server's own chat template and default options. Client documents,
   template options, a request-supplied template and extra message fields are
   never part of that render, so whatever they add to the prompt can only move
   the boundary earlier. The token is verified once per request. The result is sealed into the request's `cache_salt`, MAC'd with
   an internal key and bound to the request's token ids. A client-supplied
   `cache_salt` is rejected.
2. **Keys** (EngineCore process): vLLM hashes the prefix cache in fixed-size
   blocks (16 tokens in the A100 runs, set with `--block-size 16`), each hash chained to its parent's, plus per-block extra keys. Stock
   vLLM adds `cache_salt` to the first block only. With the patch, every
   block's extra keys carry the scope of the block's last token, which under
   the narrowing rule is the narrowest scope in the block. The block that
   straddles a segment boundary is therefore cached as the narrower scope:
   up to 15 tokens of an approved shared segment per request aren't shared.
   The parent chain does the rest: once a block is private, every later
   block's hash depends on it.
3. **Fail closed**: any request without a valid internal salt (completions,
   responses and other endpoints, a client-chosen or forged salt, embeddings
   input) gets a key of its own on every block and shares nothing. That key
   is a random per-request id, not the request id, which clients can choose.
   Block hashes computed by a frontend are ignored while ifabsec is on.
4. **Observe mode** runs every check and keys labeled requests like stock
   (no salt), logs failures instead of rejecting, and leaves an operator's own
   `cache_salt` on other requests working as in stock vLLM.

Model inputs are unchanged: the patch touches only what the cache is keyed
by, never the token ids the model sees.

Patched call sites:

| File | Change |
|---|---|
| `v1/core/kv_cache_utils.py` `generate_block_hash_extra_keys` | Per-block scope key in place of the first-block salt |
| `v1/core/kv_cache_utils.py` `frontend_block_hashes` | Frontend-computed hashes ignored while ifabsec is on |
| `entrypoints/openai/chat_completion/serving.py` `_create_chat_completion` | Ingress hook after rendering; a failed check is an HTTP 400 |
| `ifabsec_hooks.py` (new) | No-op unless `IFAB_MODE` is `observe` or `enforce` |

Inside EngineCore, every path that hashes blocks goes through
`generate_block_hash_extra_keys` (the request block hasher, speculative-decoding
lookahead hashing and KV event publishing), and hashes a frontend computed
itself are refused, so they all see scoped keys. KV events publish the scope
key's value: an HMAC of the scope id under the internal key for labeled
blocks (so consumers can't map it back to a name like `user:acme/alice`),
and the random isolation id for isolated ones. The events still carry raw
token ids, so their consumers must be trusted like the engine. With several
API servers (`--api-server-count`), each keeps its own replay set.

## Block granularity and the attack

vLLM reports cached tokens in whole blocks, so on stock vLLM a single guessed
digit moves Eve's cached count only when it completes a block. That makes
digit-by-digit extraction harder, not impossible: Eve guesses digits in groups
up to the next block boundary, at ten times the cost per extra digit
(`attack/harness.py` `extract_blocks_attack`). Guessing from a candidate list
is unaffected when the secret sits in a full block. With the patch, neither
works: Eve's blocks carry her own scope after the org prompt.

## Not covered in v0.1

Multimodal and prompt-embeds sharing (isolated), the Responses and Anthropic
endpoints (isolated), prefill/decode disaggregation and external KV
connectors (LMCache) beyond what block hashes carry, and decode-side token
reuse (`kv_transfer_params`), whose ids stay in the requester's own scope.

## Pod checklist

`bash scripts/pod/setup-vllm.sh`, then `python scripts/pod/check.py`:

- stock (`IFAB_MODE=off`): the leak exists (a second sender of identical text
  hits all full blocks);
- enforce: same prompt and same greedy output as stock; Alice's re-send hits;
  Bob (same org, identical text) hits only the org prompt's full blocks; Eve
  (other org) hits nothing; requests without a token, with a client
  `cache_salt`, or on `/v1/completions` share nothing; approved tool schemas
  are shared, unapproved ones aren't, altered ones are rejected; segment
  boundaries are stable for the model's chat template.

Then `python attack/run_pod.py` and `python bench/latency.py` as on SGLang.
