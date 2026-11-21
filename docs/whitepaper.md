# ifabsec: zero trust inside the inference engine

November 21, 2026 · exported from the working draft, which is the version to edit

Shared LLM inference servers leak what one tenant sent to another through their prefix cache. Per-tenant isolation fixes the leak only by discarding the cache hits that make sharing worthwhile. ifabsec carries verified identity from a zero-trust network layer into the inference engine and enforces it in the cache keys. On an A100 running Qwen3-8B on SGLang, a same-org co-worker recovered a 6-digit account number from stock SGLang every time; with ifabsec, they recovered nothing. With 1,024 concurrent users, ifabsec kept stock's cache hit rate (90.3% vs 90.6%) and about 98% of its throughput, twice the throughput of per-user isolation, for about 25 ms of extra median first-token latency.

## Background: prefix caching

Prefix caching reuses the attention state of a prompt's opening tokens across requests, cutting time to first token without changing the output. Its defining property, that any request can reuse any matching prefix, is also what makes it observable across tenants.

SGLang is an open-source inference engine. It loads a model onto GPUs, serves an OpenAI-compatible API, batches requests from many users continuously, and manages the KV cache in GPU memory. vLLM and TensorRT-LLM fill the same role. ifabsec patches SGLang; the idea applies to any engine with a shared prefix cache.

- **Two phases.** LLMs generate autoregressively, each token predicted from all tokens before it. Prefill computes the attention keys and values for every prompt token at every layer; this is the KV cache. Decode then generates one token at a time while attending to that cache. For long prompts, prefill dominates time to first token.
- **Reuse across requests.** A KV cache normally lives only for its request. Prefix caching keeps the entries afterwards and reuses them for any later request whose token sequence starts the same way.
- **Exact, but prefix-only.** Attention is causal, so a token's keys and values depend only on the tokens before it. Reuse therefore gives identical output, but only for an identical prefix. The same text after a different opening cannot reuse anything.
- **Implementations.** SGLang keeps entries in a radix tree keyed by token ids (RadixAttention). vLLM hashes fixed-size blocks, each hash chained over the prefix before it. Hosted APIs offer the same idea as prompt caching, usually priced below uncached input.
- **What gets shared.** System prompts, tool schemas, few-shot examples, retrieved documents, and the earlier turns of a conversation. Entries live in GPU memory and are evicted, least recently used first, under pressure.

## The problem

A prefix cache reuses the computed state of any prompt that starts with text already seen, so a cached prompt answers faster and many servers report how many of its tokens were cached. If the cache is shared across tenants, anyone can test whether someone else just sent a given text: guess, send, and watch the speed or the cached-token count. A Stanford audit found this kind of global cache sharing in production APIs from seven providers in late 2024.

The usual fixes trade one problem for another:

| Policy | Who can learn what others sent | Cost |
| --- | --- | --- |
| One shared cache (stock) | Any tenant | None |
| A cache per org | Other users in the same org | Small |
| A cache per user, e.g. SGLang's `cache_salt` | No one | Every user re-computes and stores the org's shared system prompt and tool schemas |

The gap is a policy that is as safe as per-user isolation but keeps the sharing an org actually wants.

## The approach

The gateway decides and the engine enforces, the same split as in zero-trust network access, carried past the front door into the GPU server.

![ifabsec architecture: the zero-trust edge decides, the SGLang server enforces](img/architecture.svg)

The gateway signs what each part of a prompt may share. Inside SGLang, the HTTP process checks the label once, and the cache keys carry its scope from there on.

1. **Identity.** A user or agent connects through a zero-trust tunnel (WireGuard) and is authenticated.
2. **Label token.** A policy gateway mints a short-lived Ed25519-signed token per request: which scopes the request may read (`public`, `org`, `team`, `user`) and which messages belong to which scope. A shared segment must match a content hash the gateway approved, such as the org's registered system prompt.
3. **Scoped cache keys.** Inside SGLang, every cached token is keyed by `(scope, token)` instead of `token`. Identical text under different scopes never matches, so a probe cannot form the victim's key. The radix tree itself is unchanged.
4. **Narrowing.** A token's cached state depends on everything before it, so a scope can only narrow along the prompt: the org's system prompt is shared across the org, and everything after the user's first word is the user's alone.
5. **Fail closed.** Anything without a valid label (other endpoints, client-chosen salts, image requests) gets a cache space of its own and shares nothing.

![Who reuses what after Alice's request: Alice reuses everything, Bob in her org reuses only the org prompt, a user in another org reuses nothing](img/scopes.svg)

After Alice's request is cached, identical text is not enough to reuse it: Bob in her org reuses only the approved org prompt, and a user in another org reuses nothing.

The SGLang change is small: about 30 added lines across 5 SGLang files plus one 75-line hook module that does nothing unless enforcement is on.

## Threat model and limits

Labels defend against a tenant with ordinary API access who watches response times and cached-token counts. They trust the gateway that signs labels, and they leave probing within a scope open by design.

- **Stopped:** probing across scopes through cache hits, cached-token counts or first-token timing; clients choosing their own cache salt; unlabeled traffic, which gets a private cache space.
- **Trusted:** the gateway, which authenticates users and decides what is shared, and the engine host. A compromised gateway can label anything as shared.
- **Allowed by design:** anyone inside a scope can still probe that scope. Team-scoped text is visible to the whole team.
- **Policy, not mechanism:** someone must decide which prompts are org-approved. The token carries that decision; it does not make it.
- **Replay:** each engine process remembers token IDs until they expire (at most 5 minutes). Multiple replicas rely on the short expiry, not on shared replay state.
- **Not covered:** eviction-pressure probing (per-scope quotas planned); timing from batching and queueing; KV transfer between nodes in disaggregated serving; SGLang's other cache backends, which fail closed and lose sharing.
- **Not yet reviewed:** nobody outside this project has reviewed the token design.

## Evaluation

Stock SGLang leaked a full account number to a same-org co-worker on both GPUs, and labels closed every channel we tested while keeping the org prompt shared. Setup: SGLang `efab9d61` with the ifabsec patch, Qwen3-8B unless noted, synthetic tenants, attacks only against our own servers. Eve sits in Alice's org, so she legitimately shares the org system prompt.

### How the attack works

Eve needs nothing but the API and the cached-token count that comes back in each response's usage block. SGLang's chat endpoint reports that count only when the server runs with `--enable-cache-report`, which our tests turn on; many hosted APIs report it by default, and the timing channel needs no count at all. The prompts below are the ones the test harness sends; the account number is drawn at random for each trial, and this one is from the A100 run below.

```text
System (shared by the org):  You are Acme Corp's internal billing assistant. Answer briefly.
Alice sends:                 My account number is 877893. Please check my balance.

Eve probes, one request each, and reads cached_tokens from the response:
  My account number is 0   ->  cached count stays at the shared prefix
  My account number is 8   ->  cached count is one token higher: the first digit is 8
  My account number is 80 ... 89   ->  one more token for 87
  ...six positions, ten probes each, and the full number is recovered
```

The extraction works because the tokenizer splits digits, so every correct digit extends Alice's cached prefix by exactly one token. With labels, Alice's message is cached under her own scope, so none of Eve's probes match past the shared system prompt and every digit looks the same.

![Extraction probes on an A100: on stock SGLang the right digit returns one more cached token at each of six positions; with labels all ten digits return 30](img/extraction-probes.svg)

The guessing attack is the coarser version: Eve holds a list of 20 candidate account numbers, sends each one inside a long form, and picks the probe that returned fastest or with the most cached tokens.

![Guess timing on an A100: on stock SGLang the right guess returns in 31.7 ms against 63-77 ms for wrong guesses; with labels it returns in 63.9 ms, among the rest](img/guess-timing.svg)

On stock SGLang the right guess also returned 579 cached tokens against 37–39 for the others; with labels it returned 37, like the rest.

### Attacks

![Attack success: stock SGLang 60-100%, with labels at or near chance](img/attack-success.svg)

On stock SGLang a right guess came back 42 ms faster on the 4090 and 36.6 ms on the A100; with labels the gap was under 0.3 ms, which is noise. The 4090 caps stock guessing at 70% because its 6,860-token KV cache evicts Alice's entry partway through a trial; the A100 has no such limit. On Phi-4-mini, stock guessing also reached 100% with a 14.4 ms gap, and labels brought it to 10% and 0%.

### Correctness

- The labeled path feeds the model exactly the same token ids as stock and produces the same greedy output.
- Alice's repeat of her own prompt hits all but the last token; Bob, in her org, gets exactly the org prompt; a user in another org gets nothing.
- A second chat-template family, Phi-4-mini, first failed closed: its template appends an end-of-text token when rendering a partial chat. Defining the boundary as the common prefix with the full prompt fixed it, and all checks pass with no isolated requests.

### Cost under load

Labels keep stock's hit rate and about 98% of its throughput, while per-user isolation halves throughput and computes 5.4× more prompt tokens. Workload on the A100: 4 orgs × 256 users, two-turn sessions, 16 in flight, averaged over runs.

![Cost by policy: hit rate, throughput, p95 latency, prompt tokens computed](img/policy-cost.svg)

At the median, labels' first token took 191 ms against stock's 166 ms and per-user isolation's 213 ms; across three runs it ranged from 183 to 200 ms. Profiling locates the cost: the scheduler spends about 0.5 ms per request on scoped keys, and the HTTP front end about 2.2 ms, of which only 0.7 ms is computation. The rest is waiting for Python's global interpreter lock behind the response stream, an engineering cost rather than a property of the design. An observe mode that runs every check but keys the cache like stock sat at 175 ms.

In a simulation of 20 orgs with 50 users each, an agent workload with a 6,000-token system prompt kept a 94.8% hit rate with labels, the same as stock, versus 74.9% with per-user isolation. That workload is favourable: when users paste shared documents the gateway has not approved, labels recover about half of the lost hits.

## Deployment

ifabsec is a small patch plus a token library, off by default and switched on per server.

- **SGLang patch:** about 30 added lines across 5 files, plus a hook module. With `IFAB_MODE=off` the engine behaves exactly like stock; `observe` runs every check but keys the cache like stock, for measuring; `enforce` turns isolation on.
- **Inside the engine:** the HTTP process verifies the label once. It hands the scheduler an internal salt, authenticated with a server key and bound to the request's exact input tokens, so the scheduler never parses tokens and a request cannot borrow another's scopes.
- **Gateway side:** a Go library and command-line tool mint and verify label tokens; Python verifies the same test vectors.
- **Configuration:** the server's audience name, the gateway's public keys, and an internal key shared by the engine's processes.
- **Other engines:** vLLM already has a per-request `cache_salt` that seeds its block hashes. A port would apply the same scope-per-segment keying there; it has not been done.

## Related work

Other defenses decide inside the engine what is sensitive; ifabsec takes that decision from an authenticated policy at the network edge. The closest idea, boundary salting, has the same shape as ifabsec's scopes, and ifabsec supplies the authenticated identity and boundary it assumes.

| Work | Approach | How ifabsec differs |
| --- | --- | --- |
| [Gu et al., ICML 2025](https://arxiv.org/abs/2502.07776) | Audit: detected global cache sharing in production APIs from seven providers | The attack setting ifabsec defends against |
| [KVGov](https://arxiv.org/abs/2608.09225) | Boundary salting: blocks before a divergence point stay shared, a per-principal salt applies after it; vLLM's root `cache_salt` is all-or-nothing | Same structure; ifabsec gets the principal and boundaries from a signed token and enforces them in a running engine |
| [SafeKV](https://arxiv.org/abs/2508.08438) | Detects sensitive content in the runtime and isolates those KV blocks; up to 2.66× throughput over isolation baselines | Sharing set by policy, not by detecting sensitive content |
| [CacheSolidarity](https://arxiv.org/abs/2603.10726) | Tracks reuse across users, flags suspicious sharing, isolates flagged prefixes | Prevents cross-scope matches up front rather than reacting to suspicious reuse |
| [CachePrune](https://arxiv.org/abs/2605.23640) | Fine-grained sharing of privacy-irrelevant segments such as system instructions | Same goal; segments marked by a signed gateway policy |

To our knowledge, ifabsec is the first to enforce gateway-signed sharing scopes inside a production engine's prefix cache, measured for both leakage and cost on real GPUs. That claim needs a fuller literature check before publication.

## Next steps

The priority is an outside review of the token design. After that comes breadth: other engines, more nodes.

1. Outside review of the token format, scope rules and fail-closed paths.
2. A vLLM port using its existing per-request salt.
3. Multiple replicas: label-aware routing, and shared replay state or a policy that relies on short expiry.
4. Disaggregated serving: scopes carried with KV transfers between prefill and decode nodes.
5. A gateway service that turns WireGuard identity into label tokens end to end.
6. Per-scope eviction quotas against eviction-pressure probing.
7. A proposal to SGLang upstream for gateway-set cache scopes.

## Sources

- Gu et al., [Auditing Prompt Caching in Language Model APIs](https://proceedings.mlr.press/v267/gu25b.html), ICML 2025.
- [Governing the KV Cache: Preventing Timing Side-Channel Leakage in Multi-Tenant LLM Inference](https://arxiv.org/abs/2608.09225) (KVGov), arXiv 2608.09225.
- Chu et al., [Selective KV-Cache Sharing to Mitigate Timing Side-Channels in LLM Inference](https://arxiv.org/abs/2508.08438) (SafeKV), arXiv 2508.08438.
- Pennas et al., [CacheSolidarity: Preventing Prefix Caching Side Channels in Multi-tenant LLM Serving Systems](https://arxiv.org/abs/2603.10726), arXiv 2603.10726.
- Wu et al., [CachePrune: Privacy-Aware and Fine-Grained KV Cache Sharing for Efficient LLM Inference](https://arxiv.org/abs/2605.23640), arXiv 2605.23640.
- Full setup and raw numbers: [`results/2026-11-21-rtx4090.md`](results/2026-11-21-rtx4090.md), [`results/2026-11-21-a100.md`](results/2026-11-21-a100.md) and [`../sim/README.md`](../sim/README.md).
