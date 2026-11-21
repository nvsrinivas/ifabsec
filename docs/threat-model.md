# Threat model (draft)

## Setting

A shared inference cluster serves many principals (users, agents) from several
organizations. A zero-trust layer authenticates each principal; a policy
gateway mints a label token per request (see `label-token.md`); the engine
enforces scopes.

## Attackers

| Attacker | Can | Cannot |
|---|---|---|
| **Co-tenant** (primary) | Send any requests it is authorized to send; measure response timing and response metadata such as cached-token counts; run many probes | Read other tenants' requests or responses directly; forge gateway tokens |
| **Org insider** | Everything a co-tenant can, inside the same org | Put unapproved content into org-shared scope (blocked by `content_sha256`) |
| **Network observer** | See encrypted traffic sizes and timing | Decrypt traffic |

Out of scope for now: a compromised gateway or engine host, a malicious model
provider, physical access, and denial of service.

## Channels

| Channel | What leaks | Attacker | Defense | Status |
|---|---|---|---|---|
| Prefix-cache hit timing | Whether another principal sent a given prefix | Co-tenant | `(scope, token)` cache keys | v0.1 |
| Cached-token count in responses | Same, without timing noise | Co-tenant | Counts only include readable entries (falls out of scoped keys) | v0.1 |
| Writing into shared scope | Planted shared entries become a probe target for other org members | Org insider | Gateway-approved content only, enforced by digest | Done (token layer) |
| Eviction pressure | Whose entries are resident, by forcing evictions and timing | Co-tenant | Per-scope memory quotas | v0.2 |
| Cache-aware routing | Which node holds a prefix, via routing decisions and latency | Co-tenant | Label-aware routing | v0.4 |
| Batching and queueing interference | Other tenants' prompt and output lengths, activity | Co-tenant | Per-scope batching or padding (throughput cost) | Not planned for v0.x |
| Streaming token-length leak | Token lengths, sometimes topic | Network observer | Padding, batched flushes | Published elsewhere; not our focus |
| MoE all-to-all traffic | Expert routing patterns correlated with content | Fabric observer | Padded or constant-rate collectives | Needs a multi-node expert-parallel cluster |
| KV transfer between nodes (disaggregated prefill/decode, offload) | KV contents or integrity | Insider on the cluster fabric | Authenticated, encrypted transfer | Needs RDMA nodes |
| Cache-key incompleteness (adapter, embeddings, media not in key) | Cross-tenant *integrity*: KV computed under one condition served under another | Co-tenant | Every input that changes KV must be in the key | To audit |

## What scopes guarantee, and what they don't

**Guarantee (hit channel):** for a fixed sequence of requests by principal P,
P's cache observations (hit lengths, and so cached-token counts and the timing
those cause) are the same whether or not any other principal sent requests,
except for content in a scope P may read that the gateway approved for sharing.
`engine/tests/test_isolation.py` checks this against the reference cache.

**Not guaranteed:**

- Contention side effects: queueing, batching and memory pressure (until v0.2's quotas).
- Correct policy: if the gateway labels secret content as org-shared, the engine
  will share it. The engine enforces policy; it doesn't decide it.
- Anything a compromised gateway or engine host can do.
