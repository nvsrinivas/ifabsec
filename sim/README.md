# Hit-rate simulation

How many prefix-cache hits does each isolation policy keep? `hitrate.py` runs
synthetic multi-tenant workloads through a token-level prefix tree once per
policy. It needs only Python and runs in a few seconds.

```sh
python sim/hitrate.py [--json results.json]
```

| Policy | What it is | Who can learn what others sent |
|---|---|---|
| `stock` | One shared cache | Any tenant |
| `per_org` | A namespace per org, as many providers do | Users in the same org |
| `per_user` | A namespace per user, e.g. SGLang's `cache_salt` set by the gateway | No one |
| `labels` | ifabsec: approved org prompt shared in the org, the rest per user | No one |
| `labels+docs` | Same, with the org's popular documents also approved for sharing | No one |

## Results with the default workloads

20 orgs with 50 users each, Zipf-skewed activity, interleaved multi-turn
sessions. Infinite cache: nothing is evicted.

| Workload | stock | per_user | labels | labels+docs |
|---|---|---|---|---|
| Chat assistant (1.5K-token system prompt) | 92.7% | 81.4% | 92.7% | 92.7% |
| Agents with tool schemas (6K-token system prompt) | 94.8% | 74.9% | 94.8% | 94.8% |
| Chat over shared org documents (60% of sessions paste one of 10 docs) | 91.6% | 73.8% | 83.1% | 91.6% |

Compared with per-user isolation, labels in the agent workload need **79% less
prefill compute** and **28% of the KV memory**, because the org's prompt is
cached once instead of once per user. The gap grows with org size: at 5 users
per org labels reach 93.2% vs 84.9%, and at 200 users 95.1% vs 72.9%.

## How to read this honestly

- **Labels match stock in the first two workloads by construction.** There,
  the only content legitimately shared across users is the org prompt, and
  users never send identical private text. The result says that isolation
  costs nothing *when the shareable part is approved*. It doesn't say labels
  are free in general.
- **The documents workload shows the real trade-off.** Content users share
  that the gateway hasn't approved gets isolated, so labels recover about half
  of what per-user isolation loses. Registering those documents as approved
  content recovers the rest. That needs the gateway to know which content is
  shared, which is a policy question, not a cache one.
- **No eviction.** With a real, finite KV cache, per-user isolation's extra
  memory causes evictions and pushes its hit rate lower still. These numbers
  likely understate the gap.
- **Synthetic workloads.** Prompt sizes, user counts and activity skew are
  assumptions. Change the `WORKLOADS` table to match a real deployment, or
  replay a real trace.
- **Hit rate isn't latency.** The pod benchmark measures time to first token
  and throughput on real hardware.
