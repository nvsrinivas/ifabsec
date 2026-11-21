# Latency benchmark

Time to first token, end-to-end latency and throughput under concurrent
multi-tenant load, for three policies on the same workload:

| Policy | Server | What's shared |
|---|---|---|
| `stock` | `IFAB_MODE=off`, no salt | Everything (leaks across tenants) |
| `per_user` | `IFAB_MODE=off`, `cache_salt` = org/user, as a gateway would set it | Only each user's own history; the org prompt is cached once per user |
| `labels` | `IFAB_MODE=enforce` with label tokens | The org prompt once per org, plus each user's own history |

Default workload: 4 orgs × 16 users, each org with a ~1.5K-token system
prompt, two-turn sessions with ~150-token messages, 16 sessions in flight, 32
output tokens per request.

```sh
python bench/latency.py               # on the pod, after scripts/pod/setup.sh
```

It streams each response to time the first token, flushes the cache before
each policy, and prints a table (`.pod/latency.json`).

## What to expect

`labels` should match `stock` on hit rate and time to first token, and beat
`per_user`, which prefills the org prompt once per user. On a 24 GB card the
gap may be larger than the hit rates alone suggest: 64 users × 1.5K tokens of
duplicated org prompts is more than the KV cache likely holds alongside an 8B
model, so `per_user` should also evict more.

The fake-server numbers in the tests check the logic only; their latency model
is made up.
