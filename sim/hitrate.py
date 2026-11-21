#!/usr/bin/env python3
"""How many prefix-cache hits does each isolation policy keep?

Synthetic multi-tenant workloads run through a token-level prefix tree, once
per policy:

  stock      one shared cache for everyone (fastest; leaks across tenants)
  per_org    one cache namespace per org (what many providers do; leaks
             between users of the same org)
  per_user   one namespace per user, e.g. SGLang's cache_salt set by the
             gateway (safe; loses the org's shared system prompt)
  labels     ifabsec: approved org content shared within the org, everything
             after it per user (safe)
  labels+docs  labels, with the org's popular documents also registered as
             approved shared content (safe; needs the gateway to know them)

Reported per policy: share of prompt tokens served from cache, KV memory used
(distinct cached tokens), and who can see whom. The workloads are made-up
but parameterized; change them to match a real deployment. Infinite cache:
no eviction, so memory is reported rather than enforced.

    python sim/hitrate.py [--json out.json]
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
from dataclasses import dataclass, field

PAGE = 16  # one simulated unit = one 16-token KV page, to keep the run fast
POLICIES = ("stock", "per_org", "per_user", "labels", "labels+docs")
LEAKS = {
    "stock": "any tenant",
    "per_org": "same-org users",
    "per_user": "none",
    "labels": "none (approved org prompt only)",
    "labels+docs": "none (approved org prompt and docs only)",
}


@dataclass
class Workload:
    name: str
    orgs: int
    users_per_org: int
    system_tokens: int  # org system prompt, tool schemas, instructions
    turn_tokens: tuple[int, int]  # user message length range
    output_tokens: int
    turns: tuple[int, int]  # turns per session
    sessions_per_user: tuple[int, int]
    zipf: float = 1.1  # user activity skew
    docs_per_org: int = 0  # popular org documents users paste in
    doc_tokens: int = 0
    p_doc: float = 0.0  # chance a session starts by pasting one of them
    seed: int = 0


WORKLOADS = {
    "chat": Workload("chat assistant", orgs=20, users_per_org=50, system_tokens=1500,
                     turn_tokens=(64, 320), output_tokens=240, turns=(1, 8), sessions_per_user=(1, 4)),
    "agents": Workload("agents with tool schemas", orgs=20, users_per_org=50, system_tokens=6000,
                       turn_tokens=(128, 512), output_tokens=160, turns=(1, 3), sessions_per_user=(2, 10)),
    "rag": Workload("chat over shared org documents", orgs=20, users_per_org=50, system_tokens=1500,
                    turn_tokens=(64, 320), output_tokens=240, turns=(1, 6), sessions_per_user=(1, 4),
                    docs_per_org=10, doc_tokens=3000, p_doc=0.6),
}


@dataclass
class Request:
    org: int
    user: int
    system: list[int]  # approved org content
    rest: list[int]  # everything after it: history and the new message
    output: list[int]
    doc_units: int = 0  # leading units of rest that are a popular org document


def _units(n_tokens: int) -> int:
    return max(1, round(n_tokens / PAGE))


def generate(w: Workload) -> list[Request]:
    """Interleaved sessions; each turn's prompt = system + history + new message."""
    rng = random.Random(w.seed)
    fresh = itertools.count(1_000_000)
    systems = [[next(fresh) for _ in range(_units(w.system_tokens))] for _ in range(w.orgs)]
    docs = [[[next(fresh) for _ in range(_units(w.doc_tokens))] for _ in range(w.docs_per_org)]
            for _ in range(w.orgs)]
    sessions = []
    for org in range(w.orgs):
        weights = [1 / (r + 1) ** w.zipf for r in range(w.users_per_org)]
        scale = w.sessions_per_user[1] / weights[0]
        for user in range(w.users_per_org):
            n = max(w.sessions_per_user[0], min(w.sessions_per_user[1], round(weights[user] * scale)))
            for _ in range(n):
                sessions.append((org, user, rng.randint(*w.turns)))
    rng.shuffle(sessions)

    # Run sessions concurrently in random order so different tenants interleave.
    active = []
    for org, user, turns in sessions:
        doc = rng.choice(docs[org]) if docs[org] and rng.random() < w.p_doc else []
        active.append([org, user, turns, list(doc), len(doc)])
    out: list[Request] = []
    while active:
        i = rng.randrange(len(active))
        org, user, turns_left, history, doc_units = active[i]
        msg = [next(fresh) for _ in range(_units(rng.randint(*w.turn_tokens)))]
        output = [next(fresh) for _ in range(_units(w.output_tokens))]
        out.append(Request(org, user, systems[org], history + msg, output, doc_units))
        active[i][3] = history + msg + output
        active[i][2] -= 1
        if active[i][2] == 0:
            active.pop(i)
    return out


@dataclass
class Trie:
    root: dict = field(default_factory=dict)
    nodes: int = 0

    def match(self, keys) -> int:
        node, n = self.root, 0
        for k in keys:
            node = node.get(k)
            if node is None:
                break
            n += 1
        return n

    def insert(self, keys) -> None:
        node = self.root
        for k in keys:
            nxt = node.get(k)
            if nxt is None:
                nxt = node[k] = {}
                self.nodes += 1
            node = nxt


def keys_for(policy: str, r: Request) -> tuple[list, list]:
    """Cache keys for the prompt and for prompt + output."""
    tokens = r.system + r.rest
    if policy == "stock":
        ns = [""] * len(tokens)
    elif policy == "per_org":
        ns = [f"o{r.org}"] * len(tokens)
    elif policy == "per_user":
        ns = [f"o{r.org}u{r.user}"] * len(tokens)
    else:  # labels: the scope narrows from org to user after the approved content
        shared = len(r.system) + (r.doc_units if policy == "labels+docs" else 0)
        ns = [f"o{r.org}"] * shared + [f"o{r.org}u{r.user}"] * (len(tokens) - shared)
    prompt = list(zip(ns, tokens))
    out_ns = ns[-1] if ns else ""
    return prompt, prompt + [(out_ns, t) for t in r.output]


def simulate(requests: list[Request], policy: str) -> dict:
    trie = Trie()
    prompt_units = cached_units = 0
    for r in requests:
        prompt, full = keys_for(policy, r)
        cached_units += min(trie.match(prompt), len(prompt) - 1)  # the last token is always computed
        prompt_units += len(prompt)
        trie.insert(full)
    return {
        "policy": policy,
        "hit_rate": round(cached_units / prompt_units, 4),
        "prefill_tokens": prompt_units * PAGE - cached_units * PAGE,
        "kv_tokens_stored": trie.nodes * PAGE,
        "leaks_to": LEAKS[policy],
    }


def run_workload(w: Workload) -> dict:
    reqs = generate(w)
    rows = [simulate(reqs, p) for p in POLICIES]
    by = {r["policy"]: r for r in rows}
    lost = by["stock"]["hit_rate"] - by["per_user"]["hit_rate"]
    recovered = (by["labels"]["hit_rate"] - by["per_user"]["hit_rate"]) / lost if lost > 0 else 0.0
    return {
        "workload": w.name, "requests": len(reqs), "rows": rows,
        "labels_recover_share_of_hits_lost_to_per_user": round(recovered, 3),
        "labels_prefill_saved_vs_per_user": round(1 - by["labels"]["prefill_tokens"] / by["per_user"]["prefill_tokens"], 3),
        "labels_kv_memory_vs_per_user": round(by["labels"]["kv_tokens_stored"] / by["per_user"]["kv_tokens_stored"], 3),
    }


def sweep_users(base: Workload, sizes=(1, 5, 20, 50, 100, 200)) -> list[dict]:
    out = []
    for u in sizes:
        w = Workload(**{**base.__dict__, "users_per_org": u, "orgs": max(2, 1000 // max(u, 1) // 10)})
        reqs = generate(w)
        out.append({"users_per_org": u, **{p: simulate(reqs, p)["hit_rate"] for p in ("per_user", "labels")}})
    return out


def _table(res: dict) -> str:
    lines = [f"\n{res['workload']} ({res['requests']} requests)",
             f"{'policy':<12} {'hit rate':>9} {'prefill tok':>13} {'KV stored':>11}  leaks to"]
    for r in res["rows"]:
        lines.append(f"{r['policy']:<12} {r['hit_rate']:>9.1%} {r['prefill_tokens']:>13,} "
                     f"{r['kv_tokens_stored']:>11,}  {r['leaks_to']}")
    lines.append(f"labels recover {res['labels_recover_share_of_hits_lost_to_per_user']:.0%} of the hits "
                 f"per-user isolation loses; {res['labels_prefill_saved_vs_per_user']:.0%} less prefill and "
                 f"{res['labels_kv_memory_vs_per_user']:.0%} of the KV memory vs per-user")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write results here")
    a = ap.parse_args()
    results = {name: run_workload(w) for name, w in WORKLOADS.items()}
    results["sweep_agents_users_per_org"] = sweep_users(WORKLOADS["agents"])
    for name in WORKLOADS:
        print(_table(results[name]))
    print("\nagents: hit rate vs users per org")
    for row in results["sweep_agents_users_per_org"]:
        print(f"  {row['users_per_org']:>4} users/org   per_user {row['per_user']:.1%}   labels {row['labels']:.1%}")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
