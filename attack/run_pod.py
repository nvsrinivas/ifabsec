#!/usr/bin/env python3
"""Run both attacks on the pod: stock behavior (IFAB_MODE=off), then labels on.

    python attack/run_pod.py [--model Qwen/Qwen3-8B] [--k 20] [--trials 10]

Needs scripts/pod/setup.sh first. Writes .pod/attack.json.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "engine")]

from attack import harness  # noqa: E402
from ifabsec_engine.devmint import chat_token  # noqa: E402

STATE = ROOT / ".pod"


def load_check():
    spec = importlib.util.spec_from_file_location("check", ROOT / "scripts" / "pod" / "check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3-8B")
    ap.add_argument("--port", type=int, default=30000)
    ap.add_argument("--k", type=int, default=20)
    ap.add_argument("--trials", type=int, default=10)
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
    out = {}
    for mode, server_env in (("stock", {"IFAB_MODE": "off"}), ("labels", env)):
        print(f"== {mode}", flush=True)
        server = check.Server(a.model, a.port, server_env, STATE / f"server-attack-{mode}.log")
        try:
            server.wait()
            out[mode] = [
                harness.guess_attack(server, a.model, mint, k=a.k, trials=a.trials),
                harness.extract_attack(server, a.model, mint, trials=max(3, a.trials // 2)),
            ]
            for r in out[mode]:
                print(json.dumps(r), flush=True)
        finally:
            server.stop()

    (STATE / "attack.json").write_text(json.dumps(out, indent=2))
    g_s, g_l = out["stock"][0], out["labels"][0]
    e_s, e_l = out["stock"][1], out["labels"][1]
    print(f"""
                                  stock     labels    chance
guess, cached-token channel      {g_s['metadata_accuracy']:>6}    {g_l['metadata_accuracy']:>6}    {g_s['chance']:>6}
guess, timing channel            {g_s['timing_accuracy']:>6}    {g_l['timing_accuracy']:>6}    {g_s['chance']:>6}
  latency gap, right vs wrong    {g_s['median_latency_gap_ms']:>5}ms  {g_l['median_latency_gap_ms']:>5}ms
extract, digits recovered (of {e_s['digits']})  {e_s['mean_digits_recovered']:>6}    {e_l['mean_digits_recovered']:>6}

results: {STATE / 'attack.json'}""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
