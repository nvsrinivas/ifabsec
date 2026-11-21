#!/usr/bin/env python3
"""Latency and throughput under multi-tenant load: stock vs per-user salt vs labels.

Each org has one long system prompt (approved for sharing within the org).
Each user runs short two-turn sessions on top of it; many sessions run
concurrently. Three policies, same workload:

  stock     IFAB_MODE=off, no salt: everything shared (leaks)
  per_user  IFAB_MODE=off, cache_salt = org/user, as a gateway would set it
            with SGLang's built-in salt (safe; the org prompt is cached once
            per user)
  labels    IFAB_MODE=enforce with label tokens (safe; the org prompt is
            cached once per org)

Reports, per policy: prefix-cache hit rate, time to first token (p50, p95),
end-to-end latency, and throughput. On the pod:

    python bench/latency.py [--model Qwen/Qwen3-8B] [--orgs 4] [--users 16]

Needs scripts/pod/setup.sh first. Writes .pod/latency.json.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".pod"

WORDS = ("account balance invoice refund policy customer region quarterly report approval limit "
         "escalation review contract renewal vendor payment schedule audit compliance ticket").split()


@dataclass(frozen=True)
class Workload:
    orgs: int = 4
    users_per_org: int = 16
    system_words: int = 1100  # about 1.5K tokens
    message_words: int = 110  # about 150 tokens
    turns: int = 2
    max_tokens: int = 32
    concurrency: int = 16
    seed: int = 0


@dataclass
class Session:
    org: str
    user: str
    system: dict
    messages: list[str]  # one user message per turn


@dataclass
class Sample:
    ttft: float
    latency: float
    prompt_tokens: int
    cached_tokens: int
    output_tokens: int


# (policy, org, user, messages) -> (Sample, assistant_text)
Sender = Callable[[str, str, str, list], tuple[Sample, str]]


def _text(rng: random.Random, n: int) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(n))


def build_sessions(w: Workload) -> list[Session]:
    rng = random.Random(w.seed)
    sessions = []
    for o in range(w.orgs):
        org = f"org{o}"
        system = {"role": "system", "content": f"You are the internal assistant for {org}. Policy manual: "
                                               + _text(rng, w.system_words)}
        for u in range(w.users_per_org):
            sessions.append(Session(org, f"{org}-u{u}", system,
                                    [_text(rng, w.message_words) for _ in range(w.turns)]))
    rng.shuffle(sessions)
    return sessions


def run_policy(policy: str, sessions: list[Session], send: Sender, concurrency: int) -> dict:
    samples: list[Sample] = []
    lock = threading.Lock()

    def run_session(s: Session) -> None:
        history = [s.system]
        for msg in s.messages:
            history.append({"role": "user", "content": msg})
            sample, reply = send(policy, s.org, s.user, list(history))
            history.append({"role": "assistant", "content": reply})
            with lock:
                samples.append(sample)

    t0 = time.perf_counter()
    with ThreadPoolExecutor(concurrency) as pool:
        list(pool.map(run_session, sessions))
    wall = time.perf_counter() - t0

    def pct(xs, q):
        xs = sorted(xs)
        return xs[min(len(xs) - 1, int(q * len(xs)))]

    ttft = [s.ttft for s in samples]
    prompt = sum(s.prompt_tokens for s in samples)
    return {
        "policy": policy,
        "requests": len(samples),
        "hit_rate": round(sum(s.cached_tokens for s in samples) / prompt, 4) if prompt else None,
        "ttft_p50_ms": round(statistics.median(ttft) * 1000, 1),
        "ttft_p95_ms": round(pct(ttft, 0.95) * 1000, 1),
        "latency_p50_ms": round(statistics.median(s.latency for s in samples) * 1000, 1),
        "requests_per_s": round(len(samples) / wall, 2),
        "output_tokens_per_s": round(sum(s.output_tokens for s in samples) / wall, 1),
        "prefill_tokens": prompt - sum(s.cached_tokens for s in samples),
    }


# ------------------------------------------------------------------ HTTP sender


def _find(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            if (r := _find(v, key)) is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            if (r := _find(v, key)) is not None:
                return r
    return None


def http_sender(url: str, model: str, max_tokens: int, mint: Optional[Callable] = None) -> Sender:
    """Streams /v1/chat/completions and times the first content token."""

    def send(policy, org, user, messages):
        body = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": 0,
                "stream": True, "stream_options": {"include_usage": True}}
        headers = {"Content-Type": "application/json"}
        if policy == "per_user":
            body["cache_salt"] = f"{org}/{user}"
        if policy == "labels":
            headers["X-Ifab-Token"] = mint(user, org, messages[:1])
        req = urllib.request.Request(url.rstrip("/") + "/v1/chat/completions",
                                     data=json.dumps(body).encode(), headers=headers)
        t0 = time.perf_counter()
        ttft, text, usage = None, [], {}
        with urllib.request.urlopen(req, timeout=600) as r:
            for raw in r:
                line = raw.decode().strip()
                if not line.startswith("data:") or line == "data: [DONE]":
                    continue
                chunk = json.loads(line[5:])
                delta = _find(chunk.get("choices") or [], "content")
                if delta:
                    if ttft is None:
                        ttft = time.perf_counter() - t0
                    text.append(delta)
                if chunk.get("usage"):
                    usage = chunk["usage"]
        latency = time.perf_counter() - t0
        return Sample(ttft if ttft is not None else latency, latency, usage.get("prompt_tokens", 0),
                      _find(usage, "cached_tokens") or 0, usage.get("completion_tokens", 0)), "".join(text)

    return send


# ------------------------------------------------------------------ pod runner


def _load_check():
    spec = importlib.util.spec_from_file_location("check", ROOT / "scripts" / "pod" / "check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def table(rows: list[dict]) -> str:
    head = f"{'policy':<9} {'hit rate':>9} {'TTFT p50':>9} {'TTFT p95':>9} {'e2e p50':>9} {'req/s':>7} {'prefill tok':>12}"
    lines = [head]
    for r in rows:
        lines.append(f"{r['policy']:<9} {r['hit_rate']:>9.1%} {r['ttft_p50_ms']:>7.1f}ms {r['ttft_p95_ms']:>7.1f}ms "
                     f"{r['latency_p50_ms']:>7.1f}ms {r['requests_per_s']:>7.2f} {r['prefill_tokens']:>12,}")
    return "\n".join(lines)


def main() -> int:
    sys.path[:0] = [str(ROOT / "engine")]
    from ifabsec_engine.devmint import chat_token

    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3-8B")
    ap.add_argument("--port", type=int, default=30000)
    ap.add_argument("--orgs", type=int, default=Workload.orgs)
    ap.add_argument("--users", type=int, default=Workload.users_per_org)
    ap.add_argument("--concurrency", type=int, default=Workload.concurrency)
    a = ap.parse_args()
    if not (STATE / "env").exists():
        print("run scripts/pod/setup.sh first", file=sys.stderr)
        return 2

    w = Workload(orgs=a.orgs, users_per_org=a.users, concurrency=a.concurrency)
    sessions = build_sessions(w)
    env = dict(line.split("=", 1) for line in (STATE / "env").read_text().split())
    seed = bytes.fromhex((STATE / "gw.seed").read_text().strip())
    kid, aud = env["IFAB_GATEWAY_KEYS"].split(":", 1)[0], env["IFAB_AUDIENCE"]

    def mint(user, org, shared):
        return chat_token(seed, kid=kid, aud=aud, user=user, org=org, shared_messages=shared)

    check = _load_check()
    rows = []
    for server_env, policies in (({"IFAB_MODE": "off"}, ("stock", "per_user")), (env, ("labels",))):
        server = check.Server(a.model, a.port, server_env, STATE / f"server-bench-{policies[0]}.log")
        try:
            server.wait()
            send = http_sender(server.url, a.model, w.max_tokens, mint)
            for policy in policies:
                server.flush()
                send(policy, "warmup", "warmup", [{"role": "user", "content": "hello"}])  # load kernels
                server.flush()
                rows.append(run_policy(policy, sessions, send, w.concurrency))
                print(json.dumps(rows[-1]), flush=True)
        finally:
            server.stop()

    out = {"workload": w.__dict__, "results": rows}
    (STATE / "latency.json").write_text(json.dumps(out, indent=2))
    print(f"\n{w.orgs} orgs x {w.users_per_org} users, {w.turns}-turn sessions, concurrency {w.concurrency}\n")
    print(table(rows))
    print(f"\nresults: {STATE / 'latency.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
