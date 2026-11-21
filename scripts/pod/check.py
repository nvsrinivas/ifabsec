#!/usr/bin/env python3
"""First-GPU-session checks for the ifabsec SGLang patch.

Starts the patched server twice, first with IFAB_MODE=off (stock behavior,
shows the leak) and then with IFAB_MODE=enforce, and checks the items in
engine/sglang/README.md. Prints a report and writes .pod/results.json.

    python scripts/pod/check.py [--model Qwen/Qwen3-8B] [--port 30000]
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STATE = REPO / ".pod"

SYSTEM = {"role": "system", "content": "You are Acme Corp's internal support assistant. Answer briefly."}
SECRET = "Customer 88214 disputes invoice 4417 for $12,950 and threatens to cancel."

IDENTITY_TEXT = "List three things to check before approving a refund."

results: list[dict] = []


def record(name: str, ok: bool | None, detail: str) -> None:
    mark = {True: "PASS", False: "FAIL", None: "SKIP"}[ok]
    print(f"[{mark}] {name}: {detail}", flush=True)
    results.append({"check": name, "ok": ok, "detail": detail})


# ------------------------------------------------------------------ server


class Server:
    def __init__(self, model: str, port: int, env: dict, log: Path):
        self.url = f"http://127.0.0.1:{port}"
        self.log_path = log
        args = [sys.executable, "-m", "sglang.launch_server", "--model-path", model,
                "--port", str(port), "--host", "127.0.0.1"]
        help_text = subprocess.run([sys.executable, "-m", "sglang.launch_server", "--help"],
                                   capture_output=True, text=True).stdout
        if "--enable-cache-report" in help_text:
            args.append("--enable-cache-report")
        self.log = open(log, "w")
        self.proc = subprocess.Popen(args, env={**os.environ, **env}, stdout=self.log, stderr=subprocess.STDOUT)

    def wait(self, timeout: float = 1800) -> None:
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited; see {self.log_path}")
            try:
                with urllib.request.urlopen(self.url + "/health", timeout=5) as r:
                    if r.status == 200:
                        return
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                pass
            time.sleep(5)
        raise TimeoutError("server did not become healthy")

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()

    def flush(self) -> bool:
        sys.path.insert(0, str(REPO))
        from attack.harness import flush_url

        return flush_url(self.url)

    def post(self, path: str, body: dict, headers: dict | None = None) -> tuple[int, dict, float]:
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", **(headers or {})})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return r.status, json.loads(r.read()), time.perf_counter() - t0
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read())
            except ValueError:
                payload = {}
            return e.code, payload, time.perf_counter() - t0


def find_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = find_key(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = find_key(v, key)
            if found is not None:
                return found
    return None


def chat(server, model, messages, token=None, extra=None):
    body = {"model": model, "messages": messages, "max_tokens": 1, "temperature": 0,
            "return_prompt_token_ids": True, **(extra or {})}
    headers = {"X-Ifab-Token": token} if token else {}
    status, resp, latency = server.post("/v1/chat/completions", body, headers)
    cached = find_key(resp.get("usage") or {}, "cached_tokens")
    prompt_tokens = (resp.get("usage") or {}).get("prompt_tokens")
    return {"status": status, "cached": cached, "prompt_tokens": prompt_tokens,
            "ids": find_key(resp, "prompt_token_ids"), "content": find_key(resp.get("choices") or [], "content"),
            "latency": latency, "resp": resp}


def msgs(text):
    return [SYSTEM, {"role": "user", "content": text}]


# ------------------------------------------------------------------ checks


def run(model: str, port: int, only: str = "all") -> None:
    from transformers import AutoTokenizer

    from ifabsec_engine.devmint import chat_token

    env = dict(line.split("=", 1) for line in (STATE / "env").read_text().split())
    seed = bytes.fromhex((STATE / "gw.seed").read_text().strip())
    kid = env["IFAB_GATEWAY_KEYS"].split(":", 1)[0]
    aud = env["IFAB_AUDIENCE"]
    tok = AutoTokenizer.from_pretrained(model)
    org_len = len(tok.encode(tok.apply_chat_template([SYSTEM], tokenize=False, add_generation_prompt=False),
                             add_special_tokens=False))
    print(f"org system prompt = {org_len} tokens", flush=True)

    def token(user, org):
        return chat_token(seed, kid=kid, aud=aud, user=user, org=org, shared_messages=[SYSTEM])

    # ---- stock behavior (IFAB_MODE=off)
    ref_ids, off_lat, ref_greedy = None, [0.0], None
    off = Server(model, port, {"IFAB_MODE": "off"}, STATE / "server-off.log") if only == "all" else None
    try:
        if off is not None:
            off.wait()
            a = chat(off, model, msgs(SECRET))
            record("off: chat works", a["status"] == 200, f"status {a['status']}")
            if a["cached"] is None:
                record("off: cached-token reporting", False,
                       "no cached_tokens in usage; is --enable-cache-report supported?")
            b = chat(off, model, msgs(SECRET))  # a different tenant sending identical text
            record("off: the leak exists on stock behavior", (b["cached"] or 0) >= (b["prompt_tokens"] or 1) - 1,
                   f"second sender's cached_tokens={b['cached']} of {b['prompt_tokens']}")
            ref_ids = a["ids"]
            # Empty cache on both sides: a cached prefix changes the floating-point
            # path enough to change a long greedy output, which is not an input difference.
            off.flush()
            ref_greedy = chat(off, model, msgs(IDENTITY_TEXT), extra={"max_tokens": 48})
            off_lat = [chat(off, model, msgs(f"probe {i}"))["latency"] for i in range(10)]
    finally:
        if off is not None:
            off.stop()

    # ---- enforcement on
    on = Server(model, port, {**env, "IFAB_DEBUG": "1"}, STATE / "server-enforce.log")
    try:
        on.wait()
        alice1 = chat(on, model, msgs(SECRET), token("alice", "acme"))
        record("enforce: labeled chat works", alice1["status"] == 200,
               f"status {alice1['status']} {str(alice1['resp'])[:200] if alice1['status'] != 200 else ''}")
        if ref_ids and alice1["ids"]:
            record("enforce: model input identical to stock", list(ref_ids) == list(alice1["ids"]),
                   f"{len(ref_ids)} vs {len(alice1['ids'])} ids")
        else:
            record("enforce: model input identical to stock", None, "server did not return prompt_token_ids")

        if ref_greedy is not None:
            on.flush()
            g = chat(on, model, msgs(IDENTITY_TEXT), token("idcheck", "acme"), {"max_tokens": 48})
            same = g["prompt_tokens"] == ref_greedy["prompt_tokens"] and g["content"] == ref_greedy["content"]
            record("enforce: same prompt length and same greedy output as stock", same,
                   f"prompt_tokens {g['prompt_tokens']} vs {ref_greedy['prompt_tokens']}, "
                   f"48-token greedy output {'identical' if g['content'] == ref_greedy['content'] else 'DIFFERS'}")

        alice2 = chat(on, model, msgs(SECRET), token("alice", "acme"))
        record("enforce: Alice re-sends, full hit", (alice2["cached"] or 0) >= (alice2["prompt_tokens"] or 1) - 1,
               f"cached={alice2['cached']} of {alice2['prompt_tokens']}")

        bob = chat(on, model, msgs(SECRET), token("bob", "acme"))
        record("enforce: Bob, identical text, hits only the org prompt",
               bob["cached"] is not None and 0 < bob["cached"] <= org_len,
               f"cached={bob['cached']}, org prompt={org_len}, prompt={bob['prompt_tokens']}")

        eve = chat(on, model, msgs(SECRET), token("eve", "beta"))
        record("enforce: Eve (other org, same text) hits nothing", eve["cached"] == 0, f"cached={eve['cached']}")

        none = chat(on, model, msgs(SECRET))
        record("enforce: request without a token is rejected", none["status"] in (400, 401, 403), f"status {none['status']}")
        salted = chat(on, model, msgs(SECRET), token("eve", "beta"), {"cache_salt": "guess"})
        record("enforce: client-chosen cache_salt is rejected", salted["status"] in (400, 401, 403),
               f"status {salted['status']}")

        text = tok.apply_chat_template(msgs(SECRET), tokenize=False, add_generation_prompt=True)
        status, raw, _ = on.post("/generate", {"text": text, "sampling_params": {"max_new_tokens": 1}})
        raw_cached = find_key(raw, "cached_tokens")
        record("enforce: /generate without a token shares nothing", status == 200 and raw_cached == 0,
               f"status {status}, cached={raw_cached}")

        on_lat = [chat(on, model, msgs(f"probe {i}"), token("lat", "acme"))["latency"] for i in range(10)]
        if only == "all":
            record("enforce: overhead", None,
                 f"median latency {statistics.median(on_lat)*1000:.1f} ms vs {statistics.median(off_lat)*1000:.1f} ms off")
    finally:
        on.stop()

    log = (STATE / "server-enforce.log").read_text(errors="replace")
    n_iso = log.count("isolating request")
    record("enforce: segment boundaries stable for this chat template", n_iso == 0,
           f"{n_iso} 'isolating request' warnings in the server log")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3-8B")
    ap.add_argument("--port", type=int, default=30000)
    ap.add_argument("--only", choices=["all", "enforce"], default="all",
                    help="enforce: skip the stock-behavior server")
    a = ap.parse_args()
    if not (STATE / "env").exists():
        print("run scripts/pod/setup.sh first", file=sys.stderr)
        return 2
    try:
        run(a.model, a.port, a.only)
    finally:
        (STATE / "results.json").write_text(json.dumps(results, indent=2))
        print(f"\nresults: {STATE / 'results.json'}; server logs in {STATE}")
    return 0 if all(r["ok"] is not False for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
