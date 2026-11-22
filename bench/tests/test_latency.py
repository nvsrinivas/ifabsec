"""Benchmark logic on the fake server (illustrative latency model, no GPU)."""

import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "engine")]

from attack.fakeserver import FakeServer  # noqa: E402
from bench.latency import Sample, Workload, build_sessions, run_policy, tag_messages  # noqa: E402
from ifabsec_engine import sglang_glue as g  # noqa: E402
from ifabsec_engine.devmint import chat_token, public_key  # noqa: E402

SEED = bytes(range(96, 128))
KEYS = {"dev-1": public_key(SEED)}
INTERNAL = os.urandom(32)
W = Workload(orgs=3, users_per_org=6, system_words=300, message_words=40, concurrency=4)


def fake_sender(server: FakeServer):
    lock = threading.Lock()  # the fake server isn't thread-safe

    def send(policy, org, user, messages):
        body = {"messages": messages}
        headers = {}
        if policy == "per_user":
            body["cache_salt"] = f"{org}.{user}"  # vLLM rejects "/" in salts
        if policy == "tag":
            body["messages"] = tag_messages(org, user, messages)
        if policy in ("labels", "labels_shared"):
            shared = messages[:1] if policy == "labels" else messages
            headers["X-Ifab-Token"] = chat_token(SEED, kid="dev-1", aud="pod-1", user=user,
                                                 org=org, shared_messages=shared)
        with lock:
            status, resp, lat = server.post("/v1/chat/completions", body, headers)
        assert status == 200, resp
        u = resp["usage"]
        return Sample(lat, lat, u["prompt_tokens"], u["prompt_tokens_details"]["cached_tokens"], 1), "ok"

    return send


def run(policy):
    server = FakeServer(policy.startswith("labels"), KEYS, INTERNAL)
    try:
        return run_policy(policy, build_sessions(W), fake_sender(server), W.concurrency)
    finally:
        g._reset_for_tests()


def test_policies_order_as_expected():
    stock, per_user, labels = run("stock"), run("per_user"), run("labels")
    assert stock["requests"] == per_user["requests"] == labels["requests"] == W.orgs * W.users_per_org * W.turns
    assert stock["hit_rate"] >= labels["hit_rate"] > per_user["hit_rate"]
    assert labels["prefill_tokens"] < per_user["prefill_tokens"]
    assert labels["ttft_p50_ms"] < per_user["ttft_p50_ms"]


def test_tag_baseline_shares_the_org_prompt_like_labels():
    """The user tag keeps the org prompt shared (unlike per-user salt), at a
    hit rate close to labels: the cost case for labels is not about sharing."""
    tag, labels, per_user = run("tag"), run("labels"), run("per_user")
    assert tag["hit_rate"] > per_user["hit_rate"]
    assert abs(tag["hit_rate"] - labels["hit_rate"]) < 0.05


def test_tag_goes_right_after_the_system_prompt():
    msgs = [{"role": "system", "content": "S"}, {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "a"}, {"role": "user", "content": "again"}]
    out = tag_messages("acme", "alice", msgs)
    assert out[0] == msgs[0] and out[1]["content"].startswith("[user ") and out[3] == msgs[3]
    assert out[1] != tag_messages("acme", "bob", msgs)[1]


def test_sessions_are_deterministic_and_share_org_prompts():
    a, b = build_sessions(W), build_sessions(W)
    assert [(s.user, s.messages) for s in a] == [(s.user, s.messages) for s in b]
    by_org = {}
    for s in a:
        by_org.setdefault(s.org, set()).add(s.system["content"])
    assert all(len(v) == 1 for v in by_org.values())


def test_http_sender_parses_sglang_style_stream():
    """Run http_sender against a local SSE server shaped like SGLang's output."""
    import json
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from bench.latency import http_sender

    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen["body"], seen["token"] = body, self.headers.get("X-Ifab-Token")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            chunks = [
                {"choices": [{"delta": {"role": "assistant", "content": ""}}]},
                {"choices": [{"delta": {"content": "Hel"}}]},
                {"choices": [{"delta": {"content": "lo"}}]},
                {"choices": [], "usage": {"prompt_tokens": 40, "completion_tokens": 2,
                                          "prompt_tokens_details": {"cached_tokens": 30}}},
            ]
            for c in chunks:
                self.wfile.write(f"data: {json.dumps(c)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        send = http_sender(f"http://127.0.0.1:{srv.server_port}", "m", 8, mint=lambda u, o, s: "tok")
        sample, text = send("labels", "org0", "org0-u1", [{"role": "system", "content": "s"}])
        assert text == "Hello" and sample.prompt_tokens == 40 and sample.cached_tokens == 30
        assert sample.output_tokens == 2 and 0 < sample.ttft <= sample.latency
        assert seen["token"] == "tok" and seen["body"]["stream"] is True
        send("per_user", "org0", "org0-u1", [{"role": "user", "content": "x"}])
        assert seen["body"]["cache_salt"] == "org0.org0-u1"
    finally:
        srv.shutdown()


def test_labels_shared_nearly_matches_stock_sharing():
    """The control shares what stock shares, except that model replies stay in
    the requester's scope (the gateway can't approve text not yet written), so
    a second turn re-computes the first reply. Within a point of stock."""
    shared, stock = run("labels_shared")["hit_rate"], run("stock")["hit_rate"]
    assert stock - 0.01 <= shared <= stock
