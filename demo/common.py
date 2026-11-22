"""Shared pieces of the live demo: the chat prompt, the HTTP client, and the dev gateway.

The demo plays a tiny gateway: it mints a label token for the user each script
says it is (alice, or eve's throwaway accounts), using the key that
scripts/pod/setup.sh generated. A real gateway would authenticate the user
first. A server running with IFAB_MODE=off ignores the tokens.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "engine")]

from attack.harness import HttpServer  # noqa: E402
from ifabsec_engine.devmint import chat_token  # noqa: E402

STATE = ROOT / ".pod"
ORG = "acme"
SYSTEM = {"role": "system", "content": "You are Acme Corp's internal billing assistant. Answer briefly."}
PREFIX = "My account number is "  # the one thing Eve has to know: how Alice's message starts


def gateway():
    """Returns mint(user) -> token, or a no-op if setup.sh has not made a gateway key."""
    try:
        env = dict(line.split("=", 1) for line in (STATE / "env").read_text().split())
        seed = bytes.fromhex((STATE / "gw.seed").read_text().strip())
    except FileNotFoundError:
        return lambda user: None
    kid, aud = env["IFAB_GATEWAY_KEYS"].split(":", 1)[0], env["IFAB_AUDIENCE"]
    return lambda user: chat_token(seed, kid=kid, aud=aud, user=user, org=ORG, shared_messages=[SYSTEM])


def chat(server, model: str, token, text: str) -> tuple[int, dict]:
    body = {"model": model, "messages": [SYSTEM, {"role": "user", "content": text}], "max_tokens": 1, "temperature": 0}
    status, resp, _ = server.post("/v1/chat/completions", body, {"X-Ifab-Token": token} if token else {})
    return status, resp


def cached_tokens(resp: dict):
    usage = resp.get("usage") or {}
    details = usage.get("prompt_tokens_details") or {}
    return details.get("cached_tokens", usage.get("cached_tokens"))


def client(url: str) -> HttpServer:
    return HttpServer(url)


def dump(resp: dict) -> str:
    return json.dumps(resp.get("usage") or resp, indent=2)
