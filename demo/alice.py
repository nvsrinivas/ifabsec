#!/usr/bin/env python3
"""Alice asks the shared assistant about her account.

    python demo/alice.py [--url http://127.0.0.1:30000]

The account number is typed at a hidden prompt (or piped on stdin). It is never
a command-line argument, never printed, and never written to disk, so nothing
another process can see carries it.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from common import PREFIX, chat, client, gateway


def send(server, model: str, mint, account: str) -> int:
    """Alice's request. Returns how many of her prompt tokens were cached (normally 0 or the system prompt)."""
    status, resp = chat(server, model, mint("alice"), f"{PREFIX}{account}. Please check my balance.")
    if status != 200:
        raise SystemExit(f"Alice's request failed with HTTP {status}")
    return (resp.get("usage") or {}).get("prompt_tokens", 0)


def read_account() -> str:
    account = (getpass.getpass("Alice's account number (hidden): ") if sys.stdin.isatty() else sys.stdin.readline()).strip()
    if not (account.isdigit() and 4 <= len(account) <= 12):
        raise SystemExit("enter 4 to 12 digits")
    return account


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:30000")
    ap.add_argument("--model", default="Qwen/Qwen3-8B")
    ap.add_argument("--keep-cache", action="store_true", help="don't flush the server's cache first")
    a = ap.parse_args()
    server = client(a.url)
    if not a.keep_cache:
        server.flush()  # start clean, so earlier runs can't help or hurt Eve
    account = read_account()
    n = send(server, a.model, gateway(), account)
    print(f"Alice sent her question ({n} prompt tokens, {len(account)}-digit account). Her number is not shown here.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
