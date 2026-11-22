#!/usr/bin/env python3
"""The whole demo in one command: stock SGLang, then SGLang with labels.

    python demo/run.py [--model Qwen/Qwen3-8B] [--modes stock,labels]

For each mode it starts the server, asks the audience for an account number at
a hidden prompt, and runs Alice and Eve as two separate processes:

- Alice gets the number on her stdin and sends her question.
- Eve gets no input at all, only the server's address, and prints each round live.

Only after Eve has finished does this script reveal the number that was typed,
so the audience can compare. Needs scripts/pod/setup.sh first.
"""

from __future__ import annotations

import argparse
import getpass
import importlib.util
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
STATE = ROOT / ".pod"


def load_check():
    spec = importlib.util.spec_from_file_location("check", ROOT / "scripts" / "pod" / "check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ask_account(mode: str) -> str:
    while True:
        a = getpass.getpass(f"[{mode}] Audience: type any 4-12 digit account number for Alice (hidden): ").strip()
        if a.isdigit() and 4 <= len(a) <= 12:
            return a
        print("  4 to 12 digits, please.")


def run_mode(check, mode: str, env: dict, model: str, port: int, show_raw: bool) -> None:
    print(f"\n=== {mode.upper()}: starting SGLang ({'labels enforced' if mode == 'labels' else 'IFAB_MODE=off, as shipped'}) ...", flush=True)
    server = check.Server(model, port, env, STATE / f"server-demo-{mode}.log")
    try:
        server.wait()
        url = server.url
        account = ask_account(mode)
        subprocess.run([sys.executable, str(HERE / "alice.py"), "--url", url, "--model", model],
                       input=account + "\n", text=True, check=True)
        print("\n--- Eve's terminal (separate process, no input) ---", flush=True)
        eve = [sys.executable, str(HERE / "eve.py"), "--url", url, "--model", model] + (["--show-raw"] if show_raw else [])
        lines = []
        with subprocess.Popen(eve, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True) as p:
            for line in p.stdout:  # live, round by round
                print(line, end="", flush=True)
                lines.append(line)
        if p.returncode:
            raise SystemExit(f"eve.py exited with {p.returncode}")
        got = "".join(lines).rsplit("Eve's result:", 1)[-1].strip()
        verdict = "MATCH: the cache leaked it" if got == account else "no match: Eve did not get it"
        print(f"--- reveal: the audience typed {account}; Eve got {got}. {verdict}", flush=True)
    finally:
        server.stop()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3-8B")
    ap.add_argument("--port", type=int, default=30000)
    ap.add_argument("--modes", default="stock,labels")
    ap.add_argument("--show-raw", action="store_true", help="also print the raw usage block of one probe")
    a = ap.parse_args()
    if not (STATE / "env").exists():
        print("run scripts/pod/setup.sh first", file=sys.stderr)
        return 2
    labels_env = dict(line.split("=", 1) for line in (STATE / "env").read_text().split())
    envs = {"stock": {"IFAB_MODE": "off"}, "labels": labels_env}
    check = load_check()
    for mode in a.modes.split(","):
        run_mode(check, mode, envs[mode], a.model, a.port, a.show_raw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
