"""The demo's Alice and Eve against the fake server: Eve reads any number on
stock behavior and nothing with labels. Real numbers come from a GPU pod."""

import os
import sys
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(DEMO), str(DEMO.parent), str(DEMO.parent / "engine")]

import alice  # noqa: E402
import eve  # noqa: E402
from attack.fakeserver import FakeServer  # noqa: E402
from common import ORG, SYSTEM  # noqa: E402
from ifabsec_engine import sglang_glue as g  # noqa: E402
from ifabsec_engine.devmint import chat_token, public_key  # noqa: E402

SEED = bytes(range(64, 96))
KEYS = {"dev-1": public_key(SEED)}


def mint(user):
    return chat_token(SEED, kid="dev-1", aud="pod-1", user=user, org=ORG, shared_messages=[SYSTEM])


@pytest.fixture(autouse=True)
def _reset():
    yield
    g._reset_for_tests()


@pytest.mark.parametrize("account", ["4417", "877893", "000123456789"])
def test_eve_reads_any_number_on_stock(account):
    server = FakeServer(False, KEYS, os.urandom(32))
    alice.send(server, "m", mint, account)
    lines = []
    assert eve.extract(server, "m", mint, out=lines.append) == account
    assert lines[-1].endswith("no digit stands out; stopping") or len(account) == eve.MAX_DIGITS


def test_eve_reads_nothing_with_labels():
    server = FakeServer(True, KEYS, os.urandom(32))
    alice.send(server, "m", mint, "877893")
    lines = []
    assert eve.extract(server, "m", mint, out=lines.append) == ""
    assert "no digit stands out" in lines[0]
