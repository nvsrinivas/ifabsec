"""The attacks succeed against stock behavior and drop to chance with labels,
on the fake server. Real numbers come from the pod run."""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "engine")]

from attack import harness  # noqa: E402
from attack.fakeserver import FakeServer  # noqa: E402
from ifabsec_engine import sglang_glue as g  # noqa: E402
from ifabsec_engine.devmint import chat_token, public_key  # noqa: E402

SEED = bytes(range(64, 96))
KEYS = {"dev-1": public_key(SEED)}
INTERNAL = os.urandom(32)


def minter(user, org, shared):
    return chat_token(SEED, kid="dev-1", aud="pod-1", user=user, org=org, shared_messages=shared)


@pytest.fixture(autouse=True)
def _reset():
    yield
    g._reset_for_tests()


@pytest.mark.parametrize("enforce", [False, True])
def test_guess_attack(enforce):
    server = FakeServer(enforce, KEYS, INTERNAL)
    r = harness.guess_attack(server, "m", minter, k=20, trials=15)
    assert r["cache_flushed_between_trials"]
    if not enforce:
        assert r["metadata_accuracy"] == 1.0
        assert r["timing_accuracy"] >= 0.9
        assert r["median_latency_gap_ms"] > 5
    else:
        assert r["metadata_accuracy"] <= 0.3  # chance is 0.05
        assert r["timing_accuracy"] <= 0.3
        assert abs(r["median_latency_gap_ms"]) < 2


@pytest.mark.parametrize("enforce", [False, True])
def test_extract_attack(enforce):
    server = FakeServer(enforce, KEYS, INTERNAL)
    r = harness.extract_attack(server, "m", minter, digits=6, trials=5)
    if not enforce:
        assert r["full_recovery_rate"] == 1.0
    else:
        assert r["mean_digits_recovered"] == 0 and r["full_recovery_rate"] == 0


def test_org_prompt_still_shared_under_enforcement():
    """The defense isn't 'cache nothing': Eve still hits the shared org prompt."""
    server = FakeServer(True, KEYS, INTERNAL)
    system = {"role": "system", "content": harness.BASE_SYSTEM}
    harness._send(server, "m", minter, "alice", "acme", system, "hello")
    p = harness._send(server, "m", minter, "eve", "acme", system, "hello")
    org_len = len(server.tok.apply_chat_template([system]))
    assert p.cached == org_len


@pytest.mark.parametrize("enforce", [False, True])
def test_transcript_records_every_probe(enforce):
    from attack import transcript

    server = FakeServer(enforce, KEYS, INTERNAL)
    gt = transcript.guess_trial(server, "m", minter)
    assert len(gt["probes"]) == 20 and sum(p["is_secret"] for p in gt["probes"]) == 1
    et = transcript.extract_trial(server, "m", minter)
    if not enforce:
        assert et["recovered"] == et["account"] and len(et["steps"]) == 6
    else:
        assert et["recovered"] == "" and et["steps"][0]["picked"] is None
        assert len(set(et["steps"][0]["cached_by_digit"].values())) == 1  # every digit looks the same
