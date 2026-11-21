import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sim.hitrate import POLICIES, Workload, generate, simulate  # noqa: E402

SMALL = Workload("small", orgs=3, users_per_org=6, system_tokens=800, turn_tokens=(32, 160),
                 output_tokens=96, turns=(1, 4), sessions_per_user=(1, 3),
                 docs_per_org=3, doc_tokens=1200, p_doc=0.5, seed=7)


def results(w=SMALL):
    reqs = generate(w)
    return {p: simulate(reqs, p) for p in POLICIES}


def test_ordering_of_policies():
    r = {p: v["hit_rate"] for p, v in results().items()}
    assert r["per_user"] <= r["labels"] <= r["labels+docs"] <= r["per_org"] <= r["stock"]
    assert r["labels"] > r["per_user"]  # the org prompt is shared across users


def test_labels_never_use_more_memory_than_per_user():
    r = results()
    assert r["labels"]["kv_tokens_stored"] <= r["per_user"]["kv_tokens_stored"]


def test_single_user_orgs_gain_nothing():
    w = Workload(**{**SMALL.__dict__, "users_per_org": 1, "p_doc": 0.0})
    r = {p: v["hit_rate"] for p, v in results(w).items()}
    assert r["labels"] == r["per_user"]


def test_deterministic():
    assert results() == results()
