import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ifabsec_engine import Verifier, segment_digest

T0 = 1893456000
VECTOR = json.loads((Path(__file__).parents[2] / "testdata" / "token_vector_v1.json").read_text())
SEED = bytes(range(32))
ORG_PROMPT = [{"role": "system", "content": "You are Acme's internal assistant."}]


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def mint(claims: dict, seed: bytes = SEED) -> str:
    """Test-only minter. Production tokens come from the Go gateway."""
    signed = "ifab1." + b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(signed.encode())
    return signed + "." + b64(sig)


_jti = [0]


def claims(**over) -> dict:
    _jti[0] += 1
    c = {
        "v": 1, "iss": "gw-1", "kid": "gw-key-1", "sub": "user:acme/alice", "aud": "cluster-1",
        "iat": T0, "exp": T0 + 60,
        "jti": b64(_jti[0].to_bytes(16, "big")),
        "read": ["public", "org:acme", "user:acme/alice"],
        "segments": [
            {"until_message": 1, "scope": "org:acme", "content_sha256": segment_digest(ORG_PROMPT)},
            {"scope": "user:acme/alice"},
        ],
    }
    c.update(over)
    return c


@pytest.fixture
def verifier() -> Verifier:
    return Verifier("cluster-1", {"gw-key-1": bytes.fromhex(VECTOR["public_key_hex"])}, now=lambda: T0 + 10)
