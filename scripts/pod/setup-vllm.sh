#!/usr/bin/env bash
# One-time setup on a GPU pod: pinned vLLM + ifabsec patch + dev keys.
#
#   bash scripts/pod/setup-vllm.sh
#
# vLLM goes into its own virtual environment (default /opt/ifab-vllm, or
# IFAB_VENV), created with uv, so it never mixes with the image's torch:
# installing vLLM's torch over an image's older copy leaves stale files behind,
# and torch then fails at startup ("duplicate template name"). The patch is
# applied to that environment; after this, every pod script uses vLLM
# (.pod/engine) through that environment's python (.pod/python).
# Run scripts/pod/setup.sh to switch the pod back to SGLang.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
read -r VERSION COMMIT < "$REPO/engine/vllm/VLLM_VERSION"
PATCH="$REPO/engine/vllm/ifabsec-vllm.patch"
STATE="$REPO/.pod"
mkdir -p "$STATE"

echo "== GPU"
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader

VENV="${IFAB_VENV:-/opt/ifab-vllm}"
PY="$VENV/bin/python"

echo "== vLLM $VERSION ($COMMIT) in $VENV"
command -v uv >/dev/null 2>&1 || pip install -q uv
[ -x "$PY" ] || uv venv -q --python 3.12 "$VENV"
have="$("$PY" -c 'import vllm; print(vllm.__version__)' 2>/dev/null || true)"
if [ "$have" != "${VERSION#v}" ]; then
  echo "installing vllm==${VERSION#v} (a few minutes)"
  uv pip install -q --python "$PY" "vllm==${VERSION#v}"
fi
SITE="$("$PY" -c 'import os, vllm; print(os.path.dirname(os.path.dirname(vllm.__file__)))')"
cd "$SITE"
if git apply --check -R "$PATCH" 2>/dev/null; then
  echo "patch already applied"
elif [ -f vllm/ifabsec_hooks.py ]; then
  echo "replacing an older ifabsec patch"
  uv pip install -q --python "$PY" --reinstall --no-deps "vllm==${VERSION#v}"
  git apply "$PATCH"
  echo "patch applied"
else
  git apply "$PATCH"
  echo "patch applied"
fi
cd "$REPO"

uv pip install -q --python "$PY" -e "$REPO/engine"
"$PY" -c "import torch, vllm, ifabsec_engine.vllm_glue; print('vllm', vllm.__version__, 'torch', torch.__version__)"

echo "== dev keys (in $STATE, git-ignored)"
if [ ! -f "$STATE/gw.seed" ]; then
  "$PY" - "$STATE" <<'EOF'
import os, sys
from ifabsec_engine.devmint import public_key
d = sys.argv[1]
seed = os.urandom(32)
open(f"{d}/gw.seed", "w").write(seed.hex())
os.chmod(f"{d}/gw.seed", 0o600)
open(f"{d}/env", "w").write(
    "IFAB_MODE=enforce\n"
    "IFAB_AUDIENCE=pod-1\n"
    f"IFAB_GATEWAY_KEYS=dev-1:{public_key(seed).hex()}\n"
    f"IFAB_INTERNAL_KEY={os.urandom(32).hex()}\n"
)
EOF
fi
echo vllm > "$STATE/engine"
echo "$PY" > "$STATE/python"
echo "done. Next: source $VENV/bin/activate && python scripts/pod/check.py"
