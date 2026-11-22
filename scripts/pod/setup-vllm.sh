#!/usr/bin/env bash
# One-time setup on a GPU pod: pinned vLLM + ifabsec patch + dev keys.
#
#   bash scripts/pod/setup-vllm.sh
#
# Best on the official vLLM image at the pinned version
# (vllm/vllm-openai:v0.34.0), which already has vLLM, CUDA and torch. On any
# other image it pip-installs the pinned release. The patch is applied to the
# installed package; after this, every pod script uses vLLM (.pod/engine).
# Run scripts/pod/setup.sh to switch the pod back to SGLang.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
read -r VERSION COMMIT < "$REPO/engine/vllm/VLLM_VERSION"
PATCH="$REPO/engine/vllm/ifabsec-vllm.patch"
STATE="$REPO/.pod"
mkdir -p "$STATE"

echo "== GPU"
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader

pip_install() {
  local log="$STATE/pip-first-attempt.log"
  if ! pip install -q "$@" 2>"$log"; then
    echo "first attempt hit a distro-installed package; retrying with --ignore-installed (expected)"
    if ! pip install -q --ignore-installed "$@"; then
      echo "both attempts failed; first attempt's errors:" >&2
      cat "$log" >&2
      return 1
    fi
  fi
}

echo "== vLLM $VERSION ($COMMIT)"
have="$(python -c 'import vllm; print(vllm.__version__)' 2>/dev/null || true)"
if [ "$have" != "${VERSION#v}" ]; then
  echo "installed: ${have:-none}; installing vllm==${VERSION#v}"
  pip_install "vllm==${VERSION#v}"
fi
SITE="$(python -c 'import os, vllm; print(os.path.dirname(os.path.dirname(vllm.__file__)))')"
cd "$SITE"
if git apply --check -R "$PATCH" 2>/dev/null; then
  echo "patch already applied"
elif [ -f vllm/ifabsec_hooks.py ]; then
  # An older version of the patch: undo it from the previous copy, then apply.
  echo "replacing an older ifabsec patch"
  pip_install --force-reinstall --no-deps "vllm==${VERSION#v}"
  git apply "$PATCH"
  echo "patch applied"
else
  git apply "$PATCH"
  echo "patch applied"
fi
cd "$REPO"

pip_install -e "$REPO/engine"
python -c "import vllm, ifabsec_engine.vllm_glue; print('vllm', vllm.__version__)"

echo "== dev keys (in $STATE, git-ignored)"
if [ ! -f "$STATE/gw.seed" ]; then
  python - "$STATE" <<'EOF'
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
echo "done. Next: python scripts/pod/check.py"
