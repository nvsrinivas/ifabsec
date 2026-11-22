#!/usr/bin/env bash
# One-time setup on a GPU pod: pinned SGLang + ifabsec patch + dev keys.
#
#   bash scripts/pod/setup.sh
#
# Best on the official SGLang image (lmsysorg/sglang), which already has
# matching CUDA, torch and kernels. Set SGLANG_DIR to use another checkout.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
COMMIT="$(cat "$REPO/engine/sglang/SGLANG_COMMIT")"
PATCH="$REPO/engine/sglang/ifabsec-sglang.patch"
SG="${SGLANG_DIR:-/sgl-workspace/sglang}"
STATE="$REPO/.pod"
mkdir -p "$STATE"

echo "== GPU"
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader
CUDA_DRV="$(nvidia-smi | grep -o 'CUDA Version: [0-9.]*' | awk '{print $3}')"
echo "driver supports CUDA $CUDA_DRV"
if [ "${CUDA_DRV%%.*}" -lt 13 ]; then
  echo "WARNING: SGLang at $COMMIT uses CUDA 13 wheels; this driver may be too old." >&2
  echo "         Pick a pod with CUDA 13 (RunPod: filter by CUDA version when deploying)." >&2
fi

echo "== SGLang at $COMMIT"
if [ ! -d "$SG/.git" ]; then
  git clone --filter=blob:none https://github.com/sgl-project/sglang "$SG"
fi
cd "$SG"
if git apply --check -R "$PATCH" 2>/dev/null; then
  echo "patch already applied"
else
  git fetch --filter=blob:none origin "$COMMIT" 2>/dev/null || git fetch origin
  git checkout -f "$COMMIT"
  rm -f python/sglang/srt/ifabsec_hooks.py  # left over from an older version of the patch
  git apply "$PATCH"
  echo "patch applied"
fi

echo "== install (reuses the image's torch/kernels when they already match)"
if ! command -v cargo >/dev/null 2>&1; then
  # SGLang's optional Rust extensions need cargo; build without them if it's missing.
  export SGLANG_BUILD_RUST_EXTS="${SGLANG_BUILD_RUST_EXTS:-none}"
  echo "cargo not found: SGLANG_BUILD_RUST_EXTS=$SGLANG_BUILD_RUST_EXTS"
fi
# Base images often ship distro-installed Python packages pip can't uninstall
# ("no RECORD file"), so a first attempt can fail and a retry that installs
# over them succeeds. The first attempt's output only matters if both fail.
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
pip_install -e "$SG/python"
pip_install -e "$REPO/engine"
python -c "import sglang, ifabsec_engine; print('sglang', sglang.__version__)"

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
echo sglang > "$STATE/engine"
rm -f "$STATE/python"
echo "done. Next: python scripts/pod/check.py"
