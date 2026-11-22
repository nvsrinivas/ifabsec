#!/usr/bin/env bash
# One-command live demo on a GPU pod: setup if needed, then demo/run.py.
#   bash scripts/demo.sh [--show-raw]
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f .pod/env ] || ! python -c "import sglang, ifabsec_engine" 2>/dev/null; then
  bash scripts/pod/setup.sh
fi
python demo/run.py "$@"
