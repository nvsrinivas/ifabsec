#!/usr/bin/env bash
# One GPU session: setup, then checks + attacks per model, then the latency sweep.
#
#   bash scripts/pod/suite.sh
#
# Defaults suit an 80 GB H100. Override with environment variables:
#   MODELS       models for checks + attacks   (default: Qwen3-8B and Phi-4-mini)
#   BENCH_MODEL  model for the latency sweep   (default: Qwen3-8B)
#   USERS        users per org, 4 orgs         (default: 4,16,64 = 16, 64, 256 users)
#   CONC         sessions in flight            (default: 32)
#   HF_TOKEN     needed only for gated models, e.g. meta-llama/Llama-3.1-8B-Instruct
#   ENGINE       sglang (default) or vllm
#
# Each step's output lands in .pod/runs/<model>/ (.pod/runs-vllm/ for vLLM);
# summary.txt there collects the PASS/FAIL lines and every table. A failing
# step doesn't stop the others.
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
MODELS="${MODELS:-Qwen/Qwen3-8B microsoft/Phi-4-mini-instruct}"
BENCH_MODEL="${BENCH_MODEL:-Qwen/Qwen3-8B}"
USERS="${USERS:-4,16,64}"
CONC="${CONC:-32}"
ENGINE="${ENGINE:-sglang}"
case "$ENGINE" in
  sglang) SETUP=scripts/pod/setup.sh; RUNS="$REPO/.pod/runs" ;;
  vllm)   SETUP=scripts/pod/setup-vllm.sh; RUNS="$REPO/.pod/runs-vllm" ;;
  *) echo "ENGINE must be sglang or vllm"; exit 2 ;;
esac

cd "$REPO"
bash "$SETUP" || { echo "setup failed; see above"; exit 1; }
# vLLM lives in its own environment; run every step with its python.
if [ "$ENGINE" = vllm ]; then
  PATH="$(dirname "$(cat .pod/python)"):$PATH"
  export PATH
fi
mkdir -p "$RUNS"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader > "$RUNS/gpu.txt"

for model in $MODELS; do
  tag="${model//\//_}"
  out="$RUNS/$tag"
  mkdir -p "$out"
  echo "== $model: checks"
  python scripts/pod/check.py --model "$model" 2>&1 | tee "$out/check.txt"
  cp .pod/results.json "$out/" 2>/dev/null
  echo "== $model: attacks"
  python attack/run_pod.py --model "$model" 2>&1 | tee "$out/attack.txt"
  cp .pod/attack.json "$out/" 2>/dev/null
  grep -h -m1 -E "max_total_num_tokens|GPU KV cache size" .pod/server-attack-stock.log > "$out/kv-cache.txt" 2>/dev/null
done

tag="${BENCH_MODEL//\//_}"
mkdir -p "$RUNS/$tag"
echo "== $BENCH_MODEL: latency sweep, users per org $USERS"
python bench/latency.py --model "$BENCH_MODEL" --users "$USERS" --concurrency "$CONC" 2>&1 | tee "$RUNS/$tag/latency.txt"
cp .pod/latency.json "$RUNS/$tag/" 2>/dev/null

{
  echo "GPU: $(cat "$RUNS/gpu.txt")   engine: $ENGINE"
  for model in $MODELS; do
    tag="${model//\//_}"
    echo
    echo "=== $model"
    echo "KV cache: $(sed -E 's/.*(max_total_num_tokens=[0-9]+|GPU KV cache size: [0-9,]+ tokens).*/\1/' "$RUNS/$tag/kv-cache.txt" 2>/dev/null)"
    grep -E "^\[(PASS|FAIL|SKIP)\]" "$RUNS/$tag/check.txt"
    sed -n '/stock     labels    chance/,/^extract, digits/p' "$RUNS/$tag/attack.txt"
    grep -E "^extract in digit groups" "$RUNS/$tag/attack.txt"
    grep -E "skipping digit" "$RUNS/$tag/attack.txt"
  done
  echo
  echo "=== latency: $BENCH_MODEL"
  sed -n '/^users policy/,$p' "$RUNS/${BENCH_MODEL//\//_}/latency.txt" | grep -v '^results:'
} > "$RUNS/summary.txt"

echo
echo "================ SUMMARY ($RUNS/summary.txt)"
cat "$RUNS/summary.txt"
