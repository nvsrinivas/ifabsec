# Running the checks on a rented GPU

About 30–60 minutes of pod time the first time, mostly the model download and
the SGLang install. On an RTX 4090 that is well under $1.

## 1. Rent a pod (RunPod)

1. Create an account at runpod.io and add a little credit ($10 is plenty).
2. **Pods → Deploy.** Pick **RTX 4090** (24 GB). Community Cloud is the cheap
   tier and fine here: only synthetic data goes on the pod.
3. **Filter for CUDA 13** (the CUDA version filter on the deploy page). The
   pinned SGLang uses CUDA 13 wheels, and older host drivers won't run them.
4. **Template / container image:** `lmsysorg/sglang:latest`. It already has
   the right torch and kernels, which saves most of the install time.
5. **Disk:** 60 GB container disk (the 8B model is about 16 GB).
6. Deploy, then open the web terminal or connect over SSH.

**Stop the pod when you're done.** Billing runs per second while it's on.

## 2. Get the repo onto the pod

The repo is private, so use a GitHub token that can only read it: GitHub →
Settings → Developer settings → Fine-grained tokens → generate one with
**Repository access: only `ifabsec`**, **Contents: read-only**, and a short
expiry.

```sh
export GH_TOKEN=github_pat_...        # paste, don't commit
git clone https://x-access-token:$GH_TOKEN@github.com/nvsrinivas/ifabsec
cd ifabsec
```

## 3. Run

```sh
bash scripts/pod/setup.sh             # pinned SGLang + patch + dev keys
python scripts/pod/check.py           # default model: Qwen/Qwen3-8B
python attack/run_pod.py              # the attacks, stock vs labels
python bench/latency.py               # latency: stock vs per-user salt vs labels
```

`check.py` starts the patched server twice. First with enforcement off, to
show the leak on stock behavior, then with enforcement on. It prints a PASS or
FAIL line per check and writes `.pod/results.json` plus both server logs.
`attack/run_pod.py` then runs the attacks in `attack/README.md` against
both modes and prints a stock-vs-labels table (`.pod/attack.json`). Send me
both results files and any FAIL lines.

## What to expect

| Check | Expected |
|---|---|
| off: the leak exists on stock behavior | A second sender with identical text gets the whole prompt cached |
| enforce: model input identical to stock | Same prompt token ids as stock SGLang |
| enforce: Alice re-sends | Full hit |
| enforce: Bob, identical text | Only the org system prompt is cached |
| enforce: Eve, other org | Nothing cached |
| enforce: no token / client cache_salt | Rejected (HTTP 400) |
| enforce: `/generate` without a token | Nothing cached |
| enforce: boundaries stable | No `isolating request` warnings |

If setup fails on the install step, it's most likely a CUDA or driver
mismatch: try a pod with a newer driver, or the newest `lmsysorg/sglang` tag.

## Full session on an H100 (`suite.sh`)

One command runs setup, the checks and attacks on two model families, and the
latency benchmark swept over load:

```sh
export GH_TOKEN=github_pat_... && git clone https://x-access-token:$GH_TOKEN@github.com/nvsrinivas/ifabsec && cd ifabsec
nohup bash scripts/pod/suite.sh > suite.log 2>&1 &
tail -f suite.log
```

- **Pod:** 1× H100 80 GB (RunPod lists the H100 PCIe from about $2/hour on
  Community Cloud), CUDA 13, 100 GB disk for two models.
- **Models:** Qwen3-8B and Phi-4-mini by default, two chat-template families.
  `MODELS="Qwen/Qwen3-8B meta-llama/Llama-3.1-8B-Instruct"` with `HF_TOKEN`
  set works for gated models. Tokenizers that group digits (Llama, Phi) skip
  the digit-by-digit extraction; the guessing attack still runs.
- **Load sweep:** 16, 64 and 256 users (4 orgs), 32 sessions in flight, each
  policy twice, including the `labels_shared` overhead control.
- **Time:** about 1.5–2 hours. The end of `suite.log` prints a summary, also
  saved as `.pod/runs/summary.txt`. Send that, then terminate the pod.

## vLLM

The same scripts run against vLLM (patch in `engine/vllm/`). Use the image
`vllm/vllm-openai:v0.34.0` (or any CUDA image; the setup script then installs
`vllm==0.34.0`), get the repo onto the pod as above, and run everything in one
go:

```sh
ENGINE=vllm MODELS=Qwen/Qwen3-8B bash scripts/pod/suite.sh
```

or step by step: `bash scripts/pod/setup-vllm.sh`, then `check.py`,
`attack/run_pod.py` and `bench/latency.py` as for SGLang. The setup script
records the engine in `.pod/engine`; `bash scripts/pod/setup.sh` switches the
pod back to SGLang. Results land in `.pod/runs-vllm/`.
